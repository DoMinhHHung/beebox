package session

import (
	"context"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	AbsoluteLifetime   = 30 * 24 * time.Hour
	InactivityLifetime = 7 * 24 * time.Hour
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrSessionUnavailable = errors.New("session unavailable")
	ErrRefreshInvalid     = errors.New("invalid refresh credential")
	ErrRefreshReused      = errors.New("refresh credential reused")
)

type CredentialRecord struct {
	UserInternalID      identity.InternalID
	UserPublicID        string
	ApplicationPublicID string
	PasswordHash        authentication.PasswordHash
}

type CredentialLookup interface {
	LookupPasswordCredential(context.Context, applicationinstance.InternalID, string) (CredentialRecord, error)
}

type Store interface {
	CreateSession(context.Context, applicationinstance.InternalID, identity.InternalID, string, [32]byte, time.Time, time.Time, audit.CorrelationID) error
	RotateRefresh(context.Context, applicationinstance.InternalID, [32]byte, [32]byte, time.Time, time.Time, audit.CorrelationID) (CredentialRecord, string, error)
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	SessionID    string
}

type Service struct {
	credentials CredentialLookup
	store       Store
	ring        *KeyRing
	now         func() time.Time
}

func NewService(credentials CredentialLookup, store Store, ring *KeyRing) *Service {
	return &Service{credentials: credentials, store: store, ring: ring, now: time.Now}
}

func (s *Service) SignIn(ctx context.Context, appID applicationinstance.InternalID, email, password string, correlationID audit.CorrelationID) (TokenPair, error) {
	if s == nil || s.credentials == nil || s.store == nil || s.ring == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return TokenPair{}, ErrSessionUnavailable
	}
	normalized, err := identity.NormalizeEmail(email)
	if err != nil {
		return TokenPair{}, ErrInvalidCredentials
	}
	record, err := s.credentials.LookupPasswordCredential(ctx, appID, normalized.ComparisonKey)
	if err != nil {
		// Burn the same expensive primitive on unknown identifiers to reduce a cheap timing oracle.
		_, _ = authentication.HashPassword([]byte(password))
		return TokenPair{}, ErrInvalidCredentials
	}
	if err := authentication.VerifyPassword(record.PasswordHash, []byte(password)); err != nil {
		return TokenPair{}, ErrInvalidCredentials
	}
	return s.issueNewSession(ctx, appID, record, correlationID)
}

func (s *Service) issueNewSession(ctx context.Context, appID applicationinstance.InternalID, record CredentialRecord, correlationID audit.CorrelationID) (TokenPair, error) {
	sessionID, err := NewPublicID()
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	refresh, refreshHash, err := GenerateRefreshSecret()
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	now := s.now().UTC()
	if err := s.store.CreateSession(ctx, appID, record.UserInternalID, sessionID, refreshHash, now.Add(InactivityLifetime), now.Add(AbsoluteLifetime), correlationID); err != nil {
		return TokenPair{}, err
	}
	access, err := s.ring.Sign(record.UserPublicID, record.ApplicationPublicID, sessionID, now)
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	return TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int64(AccessTokenLifetime / time.Second),
		SessionID:    sessionID,
	}, nil
}

func (s *Service) Refresh(ctx context.Context, appID applicationinstance.InternalID, refresh string, correlationID audit.CorrelationID) (TokenPair, error) {
	if s == nil || s.store == nil || s.ring == nil || !appID.Valid() || refresh == "" || correlationID == (audit.CorrelationID{}) {
		return TokenPair{}, ErrRefreshInvalid
	}
	oldHash := HashRefreshSecret(refresh)
	newRefresh, newHash, err := GenerateRefreshSecret()
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	now := s.now().UTC()
	record, sessionID, err := s.store.RotateRefresh(ctx, appID, oldHash, newHash, now, now.Add(InactivityLifetime), correlationID)
	if err != nil {
		return TokenPair{}, err
	}
	access, err := s.ring.Sign(record.UserPublicID, record.ApplicationPublicID, sessionID, now)
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	return TokenPair{
		AccessToken:  access,
		RefreshToken: newRefresh,
		ExpiresIn:    int64(AccessTokenLifetime / time.Second),
		SessionID:    sessionID,
	}, nil
}
