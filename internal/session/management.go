package session

import (
	"context"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionRevoked  = errors.New("session revoked")
)

type Record struct {
	PublicID              string
	UserPublicID          string
	UserInternalID        identity.InternalID
	ApplicationPublicID   string
	ApplicationInstanceID applicationinstance.InternalID
	CreatedAt             time.Time
	LastSeenAt            time.Time
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	RevokedAt             *time.Time
	MFAMethod             string
}

type managementStore interface {
	ResolveSession(context.Context, applicationinstance.InternalID, string) (Record, error)
	RevokeSession(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) error
}

func (s *Service) Current(ctx context.Context, appID applicationinstance.InternalID, applicationPublicID, accessToken string) (Record, error) {
	store, ok := s.store.(managementStore)
	if s == nil || !ok || s.ring == nil || !appID.Valid() || accessToken == "" || applicationPublicID == "" {
		return Record{}, ErrSessionUnavailable
	}
	claims, err := s.ring.Verify(accessToken, applicationPublicID, s.now().UTC())
	if err != nil {
		return Record{}, ErrToken
	}
	record, err := store.ResolveSession(ctx, appID, claims.SessionID)
	if err != nil {
		return Record{}, err
	}
	if record.UserPublicID != claims.Subject || record.ApplicationPublicID != claims.Audience {
		return Record{}, ErrToken
	}
	now := s.now().UTC()
	if record.RevokedAt != nil || !record.ExpiresAt.After(now) || !record.IdleExpiresAt.After(now) {
		return Record{}, ErrSessionRevoked
	}
	return record, nil
}

func (s *Service) SignOut(ctx context.Context, appID applicationinstance.InternalID, applicationPublicID, accessToken string, correlationID audit.CorrelationID) error {
	record, err := s.Current(ctx, appID, applicationPublicID, accessToken)
	if err != nil {
		if errors.Is(err, ErrSessionRevoked) || errors.Is(err, ErrSessionNotFound) {
			return nil
		}
		return err
	}
	store := s.store.(managementStore)
	return store.RevokeSession(ctx, appID, record.PublicID, correlationID)
}

func (s *Service) GetSession(ctx context.Context, appID applicationinstance.InternalID, publicID string) (Record, error) {
	store, ok := s.store.(managementStore)
	if s == nil || !ok || !appID.Valid() || !ValidPublicID(publicID) {
		return Record{}, ErrSessionNotFound
	}
	return store.ResolveSession(ctx, appID, publicID)
}

func (s *Service) RevokeSession(ctx context.Context, appID applicationinstance.InternalID, publicID string, correlationID audit.CorrelationID) error {
	store, ok := s.store.(managementStore)
	if s == nil || !ok || !appID.Valid() || !ValidPublicID(publicID) || correlationID == (audit.CorrelationID{}) {
		return ErrSessionNotFound
	}
	return store.RevokeSession(ctx, appID, publicID, correlationID)
}
