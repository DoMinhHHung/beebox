package authentication

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	PasskeyAttemptTTL   = 5 * time.Minute
	PasskeyNameMaxBytes = 64
	PasskeyListLimit    = 100
)

var (
	ErrPasskeyInvalidRequest         = errors.New("invalid passkey request")
	ErrPasskeyInvalidSession         = errors.New("invalid passkey session")
	ErrPasskeyReverificationRequired = errors.New("passkey reverification required")
	ErrPasskeyInvalidAttempt         = errors.New("invalid passkey attempt")
	ErrPasskeyProof                  = errors.New("passkey proof failed")
	ErrPasskeyNotFound               = errors.New("passkey not found")
	ErrPasskeyPersistence            = errors.New("passkey persistence failure")
	ErrPasskeyUnavailable            = errors.New("passkey unavailable")
)

type PasskeySession struct {
	ApplicationInstanceID applicationinstance.InternalID
	ApplicationPublicID   applicationinstance.PublicID
	UserID                identity.InternalID
	UserPublicID          identity.PublicID
	SessionPublicID       string
	CreatedAt             time.Time
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	Revoked               bool
}

type PasskeyCredential struct {
	PublicID       string
	RPID           string
	CredentialID   []byte
	CredentialJSON json.RawMessage
	Name           string
	CreatedAt      time.Time
}

type PasskeyProtocolUser struct {
	UserID      identity.InternalID
	PublicID    identity.PublicID
	Credentials []PasskeyCredential
}

type PasskeyProtocol interface {
	BeginRegistration(PasskeyProtocolUser, string, string) (json.RawMessage, json.RawMessage, string, error)
	FinishRegistration(PasskeyProtocolUser, string, string, json.RawMessage, json.RawMessage) (PasskeyCredential, error)
	BeginAuthentication(string, string) (json.RawMessage, json.RawMessage, string, error)
	FinishAuthentication(context.Context, string, string, json.RawMessage, json.RawMessage, func(context.Context, []byte, []byte) (PasskeyProtocolUser, error)) (PasskeyProtocolUser, PasskeyCredential, error)
}

type PasskeyAttemptWrite struct {
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	SessionPublicID       string
	Purpose               string
	Origin                string
	RPID                  string
	SessionData           json.RawMessage
	ChallengeHash         [32]byte
	CreatedAt             time.Time
	ExpiresAt             time.Time
}

type PasskeyAttempt struct {
	PublicID              string
	ApplicationInstanceID applicationinstance.InternalID
	ApplicationPublicID   applicationinstance.PublicID
	UserID                identity.InternalID
	UserPublicID          identity.PublicID
	SessionPublicID       string
	Purpose               string
	Origin                string
	RPID                  string
	SessionData           json.RawMessage
	CreatedAt             time.Time
	ExpiresAt             time.Time
}

type PasskeyAuthFinalize struct {
	AttemptPublicID string
	UserID          identity.InternalID
	Credential      PasskeyCredential
	SessionPublicID string
	RefreshVerifier [32]byte
	IdleExpiresAt   time.Time
	ExpiresAt       time.Time
	CorrelationID   audit.CorrelationID
}

type PasskeyAuthResult struct {
	UserPublicID        identity.PublicID
	ApplicationPublicID applicationinstance.PublicID
}

type PasskeyPersistence interface {
	ListPasskeyCredentials(context.Context, applicationinstance.InternalID, identity.InternalID) ([]PasskeyCredential, error)
	CreatePasskeyAttempt(context.Context, PasskeyAttemptWrite) (string, error)
	ConsumePasskeyAttempt(context.Context, applicationinstance.InternalID, string, string, string) (PasskeyAttempt, error)
	CreatePasskeyCredential(context.Context, PasskeyAttempt, PasskeyCredential, audit.CorrelationID) (PasskeyCredential, error)
	LoadPasskeyUserByHandle(context.Context, applicationinstance.InternalID, string, []byte, []byte) (PasskeyProtocolUser, error)
	FinalizePasskeyAuthentication(context.Context, PasskeyAuthFinalize) (PasskeyAuthResult, error)
	RemovePasskeyCredential(context.Context, PasskeySession, string, audit.CorrelationID) error
}

type PasskeyBeginResult struct {
	AttemptID string          `json:"attempt_id"`
	PublicKey json.RawMessage `json:"public_key"`
	ExpiresIn int64           `json:"expires_in"`
}

type PasskeyView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type PasskeyService struct {
	persistence PasskeyPersistence
	protocol    PasskeyProtocol
	now         func() time.Time
}

func NewPasskeyService(persistence PasskeyPersistence, protocol PasskeyProtocol) *PasskeyService {
	return &PasskeyService{persistence: persistence, protocol: protocol, now: time.Now}
}

func (s *PasskeyService) BeginRegistration(ctx context.Context, current PasskeySession, origin string) (PasskeyBeginResult, error) {
	if s == nil || s.persistence == nil || s.protocol == nil || s.now == nil {
		return PasskeyBeginResult{}, ErrPasskeyUnavailable
	}
	now := s.now().UTC()
	if err := validateFreshPasskeySession(current, now); err != nil {
		return PasskeyBeginResult{}, err
	}
	rpID, err := passkeyRPID(origin)
	if err != nil {
		return PasskeyBeginResult{}, ErrPasskeyInvalidRequest
	}
	credentials, err := s.persistence.ListPasskeyCredentials(ctx, current.ApplicationInstanceID, current.UserID)
	if err != nil {
		return PasskeyBeginResult{}, mapPasskeyPersistenceError(ctx, err)
	}
	user := PasskeyProtocolUser{UserID: current.UserID, PublicID: current.UserPublicID, Credentials: credentials}
	options, sessionData, challenge, err := s.protocol.BeginRegistration(user, rpID, origin)
	if err != nil {
		return PasskeyBeginResult{}, ErrPasskeyUnavailable
	}
	challengeRaw, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	if err != nil || len(challengeRaw) < 16 {
		return PasskeyBeginResult{}, ErrPasskeyUnavailable
	}
	deadline := earliestTime(now.Add(PasskeyAttemptTTL), current.CreatedAt.UTC().Add(SocialLinkFreshness), current.IdleExpiresAt.UTC(), current.ExpiresAt.UTC())
	if !deadline.After(now) {
		return PasskeyBeginResult{}, ErrPasskeyReverificationRequired
	}
	attemptID, err := s.persistence.CreatePasskeyAttempt(ctx, PasskeyAttemptWrite{
		ApplicationInstanceID: current.ApplicationInstanceID,
		UserID:                current.UserID,
		SessionPublicID:       current.SessionPublicID,
		Purpose:               "registration",
		Origin:                origin,
		RPID:                  rpID,
		SessionData:           sessionData,
		ChallengeHash:         sha256.Sum256(challengeRaw),
		CreatedAt:             now,
		ExpiresAt:             deadline,
	})
	if err != nil {
		return PasskeyBeginResult{}, mapPasskeyPersistenceError(ctx, err)
	}
	return PasskeyBeginResult{AttemptID: attemptID, PublicKey: options, ExpiresIn: int64(deadline.Sub(now) / time.Second)}, nil
}

func (s *PasskeyService) FinishRegistration(ctx context.Context, current PasskeySession, origin, attemptID, name string, response json.RawMessage, correlationID audit.CorrelationID) (PasskeyView, error) {
	if s == nil || s.persistence == nil || s.protocol == nil || s.now == nil || correlationID == (audit.CorrelationID{}) || !ValidPasskeyAttemptPublicID(attemptID) || len(response) == 0 {
		return PasskeyView{}, ErrPasskeyInvalidRequest
	}
	if err := validatePasskeyName(name); err != nil {
		return PasskeyView{}, err
	}
	if err := validateFreshPasskeySession(current, s.now().UTC()); err != nil {
		return PasskeyView{}, err
	}
	attempt, err := s.persistence.ConsumePasskeyAttempt(ctx, current.ApplicationInstanceID, attemptID, "registration", origin)
	if err != nil {
		return PasskeyView{}, mapPasskeyPersistenceError(ctx, err)
	}
	if attempt.UserID != current.UserID || attempt.SessionPublicID != current.SessionPublicID || attempt.UserPublicID != current.UserPublicID {
		return PasskeyView{}, ErrPasskeyInvalidAttempt
	}
	credentials, err := s.persistence.ListPasskeyCredentials(ctx, current.ApplicationInstanceID, current.UserID)
	if err != nil {
		return PasskeyView{}, mapPasskeyPersistenceError(ctx, err)
	}
	user := PasskeyProtocolUser{UserID: current.UserID, PublicID: current.UserPublicID, Credentials: credentials}
	credential, err := s.protocol.FinishRegistration(user, attempt.RPID, attempt.Origin, attempt.SessionData, response)
	if err != nil {
		return PasskeyView{}, ErrPasskeyProof
	}
	credential.Name = name
	created, err := s.persistence.CreatePasskeyCredential(ctx, attempt, credential, correlationID)
	if err != nil {
		return PasskeyView{}, mapPasskeyPersistenceError(ctx, err)
	}
	return PasskeyView{ID: created.PublicID, Name: created.Name, CreatedAt: created.CreatedAt.UTC()}, nil
}

func (s *PasskeyService) BeginAuthentication(ctx context.Context, app applicationinstance.Instance, origin string) (PasskeyBeginResult, error) {
	if s == nil || s.persistence == nil || s.protocol == nil || s.now == nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
		return PasskeyBeginResult{}, ErrPasskeyUnavailable
	}
	rpID, err := passkeyRPID(origin)
	if err != nil {
		return PasskeyBeginResult{}, ErrPasskeyInvalidRequest
	}
	options, sessionData, challenge, err := s.protocol.BeginAuthentication(rpID, origin)
	if err != nil {
		return PasskeyBeginResult{}, ErrPasskeyUnavailable
	}
	challengeRaw, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	if err != nil || len(challengeRaw) < 16 {
		return PasskeyBeginResult{}, ErrPasskeyUnavailable
	}
	now := s.now().UTC()
	attemptID, err := s.persistence.CreatePasskeyAttempt(ctx, PasskeyAttemptWrite{
		ApplicationInstanceID: app.InternalID,
		Purpose:               "authentication",
		Origin:                origin,
		RPID:                  rpID,
		SessionData:           sessionData,
		ChallengeHash:         sha256.Sum256(challengeRaw),
		CreatedAt:             now,
		ExpiresAt:             now.Add(PasskeyAttemptTTL),
	})
	if err != nil {
		return PasskeyBeginResult{}, mapPasskeyPersistenceError(ctx, err)
	}
	return PasskeyBeginResult{AttemptID: attemptID, PublicKey: options, ExpiresIn: int64(PasskeyAttemptTTL / time.Second)}, nil
}

func (s *PasskeyService) VerifyAuthentication(ctx context.Context, app applicationinstance.Instance, origin, attemptID string, response json.RawMessage) (PasskeyAttempt, PasskeyProtocolUser, PasskeyCredential, error) {
	if s == nil || s.persistence == nil || s.protocol == nil || !app.InternalID.Valid() || !app.PublicID.Valid() || !ValidPasskeyAttemptPublicID(attemptID) || len(response) == 0 {
		return PasskeyAttempt{}, PasskeyProtocolUser{}, PasskeyCredential{}, ErrPasskeyInvalidRequest
	}
	attempt, err := s.persistence.ConsumePasskeyAttempt(ctx, app.InternalID, attemptID, "authentication", origin)
	if err != nil {
		return PasskeyAttempt{}, PasskeyProtocolUser{}, PasskeyCredential{}, mapPasskeyPersistenceError(ctx, err)
	}
	loader := func(ctx context.Context, rawID, userHandle []byte) (PasskeyProtocolUser, error) {
		return s.persistence.LoadPasskeyUserByHandle(ctx, app.InternalID, attempt.RPID, rawID, userHandle)
	}
	user, credential, err := s.protocol.FinishAuthentication(ctx, attempt.RPID, attempt.Origin, attempt.SessionData, response, loader)
	if err != nil {
		return PasskeyAttempt{}, PasskeyProtocolUser{}, PasskeyCredential{}, ErrPasskeyProof
	}
	return attempt, user, credential, nil
}

func (s *PasskeyService) List(ctx context.Context, current PasskeySession) ([]PasskeyView, error) {
	if s == nil || s.persistence == nil || !current.ApplicationInstanceID.Valid() || !current.UserID.Valid() {
		return nil, ErrPasskeyUnavailable
	}
	credentials, err := s.persistence.ListPasskeyCredentials(ctx, current.ApplicationInstanceID, current.UserID)
	if err != nil {
		return nil, mapPasskeyPersistenceError(ctx, err)
	}
	if len(credentials) > PasskeyListLimit {
		credentials = credentials[:PasskeyListLimit]
	}
	out := make([]PasskeyView, 0, len(credentials))
	for _, credential := range credentials {
		out = append(out, PasskeyView{ID: credential.PublicID, Name: credential.Name, CreatedAt: credential.CreatedAt.UTC()})
	}
	return out, nil
}

func (s *PasskeyService) Remove(ctx context.Context, current PasskeySession, publicID string, correlationID audit.CorrelationID) error {
	if s == nil || s.persistence == nil || correlationID == (audit.CorrelationID{}) || !ValidPasskeyPublicID(publicID) {
		return ErrPasskeyInvalidRequest
	}
	if err := validateFreshPasskeySession(current, s.now().UTC()); err != nil {
		return err
	}
	return mapPasskeyPersistenceError(ctx, s.persistence.RemovePasskeyCredential(ctx, current, publicID, correlationID))
}

func ValidPasskeyPublicID(value string) bool {
	return validPrefixedUUIDv4(value, "pky_")
}

func ValidPasskeyAttemptPublicID(value string) bool {
	return validPrefixedUUIDv4(value, "pka_")
}

func validPrefixedUUIDv4(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+36 {
		return false
	}
	uuid := value[len(prefix):]
	if uuid[14] != '4' || (uuid[19] != '8' && uuid[19] != '9' && uuid[19] != 'a' && uuid[19] != 'b') {
		return false
	}
	for i := range uuid {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if uuid[i] != '-' {
				return false
			}
			continue
		}
		if !((uuid[i] >= '0' && uuid[i] <= '9') || (uuid[i] >= 'a' && uuid[i] <= 'f')) {
			return false
		}
	}
	return true
}

func passkeyRPID(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return "", ErrPasskeyInvalidRequest
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || len(host) > 253 {
		return "", ErrPasskeyInvalidRequest
	}
	return host, nil
}

func validatePasskeyName(name string) error {
	if name == "" {
		return nil
	}
	if strings.TrimSpace(name) != name || len(name) > PasskeyNameMaxBytes {
		return ErrPasskeyInvalidRequest
	}
	return nil
}

func validateFreshPasskeySession(current PasskeySession, now time.Time) error {
	if !current.ApplicationInstanceID.Valid() || !current.ApplicationPublicID.Valid() || !current.UserID.Valid() || !current.UserPublicID.Valid() || current.SessionPublicID == "" {
		return ErrPasskeyInvalidSession
	}
	if current.Revoked || !current.IdleExpiresAt.UTC().After(now) || !current.ExpiresAt.UTC().After(now) {
		return ErrPasskeyInvalidSession
	}
	if !now.Before(current.CreatedAt.UTC().Add(SocialLinkFreshness)) {
		return ErrPasskeyReverificationRequired
	}
	return nil
}

func mapPasskeyPersistenceError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	switch {
	case errors.Is(err, ErrPasskeyInvalidSession):
		return ErrPasskeyInvalidSession
	case errors.Is(err, ErrPasskeyReverificationRequired):
		return ErrPasskeyReverificationRequired
	case errors.Is(err, ErrPasskeyInvalidAttempt):
		return ErrPasskeyInvalidAttempt
	case errors.Is(err, ErrPasskeyNotFound):
		return ErrPasskeyNotFound
	case errors.Is(err, ErrLastAuthenticationMethod):
		return ErrLastAuthenticationMethod
	default:
		return ErrPasskeyPersistence
	}
}
