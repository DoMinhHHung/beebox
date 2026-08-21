package session

import (
	"context"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

type RecoveryAuthenticationService struct {
	core *authentication.RecoveryCodeService
	ring *KeyRing
	now  func() time.Time
}

func NewRecoveryAuthenticationService(core *authentication.RecoveryCodeService, ring *KeyRing) *RecoveryAuthenticationService {
	return &RecoveryAuthenticationService{core: core, ring: ring, now: time.Now}
}

func (s *RecoveryAuthenticationService) Complete(ctx context.Context, appID applicationinstance.InternalID, pendingToken, code string, correlationID audit.CorrelationID) (TokenPair, error) {
	if s == nil || s.core == nil || s.ring == nil || s.now == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return TokenPair{}, ErrSessionUnavailable
	}
	pendingPublicID, tokenHash, ok := parsePendingMFAToken(pendingToken)
	if !ok {
		return TokenPair{}, ErrInvalidCredentials
	}
	sessionID, err := NewPublicID()
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	refresh, refreshHash, err := GenerateRefreshSecret()
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	now := s.now().UTC()
	result, err := s.core.CompletePendingAuthentication(ctx, appID, pendingPublicID, tokenHash, code, authentication.RecoveryAuthenticationFinalize{
		SessionPublicID: sessionID,
		RefreshVerifier: refreshHash,
		IdleExpiresAt:   now.Add(InactivityLifetime),
		ExpiresAt:       now.Add(AbsoluteLifetime),
		CorrelationID:   correlationID,
	})
	if err != nil {
		return TokenPair{}, err
	}
	access, err := s.ring.Sign(string(result.UserPublicID), string(result.ApplicationPublicID), sessionID, now)
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
