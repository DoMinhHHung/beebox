package session

import (
	"context"
	"encoding/json"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

type PasskeyService struct {
	core *authentication.PasskeyService
	ring *KeyRing
	now  func() time.Time
}

func NewPasskeyService(core *authentication.PasskeyService, ring *KeyRing) *PasskeyService {
	return &PasskeyService{core: core, ring: ring, now: time.Now}
}

func (s *PasskeyService) CompleteAuthentication(ctx context.Context, app applicationinstance.Instance, origin, attemptID string, response json.RawMessage, correlationID audit.CorrelationID) (TokenPair, error) {
	if s == nil || s.core == nil || s.ring == nil || s.now == nil || correlationID == (audit.CorrelationID{}) {
		return TokenPair{}, ErrSessionUnavailable
	}
	attempt, user, credential, err := s.core.VerifyAuthentication(ctx, app, origin, attemptID, response)
	if err != nil {
		return TokenPair{}, err
	}
	if attempt.ApplicationInstanceID != app.InternalID || attempt.ApplicationPublicID != app.PublicID || !user.UserID.Valid() || !user.PublicID.Valid() {
		return TokenPair{}, authentication.ErrPasskeyProof
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
	pending, pendingToken, err := preparePendingMFA(authentication.PrimaryMethodPasskey, "passkey:"+attempt.PublicID, now)
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	result, assurance, err := s.core.FinalizeAuthenticationWithAssurance(ctx, authentication.PasskeyAuthFinalize{
		AttemptPublicID: attempt.PublicID,
		UserID:          user.UserID,
		Credential:      credential,
		SessionPublicID: sessionID,
		RefreshVerifier: refreshHash,
		IdleExpiresAt:   now.Add(InactivityLifetime),
		ExpiresAt:       now.Add(AbsoluteLifetime),
		CorrelationID:   correlationID,
	}, pending)
	if err != nil {
		return TokenPair{}, err
	}
	if assurance.MFARequired {
		if assurance.PendingMFAPublicID != pending.PublicID || !assurance.PendingMFAExpiresAt.Equal(pending.ExpiresAt) {
			return TokenPair{}, ErrSessionUnavailable
		}
		return TokenPair{PendingMFA: &PendingMFA{Token: pendingToken, ExpiresAt: assurance.PendingMFAExpiresAt.UTC(), AvailableMethods: pendingMFAMethods(assurance.RecoveryCodeAvailable)}}, nil
	}
	access, err := s.ring.Sign(string(result.UserPublicID), string(result.ApplicationPublicID), sessionID, now)
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	return TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresIn: int64(AccessTokenLifetime / time.Second), SessionID: sessionID}, nil
}
