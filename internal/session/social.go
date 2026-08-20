package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

type SocialCompletionAssurancePersistence interface {
	ExchangeSocialCompletionWithAssurance(context.Context, authentication.SocialCompletionFinalize, authentication.PendingMFAWrite) (authentication.SocialCompletionResult, authentication.PrimaryAssuranceResult, error)
}

// SocialCompletionService turns a one-time, client-PKCE-bound social completion
// grant into either pending additional assurance or the ordinary BeeBox session
// class. Provider credentials and claims never cross this boundary.
type SocialCompletionService struct {
	persistence authentication.SocialCompletionPersistence
	admission   authentication.SocialAdmission
	ring        *KeyRing
	now         func() time.Time
}

func NewSocialCompletionService(persistence authentication.SocialCompletionPersistence, admission authentication.SocialAdmission, ring *KeyRing) *SocialCompletionService {
	return &SocialCompletionService{persistence: persistence, admission: admission, ring: ring, now: time.Now}
}

func (s *SocialCompletionService) Exchange(ctx context.Context, appID applicationinstance.InternalID, rawCode, verifier string, correlationID audit.CorrelationID) (TokenPair, error) {
	if s == nil || s.persistence == nil || s.admission == nil || s.ring == nil || s.now == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return TokenPair{}, ErrSessionUnavailable
	}
	if err := s.admission.AllowSocialExchange(ctx, appID); err != nil {
		if errors.Is(err, authentication.ErrPublicRateLimited) || errors.Is(err, authentication.ErrSocialRateLimited) {
			return TokenPair{}, ErrSignInRateLimited
		}
		return TokenPair{}, ErrSessionUnavailable
	}
	codeBytes, err := base64.RawURLEncoding.Strict().DecodeString(rawCode)
	if err != nil || len(codeBytes) != 32 || !authentication.ValidPKCEVerifier(verifier) {
		return TokenPair{}, ErrInvalidCredentials
	}
	challenge, ok := authentication.S256Challenge(verifier)
	if !ok {
		return TokenPair{}, ErrInvalidCredentials
	}
	codeHash := sha256.Sum256(codeBytes)
	sessionID, err := NewPublicID()
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	refresh, refreshVerifier, err := GenerateRefreshSecret()
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	issuedAt := s.now().UTC()
	final := authentication.SocialCompletionFinalize{
		ApplicationInstanceID: appID,
		CompletionCodeHash:    codeHash,
		ClientCodeChallenge:   challenge,
		SessionPublicID:       sessionID,
		RefreshVerifier:       refreshVerifier,
		IdleExpiresAt:         issuedAt.Add(InactivityLifetime),
		ExpiresAt:             issuedAt.Add(AbsoluteLifetime),
		CorrelationID:         correlationID,
	}
	pending, pendingToken, err := preparePendingMFA(authentication.PrimaryMethodSocial, "social_completion", issuedAt)
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	var result authentication.SocialCompletionResult
	var assurance authentication.PrimaryAssuranceResult
	if p, ok := s.persistence.(SocialCompletionAssurancePersistence); ok {
		result, assurance, err = p.ExchangeSocialCompletionWithAssurance(ctx, final, pending)
	} else {
		result, err = s.persistence.ExchangeSocialCompletion(ctx, final)
	}
	if err != nil {
		if errors.Is(err, authentication.ErrSocialCompletionInvalid) {
			return TokenPair{}, ErrInvalidCredentials
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return TokenPair{}, ctxErr
		}
		return TokenPair{}, ErrSessionUnavailable
	}
	if assurance.MFARequired {
		if assurance.PendingMFAPublicID != pending.PublicID || !assurance.PendingMFAExpiresAt.Equal(pending.ExpiresAt) {
			return TokenPair{}, ErrSessionUnavailable
		}
		return TokenPair{PendingMFA: &PendingMFA{Token: pendingToken, ExpiresAt: assurance.PendingMFAExpiresAt.UTC(), AvailableMethods: []string{"totp"}}}, nil
	}
	access, err := s.ring.Sign(result.UserPublicID, result.ApplicationPublicID, sessionID, issuedAt)
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	return TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresIn: int64(AccessTokenLifetime / time.Second), SessionID: sessionID}, nil
}
