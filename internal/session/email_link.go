package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

type EmailLinkConfirmResult struct {
	TokenPair     TokenPair
	CompletionURL string
}

type EmailLinkService struct {
	persistence authentication.EmailLinkPersistence
	ring        *KeyRing
	now         func() time.Time
}

func NewEmailLinkService(persistence authentication.EmailLinkPersistence, ring *KeyRing) *EmailLinkService {
	return &EmailLinkService{persistence: persistence, ring: ring, now: time.Now}
}

func (s *EmailLinkService) Confirm(ctx context.Context, appID applicationinstance.InternalID, challengeID, secret string, correlationID audit.CorrelationID) (EmailLinkConfirmResult, error) {
	if s == nil || s.persistence == nil || s.ring == nil || !appID.Valid() || !authentication.ValidEmailLinkChallengeID(challengeID) || secret == "" || correlationID == (audit.CorrelationID{}) {
		return EmailLinkConfirmResult{}, ErrInvalidCredentials
	}
	admission, ok := s.persistence.(authentication.EmailLinkAdmission)
	if !ok {
		return EmailLinkConfirmResult{}, ErrSessionUnavailable
	}
	fingerprint := sha256.Sum256([]byte("email-link-confirm-challenge\x00" + challengeID))
	if err := admission.AllowEmailLinkConfirm(ctx, appID, fingerprint); err != nil {
		if errors.Is(err, authentication.ErrPublicRateLimited) || errors.Is(err, authentication.ErrEmailLinkRateLimited) {
			return EmailLinkConfirmResult{}, ErrSignInRateLimited
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return EmailLinkConfirmResult{}, ctxErr
		}
		return EmailLinkConfirmResult{}, ErrSessionUnavailable
	}

	snapshot, err := s.persistence.LoadEmailLink(ctx, appID, challengeID)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return EmailLinkConfirmResult{}, ctxErr
		}
		if errors.Is(err, authentication.ErrEmailLinkInvalid) || errors.Is(err, authentication.ErrEmailLinkStale) {
			return EmailLinkConfirmResult{}, ErrInvalidCredentials
		}
		return EmailLinkConfirmResult{}, ErrSessionUnavailable
	}
	candidate, hashErr := authentication.EmailLinkSecretHash(appID, challengeID, snapshot.CompletionURL, secret)
	matched := hashErr == nil && subtle.ConstantTimeCompare(candidate[:], snapshot.SecretHash[:]) == 1

	var sessionID, refresh string
	var refreshHash [32]byte
	var pending authentication.PendingMFAWrite
	var pendingToken string
	now := s.now().UTC()
	if matched {
		sessionID, err = NewPublicID()
		if err != nil {
			return EmailLinkConfirmResult{}, ErrSessionUnavailable
		}
		refresh, refreshHash, err = GenerateRefreshSecret()
		if err != nil {
			return EmailLinkConfirmResult{}, ErrSessionUnavailable
		}
		pending, pendingToken, err = preparePendingMFA(authentication.PrimaryMethodEmailLink, challengeID, now)
		if err != nil {
			return EmailLinkConfirmResult{}, ErrSessionUnavailable
		}
	}

	result, err := s.persistence.FinalizeEmailLink(ctx, authentication.EmailLinkFinalize{
		ApplicationInstanceID: appID,
		EmailIdentifierID:     snapshot.EmailIdentifierID,
		UserID:                snapshot.UserID,
		ChallengePublicID:     snapshot.ChallengePublicID,
		ChallengeGeneration:   snapshot.ChallengeGeneration,
		CompletionURL:         snapshot.CompletionURL,
		Matched:               matched,
		SessionPublicID:       sessionID,
		RefreshVerifier:       refreshHash,
		IdleExpiresAt:         now.Add(InactivityLifetime),
		ExpiresAt:             now.Add(AbsoluteLifetime),
		PendingMFA:            pending,
		CorrelationID:         correlationID,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return EmailLinkConfirmResult{}, ctxErr
		}
		if errors.Is(err, authentication.ErrEmailLinkInvalid) || errors.Is(err, authentication.ErrEmailLinkStale) {
			return EmailLinkConfirmResult{}, ErrInvalidCredentials
		}
		return EmailLinkConfirmResult{}, ErrSessionUnavailable
	}
	if !matched {
		return EmailLinkConfirmResult{}, ErrInvalidCredentials
	}
	if result.MFARequired {
		if result.PendingMFAPublicID != pending.PublicID || !result.PendingMFAExpiresAt.Equal(pending.ExpiresAt) {
			return EmailLinkConfirmResult{}, ErrSessionUnavailable
		}
		return EmailLinkConfirmResult{
			TokenPair: TokenPair{PendingMFA: &PendingMFA{
				Token:            pendingToken,
				ExpiresAt:        result.PendingMFAExpiresAt.UTC(),
				AvailableMethods: pendingMFAMethods(result.RecoveryCodeAvailable),
			}},
			CompletionURL: snapshot.CompletionURL,
		}, nil
	}
	access, err := s.ring.Sign(result.UserPublicID, result.ApplicationPublicID, sessionID, now)
	if err != nil {
		return EmailLinkConfirmResult{}, ErrSessionUnavailable
	}
	return EmailLinkConfirmResult{
		TokenPair: TokenPair{
			AccessToken:  access,
			RefreshToken: refresh,
			ExpiresIn:    int64(AccessTokenLifetime / time.Second),
			SessionID:    sessionID,
		},
		CompletionURL: snapshot.CompletionURL,
	}, nil
}
