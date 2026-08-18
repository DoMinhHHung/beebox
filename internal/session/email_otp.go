package session

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

// EmailOTPService turns an email-OTP primary proof into the ordinary BeeBox
// session transport used by password sign-in. It deliberately does not model
// future MFA policy; ADR 0005 remains the authority when additional assurance
// exists.
type EmailOTPService struct {
	persistence authentication.EmailOTPPersistence
	ring        *KeyRing
	now         func() time.Time
}

func NewEmailOTPService(persistence authentication.EmailOTPPersistence, ring *KeyRing) *EmailOTPService {
	return &EmailOTPService{persistence: persistence, ring: ring, now: time.Now}
}

func (s *EmailOTPService) Confirm(ctx context.Context, appID applicationinstance.InternalID, rawEmail, code string, correlationID audit.CorrelationID) (TokenPair, error) {
	if s == nil || s.persistence == nil || s.ring == nil || s.now == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return TokenPair{}, ErrSessionUnavailable
	}
	normalized, err := identity.NormalizeEmail(rawEmail)
	if err != nil || !validEmailOTPCode(code) {
		return TokenPair{}, ErrInvalidCredentials
	}
	admission, ok := s.persistence.(authentication.EmailOTPAdmission)
	if !ok {
		return TokenPair{}, ErrSessionUnavailable
	}
	fingerprint := sha256.Sum256([]byte("email-otp-confirm-email\x00" + normalized.ComparisonKey))
	if err := admission.AllowEmailOTPConfirm(ctx, appID, fingerprint); err != nil {
		if errors.Is(err, authentication.ErrPublicRateLimited) || errors.Is(err, authentication.ErrEmailOTPRateLimited) {
			return TokenPair{}, ErrSignInRateLimited
		}
		return TokenPair{}, ErrSessionUnavailable
	}
	snapshot, err := s.persistence.LoadEmailOTP(ctx, appID, normalized.ComparisonKey)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return TokenPair{}, ctxErr
		}
		if errors.Is(err, authentication.ErrEmailOTPInvalid) || errors.Is(err, authentication.ErrEmailOTPStale) {
			// Match the expensive verification class for unknown, unverified,
			// consumed and absent challenges without persisting attacker input.
			if _, dummyErr := authentication.HashVerificationCodeContext(ctx, code); errors.Is(dummyErr, authentication.ErrKDFAdmissionLimited) {
				return TokenPair{}, ErrSignInRateLimited
			} else if errors.Is(dummyErr, context.Canceled) || errors.Is(dummyErr, context.DeadlineExceeded) {
				return TokenPair{}, dummyErr
			}
			return TokenPair{}, ErrInvalidCredentials
		}
		return TokenPair{}, ErrSessionUnavailable
	}
	verifyErr := authentication.VerifyVerificationCodeContext(ctx, snapshot.CodeHash, code)
	if errors.Is(verifyErr, authentication.ErrKDFAdmissionLimited) {
		return TokenPair{}, ErrSignInRateLimited
	}
	matched := verifyErr == nil
	if verifyErr != nil && !errors.Is(verifyErr, authentication.ErrVerificationCodeMismatch) {
		if errors.Is(verifyErr, context.Canceled) || errors.Is(verifyErr, context.DeadlineExceeded) {
			return TokenPair{}, verifyErr
		}
		return TokenPair{}, ErrSessionUnavailable
	}

	finalize := authentication.EmailOTPFinalize{
		ApplicationInstanceID: appID,
		EmailIdentifierID:     snapshot.EmailIdentifierID,
		UserID:                snapshot.UserID,
		ChallengeGeneration:   snapshot.ChallengeGeneration,
		Matched:               matched,
		CorrelationID:         correlationID,
	}
	var refresh string
	var issuedAt time.Time
	if matched {
		finalize.SessionPublicID, err = NewPublicID()
		if err != nil {
			return TokenPair{}, ErrSessionUnavailable
		}
		refresh, finalize.RefreshVerifier, err = GenerateRefreshSecret()
		if err != nil {
			return TokenPair{}, ErrSessionUnavailable
		}
		issuedAt = s.now().UTC()
		finalize.IdleExpiresAt = issuedAt.Add(InactivityLifetime)
		finalize.ExpiresAt = issuedAt.Add(AbsoluteLifetime)
	}
	result, err := s.persistence.FinalizeEmailOTP(ctx, finalize)
	if err != nil {
		if errors.Is(err, authentication.ErrEmailOTPInvalid) || errors.Is(err, authentication.ErrEmailOTPStale) {
			return TokenPair{}, ErrInvalidCredentials
		}
		if errors.Is(err, authentication.ErrEmailOTPRateLimited) {
			return TokenPair{}, ErrSignInRateLimited
		}
		return TokenPair{}, ErrSessionUnavailable
	}
	if !matched {
		return TokenPair{}, ErrInvalidCredentials
	}
	access, err := s.ring.Sign(result.UserPublicID, result.ApplicationPublicID, finalize.SessionPublicID, issuedAt)
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	return TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int64(AccessTokenLifetime / time.Second),
		SessionID:    finalize.SessionPublicID,
	}, nil
}

func validEmailOTPCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}
