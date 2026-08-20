package session

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

// PhoneSignupService converts a successfully proven phone-signup challenge into
// the ordinary BeeBox session class. It creates a new principal only inside the
// persistence finalization transaction after proof succeeds.
type PhoneSignupService struct {
	persistence authentication.PhoneSignupPersistence
	ring        *KeyRing
	now         func() time.Time
}

func NewPhoneSignupService(persistence authentication.PhoneSignupPersistence, ring *KeyRing) *PhoneSignupService {
	return &PhoneSignupService{persistence: persistence, ring: ring, now: time.Now}
}

func (s *PhoneSignupService) Confirm(ctx context.Context, appID applicationinstance.InternalID, rawPhone, code string, correlationID audit.CorrelationID) (TokenPair, error) {
	if s == nil || s.persistence == nil || s.ring == nil || s.now == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return TokenPair{}, ErrSessionUnavailable
	}
	phone, err := identity.NormalizePhone(rawPhone)
	if err != nil || !validPhoneOTPCode(code) {
		return TokenPair{}, ErrInvalidCredentials
	}
	admission, ok := s.persistence.(authentication.PhoneSignupAdmission)
	if !ok {
		return TokenPair{}, ErrSessionUnavailable
	}
	admissionFingerprint := sha256.Sum256([]byte("phone-signup-confirm\x00" + phone.E164))
	if err := admission.AllowPhoneSignupConfirm(ctx, appID, admissionFingerprint); err != nil {
		if errors.Is(err, authentication.ErrPublicRateLimited) || errors.Is(err, authentication.ErrPhoneSignupRateLimited) {
			return TokenPair{}, ErrSignInRateLimited
		}
		return TokenPair{}, ErrSessionUnavailable
	}
	fingerprint := authentication.PhoneSignupFingerprint(phone.E164)
	snapshot, err := s.persistence.LoadPhoneSignup(ctx, appID, fingerprint)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return TokenPair{}, ctxErr
		}
		if errors.Is(err, authentication.ErrPhoneSignupInvalid) || errors.Is(err, authentication.ErrPhoneSignupStale) {
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

	finalize := authentication.PhoneSignupFinalize{
		ApplicationInstanceID: appID,
		PhoneFingerprint:      fingerprint,
		PhoneE164:             phone.E164,
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
	result, err := s.persistence.FinalizePhoneSignup(ctx, finalize)
	if err != nil {
		if errors.Is(err, authentication.ErrPhoneSignupInvalid) || errors.Is(err, authentication.ErrPhoneSignupStale) {
			return TokenPair{}, ErrInvalidCredentials
		}
		if errors.Is(err, authentication.ErrPhoneSignupRateLimited) {
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
	return TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresIn: int64(AccessTokenLifetime / time.Second), SessionID: finalize.SessionPublicID}, nil
}

type PhoneOTPAssurancePersistence interface {
	FinalizePhoneOTPWithAssurance(context.Context, authentication.PhoneOTPFinalize, authentication.PendingMFAWrite) (authentication.PhoneOTPFinalizeResult, authentication.PrimaryAssuranceResult, error)
}

// PhoneOTPService is a primary authentication method for an existing verified
// phone identifier. Production persistence gates the proof on active TOTP before
// any ordinary session material is committed.
type PhoneOTPService struct {
	persistence authentication.PhoneOTPPersistence
	ring        *KeyRing
	now         func() time.Time
}

func NewPhoneOTPService(persistence authentication.PhoneOTPPersistence, ring *KeyRing) *PhoneOTPService {
	return &PhoneOTPService{persistence: persistence, ring: ring, now: time.Now}
}

func (s *PhoneOTPService) Confirm(ctx context.Context, appID applicationinstance.InternalID, rawPhone, code string, correlationID audit.CorrelationID) (TokenPair, error) {
	if s == nil || s.persistence == nil || s.ring == nil || s.now == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return TokenPair{}, ErrSessionUnavailable
	}
	phone, err := identity.NormalizePhone(rawPhone)
	if err != nil || !validPhoneOTPCode(code) {
		return TokenPair{}, ErrInvalidCredentials
	}
	admission, ok := s.persistence.(authentication.PhoneOTPAdmission)
	if !ok {
		return TokenPair{}, ErrSessionUnavailable
	}
	fingerprint := sha256.Sum256([]byte("phone-otp-confirm\x00" + phone.E164))
	if err := admission.AllowPhoneOTPConfirm(ctx, appID, fingerprint); err != nil {
		if errors.Is(err, authentication.ErrPublicRateLimited) || errors.Is(err, authentication.ErrPhoneOTPRateLimited) {
			return TokenPair{}, ErrSignInRateLimited
		}
		return TokenPair{}, ErrSessionUnavailable
	}
	snapshot, err := s.persistence.LoadPhoneOTP(ctx, appID, phone.E164)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return TokenPair{}, ctxErr
		}
		if errors.Is(err, authentication.ErrPhoneOTPInvalid) || errors.Is(err, authentication.ErrPhoneOTPStale) {
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

	finalize := authentication.PhoneOTPFinalize{
		ApplicationInstanceID: appID,
		PhoneIdentifierID:     snapshot.PhoneIdentifierID,
		UserID:                snapshot.UserID,
		ChallengeGeneration:   snapshot.ChallengeGeneration,
		Matched:               matched,
		CorrelationID:         correlationID,
	}
	var refresh, pendingToken string
	var issuedAt time.Time
	var pending authentication.PendingMFAWrite
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
		pending, pendingToken, err = preparePendingMFA(authentication.PrimaryMethodPhoneOTP, "phone_otp:"+strconv.FormatInt(snapshot.ChallengeGeneration, 10), issuedAt)
		if err != nil {
			return TokenPair{}, ErrSessionUnavailable
		}
	}
	var result authentication.PhoneOTPFinalizeResult
	var assurance authentication.PrimaryAssuranceResult
	if matched {
		if p, ok := s.persistence.(PhoneOTPAssurancePersistence); ok {
			result, assurance, err = p.FinalizePhoneOTPWithAssurance(ctx, finalize, pending)
		} else {
			result, err = s.persistence.FinalizePhoneOTP(ctx, finalize)
		}
	} else {
		result, err = s.persistence.FinalizePhoneOTP(ctx, finalize)
	}
	if err != nil {
		if errors.Is(err, authentication.ErrPhoneOTPInvalid) || errors.Is(err, authentication.ErrPhoneOTPStale) {
			return TokenPair{}, ErrInvalidCredentials
		}
		if errors.Is(err, authentication.ErrPhoneOTPRateLimited) {
			return TokenPair{}, ErrSignInRateLimited
		}
		return TokenPair{}, ErrSessionUnavailable
	}
	if !matched {
		return TokenPair{}, ErrInvalidCredentials
	}
	if assurance.MFARequired {
		if assurance.PendingMFAPublicID != pending.PublicID || !assurance.PendingMFAExpiresAt.Equal(pending.ExpiresAt) {
			return TokenPair{}, ErrSessionUnavailable
		}
		return TokenPair{PendingMFA: &PendingMFA{Token: pendingToken, ExpiresAt: assurance.PendingMFAExpiresAt.UTC(), AvailableMethods: pendingMFAMethods(assurance.RecoveryCodeAvailable)}}, nil
	}
	access, err := s.ring.Sign(result.UserPublicID, result.ApplicationPublicID, finalize.SessionPublicID, issuedAt)
	if err != nil {
		return TokenPair{}, ErrSessionUnavailable
	}
	return TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresIn: int64(AccessTokenLifetime / time.Second), SessionID: finalize.SessionPublicID}, nil
}

func validPhoneOTPCode(code string) bool {
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
