package authentication

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	PhoneOTPCodeTTL        = 10 * time.Minute
	PhoneOTPIssueWindow    = 15 * time.Minute
	PhoneOTPResendCooldown = time.Minute
	PhoneOTPMaxIssues      = 3
	PhoneOTPMaxAttempts    = 5
)

var (
	ErrPhoneSignupInvalid     = errors.New("invalid phone signup credentials")
	ErrPhoneSignupRateLimited = errors.New("phone signup rate limited")
	ErrPhoneSignupDelivery    = errors.New("phone signup delivery failure")
	ErrPhoneSignupPersistence = errors.New("phone signup persistence failure")
	ErrPhoneSignupStale       = errors.New("stale phone signup challenge")

	ErrPhoneOTPInvalid     = errors.New("invalid phone OTP credentials")
	ErrPhoneOTPRateLimited = errors.New("phone OTP rate limited")
	ErrPhoneOTPDelivery    = errors.New("phone OTP delivery failure")
	ErrPhoneOTPPersistence = errors.New("phone OTP persistence failure")
	ErrPhoneOTPStale       = errors.New("stale phone OTP challenge")
)

type PhoneOTPDelivery interface {
	DeliverPhoneSignupCode(context.Context, string, string, time.Time) error
	DeliverPhoneSignInCode(context.Context, string, string, time.Time) error
}

type PhoneSignupAdmission interface {
	AllowPhoneSignupIssue(context.Context, applicationinstance.InternalID, [32]byte) error
	AllowPhoneSignupConfirm(context.Context, applicationinstance.InternalID, [32]byte) error
}

type PhoneOTPAdmission interface {
	AllowPhoneOTPIssue(context.Context, applicationinstance.InternalID, [32]byte) error
	AllowPhoneOTPConfirm(context.Context, applicationinstance.InternalID, [32]byte) error
}

type PhoneSignupIssue struct {
	ApplicationInstanceID applicationinstance.InternalID
	PhoneFingerprint      [32]byte
	PhoneE164             string
	CodeHash              VerificationCodeHash
	CorrelationID         audit.CorrelationID
}

type PhoneSignupIssueResult struct {
	ShouldSend  bool
	Destination string
	ExpiresAt   time.Time
}

type PhoneSignupChallengeSnapshot struct {
	ChallengeGeneration int64
	CodeHash            VerificationCodeHash
	ExpiresAt           time.Time
	FailedAttempts      int
}

type PhoneSignupFinalize struct {
	ApplicationInstanceID applicationinstance.InternalID
	PhoneFingerprint      [32]byte
	PhoneE164             string
	ChallengeGeneration   int64
	Matched               bool
	SessionPublicID       string
	RefreshVerifier       [32]byte
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	CorrelationID         audit.CorrelationID
}

type PhoneSignupFinalizeResult struct {
	UserPublicID        string
	ApplicationPublicID string
}

type PhoneSignupPersistence interface {
	IssuePhoneSignup(context.Context, PhoneSignupIssue) (PhoneSignupIssueResult, error)
	LoadPhoneSignup(context.Context, applicationinstance.InternalID, [32]byte) (PhoneSignupChallengeSnapshot, error)
	FinalizePhoneSignup(context.Context, PhoneSignupFinalize) (PhoneSignupFinalizeResult, error)
}

type PhoneSignupService struct {
	persistence PhoneSignupPersistence
	delivery    PhoneOTPDelivery
}

func NewPhoneSignupService(persistence PhoneSignupPersistence, delivery PhoneOTPDelivery) *PhoneSignupService {
	return &PhoneSignupService{persistence: persistence, delivery: delivery}
}

func PhoneSignupFingerprint(phoneE164 string) [32]byte {
	return sha256.Sum256([]byte("phone-signup\x00" + phoneE164))
}

func (s *PhoneSignupService) RequestWithCorrelation(ctx context.Context, appID applicationinstance.InternalID, rawPhone string, correlationID audit.CorrelationID) error {
	if s == nil || s.persistence == nil || s.delivery == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return ErrPhoneSignupPersistence
	}
	phone, err := identity.NormalizePhone(rawPhone)
	if err != nil {
		return identity.ErrInvalidPhone
	}
	admission, ok := s.persistence.(PhoneSignupAdmission)
	if !ok {
		return ErrPhoneSignupPersistence
	}
	admissionFingerprint := sha256.Sum256([]byte("phone-signup-issue\x00" + phone.E164))
	if err := admission.AllowPhoneSignupIssue(ctx, appID, admissionFingerprint); err != nil {
		if errors.Is(err, ErrPublicRateLimited) || errors.Is(err, ErrPhoneSignupRateLimited) {
			return nil
		}
		return err
	}
	code, err := GenerateVerificationCode()
	if err != nil {
		return err
	}
	codeHash, err := HashVerificationCodeContext(ctx, code)
	if errors.Is(err, ErrKDFAdmissionLimited) {
		return nil
	}
	if err != nil {
		return err
	}
	result, err := s.persistence.IssuePhoneSignup(ctx, PhoneSignupIssue{
		ApplicationInstanceID: appID,
		PhoneFingerprint:      PhoneSignupFingerprint(phone.E164),
		PhoneE164:             phone.E164,
		CodeHash:              codeHash,
		CorrelationID:         correlationID,
	})
	if err != nil {
		if errors.Is(err, ErrPhoneSignupRateLimited) || errors.Is(err, ErrPhoneSignupInvalid) || errors.Is(err, ErrPhoneSignupStale) {
			return nil
		}
		return err
	}
	if !result.ShouldSend {
		return nil
	}
	if err := s.delivery.DeliverPhoneSignupCode(ctx, result.Destination, code, result.ExpiresAt); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrPhoneSignupDelivery
	}
	return nil
}

type PhoneOTPIssue struct {
	ApplicationInstanceID applicationinstance.InternalID
	PhoneE164             string
	CodeHash              VerificationCodeHash
	CorrelationID         audit.CorrelationID
}

type PhoneOTPIssueResult struct {
	ShouldSend  bool
	Destination string
	ExpiresAt   time.Time
}

type PhoneOTPChallengeSnapshot struct {
	UserID              identity.InternalID
	PhoneIdentifierID   identity.PhoneIdentifierInternalID
	ChallengeGeneration int64
	CodeHash            VerificationCodeHash
	ExpiresAt           time.Time
	FailedAttempts      int
}

type PhoneOTPFinalize struct {
	ApplicationInstanceID applicationinstance.InternalID
	PhoneIdentifierID     identity.PhoneIdentifierInternalID
	UserID                identity.InternalID
	ChallengeGeneration   int64
	Matched               bool
	SessionPublicID       string
	RefreshVerifier       [32]byte
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	CorrelationID         audit.CorrelationID
}

type PhoneOTPFinalizeResult struct {
	UserPublicID        string
	ApplicationPublicID string
}

type PhoneOTPPersistence interface {
	IssuePhoneOTP(context.Context, PhoneOTPIssue) (PhoneOTPIssueResult, error)
	LoadPhoneOTP(context.Context, applicationinstance.InternalID, string) (PhoneOTPChallengeSnapshot, error)
	FinalizePhoneOTP(context.Context, PhoneOTPFinalize) (PhoneOTPFinalizeResult, error)
}

type PhoneOTPService struct {
	persistence PhoneOTPPersistence
	delivery    PhoneOTPDelivery
}

func NewPhoneOTPService(persistence PhoneOTPPersistence, delivery PhoneOTPDelivery) *PhoneOTPService {
	return &PhoneOTPService{persistence: persistence, delivery: delivery}
}

func (s *PhoneOTPService) RequestWithCorrelation(ctx context.Context, appID applicationinstance.InternalID, rawPhone string, correlationID audit.CorrelationID) error {
	if s == nil || s.persistence == nil || s.delivery == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return ErrPhoneOTPPersistence
	}
	phone, err := identity.NormalizePhone(rawPhone)
	if err != nil {
		return identity.ErrInvalidPhone
	}
	admission, ok := s.persistence.(PhoneOTPAdmission)
	if !ok {
		return ErrPhoneOTPPersistence
	}
	fingerprint := sha256.Sum256([]byte("phone-otp-issue\x00" + phone.E164))
	if err := admission.AllowPhoneOTPIssue(ctx, appID, fingerprint); err != nil {
		if errors.Is(err, ErrPublicRateLimited) || errors.Is(err, ErrPhoneOTPRateLimited) {
			return nil
		}
		return err
	}
	code, err := GenerateVerificationCode()
	if err != nil {
		return err
	}
	codeHash, err := HashVerificationCodeContext(ctx, code)
	if errors.Is(err, ErrKDFAdmissionLimited) {
		return nil
	}
	if err != nil {
		return err
	}
	result, err := s.persistence.IssuePhoneOTP(ctx, PhoneOTPIssue{
		ApplicationInstanceID: appID,
		PhoneE164:             phone.E164,
		CodeHash:              codeHash,
		CorrelationID:         correlationID,
	})
	if err != nil {
		if errors.Is(err, ErrPhoneOTPRateLimited) || errors.Is(err, ErrPhoneOTPInvalid) || errors.Is(err, ErrPhoneOTPStale) {
			return nil
		}
		return err
	}
	if !result.ShouldSend {
		return nil
	}
	if err := s.delivery.DeliverPhoneSignInCode(ctx, result.Destination, code, result.ExpiresAt); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrPhoneOTPDelivery
	}
	return nil
}
