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
	EmailOTPCodeTTL        = 10 * time.Minute
	EmailOTPIssueWindow    = 15 * time.Minute
	EmailOTPResendCooldown = time.Minute
	EmailOTPMaxIssues      = 3
	EmailOTPMaxAttempts    = 5
)

var (
	ErrEmailOTPInvalid     = errors.New("invalid email OTP credentials")
	ErrEmailOTPRateLimited = errors.New("email OTP rate limited")
	ErrEmailOTPDelivery    = errors.New("email OTP delivery failure")
	ErrEmailOTPPersistence = errors.New("email OTP persistence failure")
	ErrEmailOTPStale       = errors.New("stale email OTP challenge")
)

type EmailOTPDelivery interface {
	DeliverSignInCode(context.Context, string, string, time.Time) error
}

type EmailOTPIssue struct {
	ApplicationInstanceID applicationinstance.InternalID
	NormalizedEmail       string
	CodeHash              VerificationCodeHash
	CorrelationID         audit.CorrelationID
}

type EmailOTPIssueResult struct {
	ShouldSend  bool
	Destination string
	ExpiresAt   time.Time
}

type EmailOTPChallengeSnapshot struct {
	UserID              identity.InternalID
	EmailIdentifierID   identity.EmailIdentifierInternalID
	ChallengeGeneration int64
	CodeHash            VerificationCodeHash
	ExpiresAt           time.Time
	FailedAttempts      int
}

type EmailOTPFinalize struct {
	ApplicationInstanceID applicationinstance.InternalID
	EmailIdentifierID     identity.EmailIdentifierInternalID
	UserID                identity.InternalID
	ChallengeGeneration   int64
	Matched               bool
	SessionPublicID       string
	RefreshVerifier       [32]byte
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	PendingMFA            PendingMFAWrite
	CorrelationID         audit.CorrelationID
}

type EmailOTPFinalizeResult struct {
	UserPublicID        string
	ApplicationPublicID string
	MFARequired         bool
	PendingMFAPublicID  string
	PendingMFAExpiresAt time.Time
}

type EmailOTPPersistence interface {
	IssueEmailOTP(context.Context, EmailOTPIssue) (EmailOTPIssueResult, error)
	LoadEmailOTP(context.Context, applicationinstance.InternalID, string) (EmailOTPChallengeSnapshot, error)
	FinalizeEmailOTP(context.Context, EmailOTPFinalize) (EmailOTPFinalizeResult, error)
}

type EmailOTPService struct {
	persistence EmailOTPPersistence
	delivery    EmailOTPDelivery
}

func NewEmailOTPService(persistence EmailOTPPersistence, delivery EmailOTPDelivery) *EmailOTPService {
	return &EmailOTPService{persistence: persistence, delivery: delivery}
}

func (s *EmailOTPService) RequestWithCorrelation(ctx context.Context, appID applicationinstance.InternalID, rawEmail string, correlationID audit.CorrelationID) error {
	if s == nil || s.persistence == nil || s.delivery == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return ErrEmailOTPPersistence
	}
	admission, ok := s.persistence.(EmailOTPAdmission)
	if !ok {
		return ErrEmailOTPPersistence
	}
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return identity.ErrInvalidEmail
	}
	fingerprint := sha256.Sum256([]byte("email-otp-issue-email\x00" + email.ComparisonKey))
	if err := admission.AllowEmailOTPIssue(ctx, appID, fingerprint); err != nil {
		if errors.Is(err, ErrPublicRateLimited) || errors.Is(err, ErrEmailOTPRateLimited) {
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
	result, err := s.persistence.IssueEmailOTP(ctx, EmailOTPIssue{
		ApplicationInstanceID: appID,
		NormalizedEmail:       email.ComparisonKey,
		CodeHash:              codeHash,
		CorrelationID:         correlationID,
	})
	if err != nil {
		if errors.Is(err, ErrEmailOTPRateLimited) || errors.Is(err, ErrEmailOTPInvalid) {
			return nil
		}
		return err
	}
	if !result.ShouldSend {
		return nil
	}
	if err := s.delivery.DeliverSignInCode(ctx, result.Destination, code, result.ExpiresAt); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrEmailOTPDelivery
	}
	return nil
}
