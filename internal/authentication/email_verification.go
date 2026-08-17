package authentication

import (
	"context"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	EmailVerificationCodeTTL        = 10 * time.Minute
	EmailVerificationIssueWindow    = 15 * time.Minute
	EmailVerificationResendCooldown = time.Minute
	EmailVerificationMaxIssues      = 3
	EmailVerificationMaxAttempts    = 5
)

var (
	ErrInvalidEmailIdentifierInternalID   = errors.New("invalid email identifier internal identifier")
	ErrEmailVerificationChallengeNotFound = errors.New("email verification challenge not found")
	ErrEmailVerificationAlreadyCompleted  = errors.New("email verification already completed")
	ErrEmailVerificationExpired           = errors.New("email verification expired")
	ErrEmailVerificationMismatch          = errors.New("email verification mismatch")
	ErrEmailVerificationAttemptLimit      = errors.New("email verification attempt limit")
	ErrEmailVerificationResendCooldown    = errors.New("email verification resend cooldown")
	ErrEmailVerificationIssueLimit        = errors.New("email verification issue limit")
	ErrEmailVerificationStaleChallenge    = errors.New("stale email verification challenge")
	ErrEmailVerificationDelivery          = errors.New("email verification delivery failure")
	ErrEmailVerificationPersistence       = errors.New("email verification persistence failure")
)

type EmailVerificationDelivery interface {
	DeliverVerificationCode(ctx context.Context, destination string, code string, expiresAt time.Time) error
}

type EmailVerificationIssue struct {
	ApplicationInstanceID applicationinstance.InternalID
	EmailIdentifierID     identity.EmailIdentifierInternalID
	CodeHash              VerificationCodeHash
	CorrelationID         audit.CorrelationID
}

type EmailVerificationIssueResult struct {
	Destination string
	ExpiresAt   time.Time
}

type EmailVerificationChallengeSnapshot struct {
	Generation     int64
	CodeHash       VerificationCodeHash
	ExpiresAt      time.Time
	FailedAttempts int
}

type EmailVerificationAttempt struct {
	ApplicationInstanceID applicationinstance.InternalID
	EmailIdentifierID     identity.EmailIdentifierInternalID
	Generation            int64
	Matched               bool
	CorrelationID         audit.CorrelationID
}

type VerifiedEmailResult struct {
	EmailIdentifier identity.EmailIdentifier
}

type EmailVerificationPersistence interface {
	IssueEmailVerification(context.Context, EmailVerificationIssue) (EmailVerificationIssueResult, error)
	LoadEmailVerificationChallenge(context.Context, applicationinstance.InternalID, identity.EmailIdentifierInternalID) (EmailVerificationChallengeSnapshot, error)
	FinalizeEmailVerification(context.Context, EmailVerificationAttempt) (VerifiedEmailResult, error)
}

type EmailVerificationService struct {
	persistence EmailVerificationPersistence
	delivery    EmailVerificationDelivery
}

func NewEmailVerificationService(persistence EmailVerificationPersistence, delivery EmailVerificationDelivery) *EmailVerificationService {
	return &EmailVerificationService{persistence: persistence, delivery: delivery}
}

func (s *EmailVerificationService) IssueEmailVerification(
	ctx context.Context,
	applicationInstanceID applicationinstance.InternalID,
	emailIdentifierID identity.EmailIdentifierInternalID,
) error {
	if !applicationInstanceID.Valid() {
		return ErrInvalidApplicationInstanceScope
	}
	if !emailIdentifierID.Valid() {
		return ErrInvalidEmailIdentifierInternalID
	}
	if s == nil || s.persistence == nil {
		return ErrEmailVerificationPersistence
	}
	if s.delivery == nil {
		return ErrEmailVerificationDelivery
	}

	code, err := GenerateVerificationCode()
	if err != nil {
		return err
	}
	codeHash, err := HashVerificationCode(code)
	if err != nil {
		return err
	}
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		return ErrEmailVerificationPersistence
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	issued, err := s.persistence.IssueEmailVerification(ctx, EmailVerificationIssue{
		ApplicationInstanceID: applicationInstanceID,
		EmailIdentifierID:     emailIdentifierID,
		CodeHash:              codeHash,
		CorrelationID:         correlationID,
	})
	if err != nil {
		return err
	}
	if err := s.delivery.DeliverVerificationCode(ctx, issued.Destination, code, issued.ExpiresAt); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrEmailVerificationDelivery
	}
	return nil
}

func (s *EmailVerificationService) VerifyEmailCode(
	ctx context.Context,
	applicationInstanceID applicationinstance.InternalID,
	emailIdentifierID identity.EmailIdentifierInternalID,
	rawCode string,
) (VerifiedEmailResult, error) {
	if !applicationInstanceID.Valid() {
		return VerifiedEmailResult{}, ErrInvalidApplicationInstanceScope
	}
	if !emailIdentifierID.Valid() {
		return VerifiedEmailResult{}, ErrInvalidEmailIdentifierInternalID
	}
	if !validVerificationCode(rawCode) {
		return VerifiedEmailResult{}, ErrInvalidVerificationCode
	}
	if s == nil || s.persistence == nil {
		return VerifiedEmailResult{}, ErrEmailVerificationPersistence
	}

	snapshot, err := s.persistence.LoadEmailVerificationChallenge(ctx, applicationInstanceID, emailIdentifierID)
	if err != nil {
		return VerifiedEmailResult{}, err
	}

	matched := true
	if err := VerifyVerificationCode(snapshot.CodeHash, rawCode); err != nil {
		switch {
		case errors.Is(err, ErrVerificationCodeMismatch):
			matched = false
		case errors.Is(err, ErrInvalidVerificationCodeHash):
			return VerifiedEmailResult{}, ErrEmailVerificationPersistence
		default:
			return VerifiedEmailResult{}, err
		}
	}

	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		return VerifiedEmailResult{}, ErrEmailVerificationPersistence
	}
	if err := ctx.Err(); err != nil {
		return VerifiedEmailResult{}, err
	}

	return s.persistence.FinalizeEmailVerification(ctx, EmailVerificationAttempt{
		ApplicationInstanceID: applicationInstanceID,
		EmailIdentifierID:     emailIdentifierID,
		Generation:            snapshot.Generation,
		Matched:               matched,
		CorrelationID:         correlationID,
	})
}
