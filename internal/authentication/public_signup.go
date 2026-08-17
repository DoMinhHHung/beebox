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
	PublicSignupIdempotencyRetention = 24 * time.Hour
	PublicSignupGlobalLimit          = 100
	PublicSignupGlobalWindow         = time.Minute
	PublicSignupIdentifierLimit      = 5
	PublicSignupIdentifierWindow     = 15 * time.Minute
)

var (
	ErrPublicIdempotencyKey      = errors.New("invalid public idempotency key")
	ErrPublicIdempotencyConflict = errors.New("public idempotency conflict")
	ErrPublicRateLimited         = errors.New("public authentication rate limited")
	ErrPublicSignupPersistence   = errors.New("public signup persistence failure")
)

type PublicSignupWrite struct {
	ApplicationInstanceID applicationinstance.InternalID
	Email                 identity.NormalizedEmail
	PasswordHash          PasswordHash
	VerificationCodeHash  VerificationCodeHash
	IdempotencyKeyHash    [32]byte
	RequestFingerprint    [32]byte
	IdentifierFingerprint [32]byte
	CorrelationID         audit.CorrelationID
	RegistrationAuditID   audit.CorrelationID
	VerificationAuditID   audit.CorrelationID
}

type PublicSignupPersistenceResult struct {
	Replay      bool
	ShouldSend  bool
	Destination string
	ExpiresAt   time.Time
}

type PublicSignupPersistence interface {
	PersistPublicSignup(context.Context, PublicSignupWrite) (PublicSignupPersistenceResult, error)
}

type PublicSignupService struct {
	persistence PublicSignupPersistence
	delivery    EmailVerificationDelivery
}

func NewPublicSignupService(persistence PublicSignupPersistence, delivery EmailVerificationDelivery) *PublicSignupService {
	return &PublicSignupService{persistence: persistence, delivery: delivery}
}

func (s *PublicSignupService) SignUp(ctx context.Context, applicationInstanceID applicationinstance.InternalID, rawEmail, rawPassword, idempotencyKey string) error {
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		return ErrPublicSignupPersistence
	}
	return s.SignUpWithCorrelation(ctx, applicationInstanceID, rawEmail, rawPassword, idempotencyKey, correlationID)
}

func (s *PublicSignupService) SignUpWithCorrelation(ctx context.Context, applicationInstanceID applicationinstance.InternalID, rawEmail, rawPassword, idempotencyKey string, correlationID audit.CorrelationID) error {
	if !applicationInstanceID.Valid() {
		return ErrInvalidApplicationInstanceScope
	}
	if len(idempotencyKey) == 0 || len(idempotencyKey) > 200 {
		return ErrPublicIdempotencyKey
	}
	if correlationID == (audit.CorrelationID{}) || s == nil || s.persistence == nil {
		return ErrPublicSignupPersistence
	}
	if s.delivery == nil {
		return ErrEmailVerificationDelivery
	}
	admission, ok := s.persistence.(PublicSignupAdmission)
	if !ok {
		return ErrPublicSignupPersistence
	}

	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return identity.ErrInvalidEmail
	}
	preparedPassword, err := PreparePublicPassword(rawPassword)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	keyHash := sha256.Sum256([]byte("signup-key\x00" + idempotencyKey))
	identifierFingerprint := sha256.Sum256([]byte("signup-email\x00" + email.ComparisonKey))
	requestInput := make([]byte, 0, len(idempotencyKey)+len(email.ComparisonKey)+len(preparedPassword)+32)
	requestInput = append(requestInput, "signup-request\x00"...)
	requestInput = append(requestInput, idempotencyKey...)
	requestInput = append(requestInput, 0)
	requestInput = append(requestInput, email.ComparisonKey...)
	requestInput = append(requestInput, 0)
	requestInput = append(requestInput, preparedPassword...)
	requestFingerprint := sha256.Sum256(requestInput)

	replay, err := admission.AdmitPublicSignup(ctx, applicationInstanceID, keyHash, requestFingerprint, identifierFingerprint)
	if err != nil {
		return err
	}
	if replay {
		return nil
	}

	passwordHash, err := HashPasswordContext(ctx, preparedPassword)
	if errors.Is(err, ErrKDFAdmissionLimited) {
		return ErrPublicRateLimited
	}
	if err != nil {
		return err
	}
	code, err := GenerateVerificationCode()
	if err != nil {
		return err
	}
	codeHash, err := HashVerificationCodeContext(ctx, code)
	if errors.Is(err, ErrKDFAdmissionLimited) {
		return ErrPublicRateLimited
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	result, err := s.persistence.PersistPublicSignup(ctx, PublicSignupWrite{
		ApplicationInstanceID: applicationInstanceID,
		Email:                 email,
		PasswordHash:          passwordHash,
		VerificationCodeHash:  codeHash,
		IdempotencyKeyHash:    keyHash,
		RequestFingerprint:    requestFingerprint,
		IdentifierFingerprint: identifierFingerprint,
		CorrelationID:         correlationID,
		RegistrationAuditID:   correlationID,
		VerificationAuditID:   correlationID,
	})
	if err != nil {
		return err
	}
	if result.Replay || !result.ShouldSend {
		return nil
	}
	if err := s.delivery.DeliverVerificationCode(ctx, result.Destination, code, result.ExpiresAt); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrEmailVerificationDelivery
	}
	return nil
}
