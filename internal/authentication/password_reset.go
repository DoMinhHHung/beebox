package authentication

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	PasswordResetCodeTTL        = 10 * time.Minute
	PasswordResetIssueWindow    = 15 * time.Minute
	PasswordResetResendCooldown = time.Minute
	PasswordResetMaxIssues      = 3
	PasswordResetMaxAttempts    = 5
)

var (
	ErrInvalidPasswordResetCode = errors.New("invalid password reset code")
	ErrPasswordResetFailed      = errors.New("password reset failed")
	ErrPasswordResetRateLimited = errors.New("password reset rate limited")
	ErrPasswordResetDelivery    = errors.New("password reset delivery failure")
	ErrPasswordResetPersistence = errors.New("password reset persistence failure")
	ErrPasswordResetStale       = errors.New("stale password reset challenge")
)

type PasswordResetCodeHash struct {
	encoded string
}

func (h PasswordResetCodeHash) StorageEncoding() string { return h.encoded }
func (h PasswordResetCodeHash) Valid() bool {
	_, err := ParsePasswordHash(h.encoded)
	return err == nil
}

func ParsePasswordResetCodeHash(encoded string) (PasswordResetCodeHash, error) {
	if _, err := ParsePasswordHash(encoded); err != nil {
		return PasswordResetCodeHash{}, ErrPasswordResetPersistence
	}
	return PasswordResetCodeHash{encoded: encoded}, nil
}

func GeneratePasswordResetCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return "", ErrPasswordResetPersistence
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}

func validPasswordResetCode(code string) bool {
	if len(code) != 8 {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

func HashPasswordResetCode(code string) (PasswordResetCodeHash, error) {
	if !validPasswordResetCode(code) {
		return PasswordResetCodeHash{}, ErrInvalidPasswordResetCode
	}
	hash, err := HashPassword([]byte(code))
	if err != nil {
		return PasswordResetCodeHash{}, ErrPasswordResetPersistence
	}
	return PasswordResetCodeHash{encoded: hash.StorageEncoding()}, nil
}

func VerifyPasswordResetCode(hash PasswordResetCodeHash, code string) error {
	if !validPasswordResetCode(code) {
		return ErrInvalidPasswordResetCode
	}
	parsed, err := ParsePasswordHash(hash.encoded)
	if err != nil {
		return ErrPasswordResetPersistence
	}
	if err := VerifyPassword(parsed, []byte(code)); err != nil {
		if errors.Is(err, ErrPasswordMismatch) {
			return ErrPasswordResetFailed
		}
		return ErrPasswordResetPersistence
	}
	return nil
}

type PasswordResetDelivery interface {
	DeliverPasswordResetCode(context.Context, string, string, time.Time) error
}

type PasswordResetIssue struct {
	ApplicationInstanceID applicationinstance.InternalID
	NormalizedEmail       string
	CodeHash              PasswordResetCodeHash
	CorrelationID         audit.CorrelationID
}

type PasswordResetIssueResult struct {
	ShouldSend  bool
	Destination string
	ExpiresAt   time.Time
}

type PasswordResetSnapshot struct {
	UserID               identity.InternalID
	EmailIdentifierID    identity.EmailIdentifierInternalID
	ChallengeGeneration  int64
	CredentialGeneration int64
	CodeHash             PasswordResetCodeHash
	ExpiresAt            time.Time
	FailedAttempts       int
}

type PasswordResetFinalize struct {
	ApplicationInstanceID applicationinstance.InternalID
	EmailIdentifierID     identity.EmailIdentifierInternalID
	UserID                identity.InternalID
	ChallengeGeneration   int64
	CredentialGeneration  int64
	Matched               bool
	NewPasswordHash       PasswordHash
	CorrelationID         audit.CorrelationID
}

type PasswordResetPersistence interface {
	IssuePasswordReset(context.Context, PasswordResetIssue) (PasswordResetIssueResult, error)
	LoadPasswordReset(context.Context, applicationinstance.InternalID, string) (PasswordResetSnapshot, error)
	FinalizePasswordReset(context.Context, PasswordResetFinalize) error
}

type PasswordResetService struct {
	persistence PasswordResetPersistence
	delivery    PasswordResetDelivery
}

func NewPasswordResetService(persistence PasswordResetPersistence, delivery PasswordResetDelivery) *PasswordResetService {
	return &PasswordResetService{persistence: persistence, delivery: delivery}
}

func (s *PasswordResetService) RequestWithCorrelation(ctx context.Context, appID applicationinstance.InternalID, rawEmail string, correlationID audit.CorrelationID) error {
	if s == nil || s.persistence == nil || s.delivery == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return ErrPasswordResetPersistence
	}
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return identity.ErrInvalidEmail
	}
	code, err := GeneratePasswordResetCode()
	if err != nil {
		return err
	}
	codeHash, err := HashPasswordResetCode(code)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := s.persistence.IssuePasswordReset(ctx, PasswordResetIssue{
		ApplicationInstanceID: appID,
		NormalizedEmail:       email.ComparisonKey,
		CodeHash:              codeHash,
		CorrelationID:         correlationID,
	})
	if err != nil {
		if errors.Is(err, ErrPasswordResetRateLimited) || errors.Is(err, ErrPasswordResetFailed) {
			return nil
		}
		return err
	}
	if !result.ShouldSend {
		return nil
	}
	if err := s.delivery.DeliverPasswordResetCode(ctx, result.Destination, code, result.ExpiresAt); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrPasswordResetDelivery
	}
	return nil
}

func (s *PasswordResetService) ConfirmWithCorrelation(ctx context.Context, appID applicationinstance.InternalID, rawEmail, code, newPassword string, correlationID audit.CorrelationID) error {
	if s == nil || s.persistence == nil || !appID.Valid() || correlationID == (audit.CorrelationID{}) {
		return ErrPasswordResetPersistence
	}
	if !validPasswordResetCode(code) {
		return ErrInvalidPasswordResetCode
	}
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return identity.ErrInvalidEmail
	}
	prepared, err := PreparePublicPassword(newPassword)
	if err != nil {
		return err
	}
	newHash, err := HashPassword(prepared)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot, err := s.persistence.LoadPasswordReset(ctx, appID, email.ComparisonKey)
	if err != nil {
		if errors.Is(err, ErrPasswordResetFailed) {
			return ErrPasswordResetFailed
		}
		return err
	}
	matched := VerifyPasswordResetCode(snapshot.CodeHash, code) == nil
	if err := ctx.Err(); err != nil {
		return err
	}
	err = s.persistence.FinalizePasswordReset(ctx, PasswordResetFinalize{
		ApplicationInstanceID: appID,
		EmailIdentifierID:     snapshot.EmailIdentifierID,
		UserID:                snapshot.UserID,
		ChallengeGeneration:   snapshot.ChallengeGeneration,
		CredentialGeneration:  snapshot.CredentialGeneration,
		Matched:               matched,
		NewPasswordHash:       newHash,
		CorrelationID:         correlationID,
	})
	if err != nil {
		return err
	}
	if !matched {
		return ErrPasswordResetFailed
	}
	return nil
}
