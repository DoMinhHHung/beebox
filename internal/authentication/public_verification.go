package authentication

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	PublicVerificationGlobalLimit      = 200
	PublicVerificationGlobalWindow     = time.Minute
	PublicVerificationIdentifierLimit  = 5
	PublicVerificationIdentifierWindow = 15 * time.Minute
)

type PublicEmailIdentifierResolver interface {
	ResolveEmailIdentifierByAddress(context.Context, applicationinstance.InternalID, string) (identity.EmailIdentifier, error)
}

type PublicVerificationRateLimiter interface {
	AllowPublicVerificationIssue(context.Context, applicationinstance.InternalID, [32]byte) error
}

type PublicVerificationService struct {
	resolver     PublicEmailIdentifierResolver
	limiter      PublicVerificationRateLimiter
	verification *EmailVerificationService
}

func NewPublicVerificationService(
	resolver PublicEmailIdentifierResolver,
	limiter PublicVerificationRateLimiter,
	verification *EmailVerificationService,
) *PublicVerificationService {
	return &PublicVerificationService{resolver: resolver, limiter: limiter, verification: verification}
}

// Request emits only a generic success/failure category at higher public layers.
// Identifier absence, verified state, cooldown, issue exhaustion, and provider
// delivery ambiguity are intentionally collapsed to preserve account secrecy.
func (s *PublicVerificationService) Request(ctx context.Context, appID applicationinstance.InternalID, rawEmail string) error {
	if !appID.Valid() {
		return ErrInvalidApplicationInstanceScope
	}
	if s == nil || s.resolver == nil || s.limiter == nil || s.verification == nil {
		return ErrEmailVerificationPersistence
	}
	normalized, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return identity.ErrInvalidEmail
	}
	fingerprint := sha256.Sum256([]byte("verification-email\x00" + normalized.ComparisonKey))
	if err := s.limiter.AllowPublicVerificationIssue(ctx, appID, fingerprint); err != nil {
		if errors.Is(err, ErrPublicRateLimited) {
			return nil
		}
		return err
	}
	identifier, err := s.resolver.ResolveEmailIdentifierByAddress(ctx, appID, rawEmail)
	if err != nil {
		if errors.Is(err, identity.ErrEmailIdentifierNotFound) {
			return nil
		}
		return err
	}
	if identifier.VerifiedAt != nil {
		return nil
	}
	if err := s.verification.IssueEmailVerification(ctx, appID, identifier.InternalID); err != nil {
		switch {
		case errors.Is(err, ErrEmailVerificationAlreadyCompleted),
			errors.Is(err, ErrEmailVerificationResendCooldown),
			errors.Is(err, ErrEmailVerificationIssueLimit),
			errors.Is(err, ErrEmailVerificationDelivery):
			return nil
		default:
			return err
		}
	}
	return nil
}

func (s *PublicVerificationService) Confirm(ctx context.Context, appID applicationinstance.InternalID, rawEmail, code string) error {
	if !appID.Valid() {
		return ErrInvalidApplicationInstanceScope
	}
	if s == nil || s.resolver == nil || s.verification == nil {
		return ErrEmailVerificationPersistence
	}
	identifier, err := s.resolver.ResolveEmailIdentifierByAddress(ctx, appID, rawEmail)
	if err != nil {
		if errors.Is(err, identity.ErrEmailIdentifierNotFound) {
			return ErrEmailVerificationMismatch
		}
		return err
	}
	_, err = s.verification.VerifyEmailCode(ctx, appID, identifier.InternalID, code)
	return err
}
