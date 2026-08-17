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
	PublicVerificationGlobalLimit       = 200
	PublicVerificationGlobalWindow      = time.Minute
	PublicVerificationIdentifierLimit   = 5
	PublicVerificationIdentifierWindow  = 15 * time.Minute
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

func (s *PublicVerificationService) Request(ctx context.Context, appID applicationinstance.InternalID, rawEmail string) error {
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		return ErrEmailVerificationPersistence
	}
	return s.RequestWithCorrelation(ctx, appID, rawEmail, correlationID)
}

// RequestWithCorrelation emits only a generic success/failure category at higher
// public layers. Identifier absence, verified state, cooldown, issue exhaustion,
// and provider delivery ambiguity are intentionally collapsed to preserve account secrecy.
func (s *PublicVerificationService) RequestWithCorrelation(
	ctx context.Context,
	appID applicationinstance.InternalID,
	rawEmail string,
	correlationID audit.CorrelationID,
) error {
	if !appID.Valid() {
		return ErrInvalidApplicationInstanceScope
	}
	if correlationID == (audit.CorrelationID{}) {
		return ErrEmailVerificationPersistence
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
	if err := s.verification.IssueEmailVerificationWithCorrelation(ctx, appID, identifier.InternalID, correlationID); err != nil {
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
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		return ErrEmailVerificationPersistence
	}
	return s.ConfirmWithCorrelation(ctx, appID, rawEmail, code, correlationID)
}

func (s *PublicVerificationService) ConfirmWithCorrelation(
	ctx context.Context,
	appID applicationinstance.InternalID,
	rawEmail string,
	code string,
	correlationID audit.CorrelationID,
) error {
	if !appID.Valid() {
		return ErrInvalidApplicationInstanceScope
	}
	if correlationID == (audit.CorrelationID{}) {
		return ErrEmailVerificationPersistence
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
	_, err = s.verification.VerifyEmailCodeWithCorrelation(ctx, appID, identifier.InternalID, code, correlationID)
	return err
}
