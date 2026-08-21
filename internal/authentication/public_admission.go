package authentication

import (
	"context"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

// PublicSignupAdmission performs cheap idempotency/rate checks before expensive
// password/verification-code KDF work. It does not reserve a new idempotency row;
// final persistence remains the transactional reservation/correctness boundary.
type PublicSignupAdmission interface {
	AdmitPublicSignup(context.Context, applicationinstance.InternalID, [32]byte, [32]byte, [32]byte) (bool, error)
}

// PublicVerificationAdmission protects public verification confirmation before
// Argon2 verification. Challenge-level failed-attempt limits remain a separate
// correctness control.
type PublicVerificationAdmission interface {
	AllowPublicVerificationConfirm(context.Context, applicationinstance.InternalID, [32]byte) error
}

// PasswordResetAdmission protects reset issue/confirm requests before expensive
// reset-code/password KDF work.
type PasswordResetAdmission interface {
	AllowPasswordResetIssue(context.Context, applicationinstance.InternalID, [32]byte) error
	AllowPasswordResetConfirm(context.Context, applicationinstance.InternalID, [32]byte) error
}

// EmailOTPAdmission protects passwordless email-OTP issue and confirmation in
// purpose-specific namespaces. Implementations must admit the fixed global
// subject before touching attacker-controlled identifier cardinality.
type EmailOTPAdmission interface {
	AllowEmailOTPIssue(context.Context, applicationinstance.InternalID, [32]byte) error
	AllowEmailOTPConfirm(context.Context, applicationinstance.InternalID, [32]byte) error
}

// EmailLinkAdmission protects one-time email-link issue and confirmation before
// identifier- or challenge-scoped persistence. Implementations admit the fixed
// global subject first so attacker-controlled identifiers cannot create an
// unbounded limiter-cardinality path.
type EmailLinkAdmission interface {
	AllowEmailLinkIssue(context.Context, applicationinstance.InternalID, [32]byte) error
	AllowEmailLinkConfirm(context.Context, applicationinstance.InternalID, [32]byte) error
}
