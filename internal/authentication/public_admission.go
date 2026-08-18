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
