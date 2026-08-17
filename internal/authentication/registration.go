package authentication

import (
	"context"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

var (
	ErrRegistrationConflict    = errors.New("registration conflict")
	ErrRegistrationPersistence = errors.New("registration persistence failure")
)

// RegistrationResult contains only the internal product state useful to the
// registration caller. It deliberately excludes password hashes and audit rows.
type RegistrationResult struct {
	User            identity.User
	EmailIdentifier identity.EmailIdentifier
}

// RegistrationWrite is normalized, hashed internal material passed to the one
// transactional persistence boundary.
type RegistrationWrite struct {
	ApplicationInstanceID applicationinstance.InternalID
	Email                 identity.NormalizedEmail
	PasswordHash          PasswordHash
	CorrelationID         audit.CorrelationID
}

// RegistrationPersistence exists because registration has one real transaction
// boundary across user, identifier, credential, and audit state.
type RegistrationPersistence interface {
	PersistRegistration(context.Context, RegistrationWrite) (RegistrationResult, error)
}

type Registrar struct {
	persistence RegistrationPersistence
}

func NewRegistrar(persistence RegistrationPersistence) *Registrar {
	return &Registrar{persistence: persistence}
}

func (r *Registrar) RegisterEmailPassword(
	ctx context.Context,
	applicationInstanceID applicationinstance.InternalID,
	rawEmail string,
	rawPassword []byte,
) (RegistrationResult, error) {
	if !applicationInstanceID.Valid() {
		return RegistrationResult{}, ErrInvalidApplicationInstanceScope
	}

	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return RegistrationResult{}, identity.ErrInvalidEmail
	}

	passwordHash, err := HashPassword(rawPassword)
	if err != nil {
		return RegistrationResult{}, err
	}

	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		return RegistrationResult{}, ErrRegistrationPersistence
	}
	if err := ctx.Err(); err != nil {
		return RegistrationResult{}, err
	}
	if r == nil || r.persistence == nil {
		return RegistrationResult{}, ErrRegistrationPersistence
	}

	return r.persistence.PersistRegistration(ctx, RegistrationWrite{
		ApplicationInstanceID: applicationInstanceID,
		Email:                 email,
		PasswordHash:          passwordHash,
		CorrelationID:         correlationID,
	})
}
