package authentication

import (
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

var (
	ErrInvalidApplicationInstanceScope = errors.New("invalid application instance scope")
	ErrInvalidUserInternalID           = errors.New("invalid user internal identifier")
	ErrPasswordCredentialNotFound      = errors.New("password credential not found")
	ErrPasswordCredentialConflict      = errors.New("password credential conflict")
	ErrPasswordCredentialPersistence   = errors.New("password credential persistence failure")
)

// PasswordCredential is an internal application-scoped credential record.
// PasswordHash contains sensitive credential-derived data and is never a
// public BeeBox model.
type PasswordCredential struct {
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	PasswordHash          PasswordHash
	CreatedAt             time.Time
}
