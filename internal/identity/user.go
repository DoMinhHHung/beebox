package identity

import (
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

var (
	ErrInvalidInternalID               = errors.New("invalid user internal identifier")
	ErrInvalidApplicationInstanceScope = errors.New("invalid application instance scope")
	ErrNotFound                        = errors.New("user not found")
	ErrPersistence                     = errors.New("user persistence failure")
)

// InternalID is the storage identity used only inside trusted server code. It
// is not a public BeeBox user identifier and does not ratify a wire encoding.
type InternalID int64

func (id InternalID) Valid() bool {
	return id > 0
}

// User is the minimal BeeBox-owned child resource persisted in this slice.
// ApplicationInstanceID is the explicit v1 root scope; no public wire model is
// defined here.
type User struct {
	InternalID            InternalID
	ApplicationInstanceID applicationinstance.InternalID
	CreatedAt             time.Time
}
