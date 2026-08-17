package identity

import (
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

var (
	ErrInvalidInternalID               = errors.New("invalid user internal identifier")
	ErrInvalidPublicID                 = errors.New("invalid user public identifier")
	ErrInvalidApplicationInstanceScope = errors.New("invalid application instance scope")
	ErrNotFound                        = errors.New("user not found")
	ErrPersistence                     = errors.New("user persistence failure")
)

// InternalID is the storage identity used only inside trusted server code.
type InternalID int64

func (id InternalID) Valid() bool { return id > 0 }

type PublicID string

func (id PublicID) Valid() bool { return publicid.IsUUIDv4(string(id), "usr") }

func NewPublicID() (PublicID, error) {
	value, err := publicid.NewUUIDv4("usr")
	if err != nil {
		return "", err
	}
	return PublicID(value), nil
}

// User remains explicitly application-scoped. PublicID is an opaque locator,
// never authorization evidence.
type User struct {
	InternalID            InternalID
	PublicID              PublicID
	ApplicationInstanceID applicationinstance.InternalID
	CreatedAt             time.Time
}
