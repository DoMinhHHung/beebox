package applicationinstance

import (
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

var (
	ErrInvalidInternalID = errors.New("invalid application instance internal identifier")
	ErrInvalidPublicID   = errors.New("invalid application public identifier")
	ErrNotFound          = errors.New("application instance not found")
	ErrPersistence       = errors.New("application instance persistence failure")
)

// InternalID is the storage identity used to select an application_instance
// root inside trusted server code. It is never a public authorization primitive.
type InternalID int64

func (id InternalID) Valid() bool { return id > 0 }

type PublicID string

func (id PublicID) Valid() bool { return publicid.IsUUIDv4(string(id), "app") }

func NewPublicID() (PublicID, error) {
	value, err := publicid.NewUUIDv4("app")
	if err != nil {
		return "", err
	}
	return PublicID(value), nil
}

// Instance is the BeeBox-owned representation of the v1 root isolation resource.
// PublicID is opaque and carries no authorization or tenant information.
type Instance struct {
	InternalID InternalID
	PublicID   PublicID
	CreatedAt  time.Time
}
