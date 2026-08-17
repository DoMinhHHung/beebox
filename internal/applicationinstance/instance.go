package applicationinstance

import (
	"errors"
	"time"
)

var (
	ErrInvalidInternalID = errors.New("invalid application instance internal identifier")
	ErrNotFound          = errors.New("application instance not found")
	ErrPersistence       = errors.New("application instance persistence failure")
)

// InternalID is the storage identity used to select an application_instance
// root inside trusted server code. It is not a public BeeBox resource ID and
// does not ratify any future wire encoding.
type InternalID int64

func (id InternalID) Valid() bool {
	return id > 0
}

// Instance is the minimal BeeBox-owned representation of the v1 root product
// isolation resource. It intentionally has no public JSON or transport model.
type Instance struct {
	InternalID InternalID
	CreatedAt  time.Time
}
