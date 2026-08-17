package audit

import (
	"crypto/rand"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	CorrelationIDBytes = 16

	ActorKindAnonymousRegistration = "anonymous_registration"
	ActionEmailPasswordRegistration = "authentication.email_password.register"
	ResourceCategoryUserRegistration = "user_registration"
	OutcomeSuccess                   = "success"
	SourceInternalRegistration       = "internal_registration"
)

var ErrCorrelationGeneration = errors.New("audit correlation generation failure")

// CorrelationID is an internal operation identifier. Its byte representation
// is not a public BeeBox contract or authorization primitive.
type CorrelationID [CorrelationIDBytes]byte

func NewCorrelationID() (CorrelationID, error) {
	var id CorrelationID
	if _, err := rand.Read(id[:]); err != nil {
		return CorrelationID{}, ErrCorrelationGeneration
	}
	return id, nil
}

// Event is the smallest BeeBox-owned internal security audit fact needed by
// the current registration core. It intentionally contains no email/password
// data and defines no public event schema.
type Event struct {
	InternalID            int64
	ApplicationInstanceID applicationinstance.InternalID
	ActorKind             string
	ActorUserID            *identity.InternalID
	SubjectUserID          *identity.InternalID
	Action                 string
	ResourceCategory       string
	Outcome                string
	CorrelationID          CorrelationID
	Source                 string
	OccurredAt             time.Time
}
