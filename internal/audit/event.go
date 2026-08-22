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

	ActorKindAnonymousRegistration      = "anonymous_registration"
	ActorKindAnonymousEmailVerification = "anonymous_email_verification"

	ActionEmailPasswordRegistration        = "authentication.email_password.register"
	ActionEmailVerificationChallengeIssued = "authentication.email_verification.challenge_issued"
	ActionEmailVerificationVerify          = "authentication.email_verification.verify"

	ResourceCategoryUserRegistration = "user_registration"
	ResourceCategoryEmailIdentifier  = "email_identifier"

	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"

	SourceInternalRegistration      = "internal_registration"
	SourceInternalEmailVerification = "internal_email_verification"
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
// current authentication cores. It intentionally contains no email/password
// or verification-code data and defines no public event schema.
type Event struct {
	InternalID               int64
	ApplicationInstanceID    applicationinstance.InternalID
	ActorKind                string
	ActorUserID              *identity.InternalID
	SubjectUserID            *identity.InternalID
	Action                   string
	ResourceCategory         string
	ResourceReference        string
	OrganizationReference    string
	RelatedResourceReference string
	Outcome                  string
	CorrelationID            CorrelationID
	Source                   string
	OccurredAt               time.Time
}
