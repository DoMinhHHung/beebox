package identity

import (
	"errors"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

var (
	ErrInvalidPhone             = errors.New("invalid phone number")
	ErrPhoneIdentifierNotFound = errors.New("phone identifier not found")
	ErrPhoneConflict           = errors.New("phone identifier conflict")
	ErrPhonePersistence        = errors.New("phone identifier persistence failure")
)

// PhoneIdentifierInternalID is the storage identity of a phone identifier.
// It is internal only and does not define a public BeeBox wire identifier.
type PhoneIdentifierInternalID int64

func (id PhoneIdentifierInternalID) Valid() bool { return id > 0 }

// CanonicalPhone is BeeBox's P2.2 public/storage phone representation. It is
// strict international E.164 shape only; BeeBox does not infer a default region
// or accept national formatting.
type CanonicalPhone struct {
	E164 string
}

func NormalizePhone(input string) (CanonicalPhone, error) {
	value := strings.TrimSpace(input)
	if len(value) < 3 || len(value) > 16 || value[0] != '+' || value[1] < '1' || value[1] > '9' {
		return CanonicalPhone{}, ErrInvalidPhone
	}
	for i := 2; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return CanonicalPhone{}, ErrInvalidPhone
		}
	}
	return CanonicalPhone{E164: value}, nil
}

// PhoneIdentifier is an application-scoped phone claim. PhoneE164 is PII and
// must not be copied into audit/metrics/rate-limit/challenge state.
type PhoneIdentifier struct {
	InternalID            PhoneIdentifierInternalID
	ApplicationInstanceID applicationinstance.InternalID
	UserID                InternalID
	PhoneE164             string
	VerifiedAt            *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}
