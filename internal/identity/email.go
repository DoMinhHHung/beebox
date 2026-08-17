package identity

import (
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

const maxEmailAddressBytes = 254

var (
	ErrInvalidEmail            = errors.New("invalid email address")
	ErrEmailIdentifierNotFound = errors.New("email identifier not found")
	ErrEmailConflict           = errors.New("email identifier conflict")
	ErrEmailPersistence        = errors.New("email identifier persistence failure")
)

// EmailIdentifierInternalID is the storage identity of an email identifier.
// It is not a public BeeBox identifier and does not ratify a wire encoding.
type EmailIdentifierInternalID int64

func (id EmailIdentifierInternalID) Valid() bool {
	return id > 0
}

// NormalizedEmail is the deterministic BeeBox v1 representation used by
// persistence. EmailAddress preserves the trimmed mailbox spelling for future
// delivery/display use. ComparisonKey lowercases the complete ASCII mailbox.
type NormalizedEmail struct {
	EmailAddress  string
	ComparisonKey string
}

// NormalizeEmail implements BeeBox v1 email normalization. It accepts only an
// ASCII mailbox address, preserves dots and plus tags, and performs no
// provider-specific aliasing.
func NormalizeEmail(input string) (NormalizedEmail, error) {
	for i := 0; i < len(input); i++ {
		b := input[i]
		if b >= 0x80 || b < 0x20 || b == 0x7f {
			return NormalizedEmail{}, ErrInvalidEmail
		}
	}

	trimmed := strings.Trim(input, " ")
	if trimmed == "" || len(trimmed) > maxEmailAddressBytes {
		return NormalizedEmail{}, ErrInvalidEmail
	}

	parsed, err := mail.ParseAddress(trimmed)
	if err != nil || parsed.Name != "" || parsed.Address != trimmed {
		return NormalizedEmail{}, ErrInvalidEmail
	}

	at := strings.LastIndexByte(trimmed, '@')
	if at <= 0 || at == len(trimmed)-1 {
		return NormalizedEmail{}, ErrInvalidEmail
	}

	return NormalizedEmail{
		EmailAddress:  trimmed,
		ComparisonKey: strings.ToLower(trimmed),
	}, nil
}

// EmailIdentifier is the BeeBox-owned internal representation of an
// application-scoped email claim. EmailAddress and NormalizedEmail are PII.
// New records are unverified; this slice defines no verification transition.
type EmailIdentifier struct {
	InternalID            EmailIdentifierInternalID
	ApplicationInstanceID applicationinstance.InternalID
	UserID                InternalID
	EmailAddress          string
	NormalizedEmail       string
	VerifiedAt            *time.Time
	CreatedAt             time.Time
}
