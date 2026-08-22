package organization

import (
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	NameMaxRunes     = 100
	SlugMaxBytes     = 63
	ListDefaultLimit = 50
	ListMaxLimit     = 100
)

var (
	ErrInvalid         = errors.New("invalid organization input")
	ErrInvalidCursor   = errors.New("invalid organization cursor")
	ErrNotFound        = errors.New("organization not found")
	ErrSlugUnavailable = errors.New("organization slug unavailable")
	ErrPersistence     = errors.New("organization persistence failure")
)

// ID is a stable BeeBox-owned opaque storage locator for P3.1. P3.1 exposes no
// public organization API, so this raw UUIDv4 representation is deliberately
// not a ratified public wire encoding.
type ID string

func (id ID) Valid() bool {
	value := string(id)
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	hexBody := strings.ReplaceAll(value, "-", "")
	if len(hexBody) != 32 {
		return false
	}
	raw, err := hex.DecodeString(hexBody)
	if err != nil || len(raw) != 16 {
		return false
	}
	return raw[6]>>4 == 4 && raw[8]&0xc0 == 0x80 && value == strings.ToLower(value)
}

type Organization struct {
	ID                    ID
	ApplicationInstanceID applicationinstance.InternalID
	Name                  string
	Slug                  string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// MutationContext carries already-trusted root application scope plus minimized
// audit actor/correlation evidence. It does not itself grant authorization.
type MutationContext struct {
	ApplicationInstanceID applicationinstance.InternalID
	ActorUserID           identity.InternalID
	CorrelationID         audit.CorrelationID
}

func (c MutationContext) Valid() bool {
	return c.ApplicationInstanceID.Valid() && c.ActorUserID.Valid() && c.CorrelationID != (audit.CorrelationID{})
}

type ListPosition struct {
	CreatedAt time.Time
	ID        ID
}

type Page struct {
	Organizations []Organization
	NextCursor    string
}

func NormalizeName(input string) (string, error) {
	name := strings.TrimSpace(input)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > NameMaxRunes {
		return "", ErrInvalid
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", ErrInvalid
		}
	}
	return name, nil
}

func NormalizeSlug(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", ErrInvalid
	}
	var out strings.Builder
	separatorPending := false
	for _, r := range input {
		switch {
		case r >= 'A' && r <= 'Z':
			if separatorPending && out.Len() > 0 {
				out.WriteByte('-')
			}
			out.WriteByte(byte(r - 'A' + 'a'))
			separatorPending = false
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if separatorPending && out.Len() > 0 {
				out.WriteByte('-')
			}
			out.WriteRune(r)
			separatorPending = false
		case r == '-' || r == '_' || r == ' ':
			if out.Len() > 0 {
				separatorPending = true
			}
		default:
			return "", ErrInvalid
		}
	}
	slug := out.String()
	if slug == "" || len(slug) > SlugMaxBytes {
		return "", ErrInvalid
	}
	return slug, nil
}
