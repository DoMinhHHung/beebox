package authentication

import (
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	PublicPasswordMinCodePoints = 15
	PublicPasswordMaxCodePoints = 128
)

var (
	ErrPublicPasswordPolicy = errors.New("public password policy rejected password")
)

var publicPasswordBlocklist = map[string]struct{}{
	"passwordpassword": {},
	"password123456":   {},
	"123456789012345":  {},
	"qwertyuiopasdfg":  {},
	"beeboxpassword":   {},
	"beebox123456789":  {},
}

// PreparePublicPassword applies the single Phase 1 public password policy.
// It never trims input. Accepted Unicode is normalized to NFC before hashing.
func PreparePublicPassword(raw string) ([]byte, error) {
	if !utf8.ValidString(raw) {
		return nil, ErrPublicPasswordPolicy
	}
	normalized := norm.NFC.String(raw)
	codePoints := utf8.RuneCountInString(normalized)
	if codePoints < PublicPasswordMinCodePoints || codePoints > PublicPasswordMaxCodePoints {
		return nil, ErrPublicPasswordPolicy
	}
	if len(normalized) > maxPasswordBytes {
		return nil, ErrPublicPasswordPolicy
	}
	if _, blocked := publicPasswordBlocklist[strings.ToLower(normalized)]; blocked {
		return nil, ErrPublicPasswordPolicy
	}
	return []byte(normalized), nil
}

func HashPublicPassword(raw string) (PasswordHash, error) {
	prepared, err := PreparePublicPassword(raw)
	if err != nil {
		return PasswordHash{}, err
	}
	return HashPassword(prepared)
}
