package authentication

import (
	"encoding/base64"
	"strings"
)

const socialLinkStateSecretBytes = 32

// DecodeSocialLinkStateWire validates the purpose-specific social-link wire
// representation. Syntax only selects the link lifecycle; persisted attempt
// state remains the authority for redemption.
func DecodeSocialLinkStateWire(raw string) ([socialLinkStateSecretBytes]byte, bool) {
	var secret [socialLinkStateSecretBytes]byte
	encodedLen := base64.RawURLEncoding.EncodedLen(len(secret))
	if len(raw) != len(SocialLinkStatePrefix)+encodedLen || !strings.HasPrefix(raw, SocialLinkStatePrefix) {
		return secret, false
	}
	encoded := raw[len(SocialLinkStatePrefix):]
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != len(secret) {
		return secret, false
	}
	copy(secret[:], decoded)
	return secret, true
}

func ValidSocialLinkStateWire(raw string) bool {
	_, ok := DecodeSocialLinkStateWire(raw)
	return ok
}
