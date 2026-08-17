package session

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
)

var ErrTokenDisabled = errors.New("access token capability disabled")

type LookupEnv func(string) (string, bool)

func KeyRingFromLookup(lookup LookupEnv) (*KeyRing, error) {
	if lookup == nil {
		return nil, ErrTokenConfig
	}
	issuer, issuerOK := lookup("BEEBOX_ISSUER")
	kid, kidOK := lookup("BEEBOX_SIGNING_KID")
	privateEncoded, privateOK := lookup("BEEBOX_SIGNING_PRIVATE_KEY")
	publicEncoded, publicOK := lookup("BEEBOX_SIGNING_PUBLIC_KEY")
	if !issuerOK && !kidOK && !privateOK && !publicOK {
		return nil, ErrTokenDisabled
	}
	if !issuerOK || !kidOK || !privateOK || !publicOK {
		return nil, ErrTokenConfig
	}
	privateBytes, err := base64.RawURLEncoding.Strict().DecodeString(privateEncoded)
	if err != nil || len(privateBytes) != ed25519.PrivateKeySize {
		return nil, ErrTokenConfig
	}
	publicBytes, err := base64.RawURLEncoding.Strict().DecodeString(publicEncoded)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return nil, ErrTokenConfig
	}
	keys := map[string]ed25519.PublicKey{kid: ed25519.PublicKey(publicBytes)}
	if retiring, ok := lookup("BEEBOX_SIGNING_RETIRING_KEYS"); ok && strings.TrimSpace(retiring) != "" {
		for _, entry := range strings.Split(retiring, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), ":", 2)
			if len(parts) != 2 || parts[0] == "" {
				return nil, ErrTokenConfig
			}
			if _, duplicate := keys[parts[0]]; duplicate {
				return nil, ErrTokenConfig
			}
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
			if err != nil || len(decoded) != ed25519.PublicKeySize {
				return nil, ErrTokenConfig
			}
			keys[parts[0]] = ed25519.PublicKey(decoded)
		}
	}
	return NewKeyRing(issuer, kid, ed25519.PrivateKey(privateBytes), keys)
}
