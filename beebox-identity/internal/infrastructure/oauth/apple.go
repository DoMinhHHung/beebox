package oauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

func appleClientSecret(creds Credentials, now time.Time) (string, error) {
	teamID := strings.TrimSpace(creds.Extra["team_id"])
	keyID := strings.TrimSpace(creds.Extra["key_id"])
	p8 := creds.Extra["private_key_p8"]
	if teamID == "" || keyID == "" || strings.TrimSpace(p8) == "" {
		return "", fmt.Errorf("apple extra incomplete")
	}
	key, err := parseECPrivateKey(p8)
	if err != nil {
		return "", err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": teamID,
		"iat": now.Unix(),
		"exp": now.Add(180 * 24 * time.Hour).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": creds.ClientID,
	})
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(header)
	c := base64.RawURLEncoding.EncodeToString(claims)
	signing := h + "." + c
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := append(pad32(r.Bytes()), pad32(s.Bytes())...)
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func parseECPrivateKey(p8 string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(p8))
	if block == nil {
		return nil, fmt.Errorf("invalid p8")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not ec key")
		}
		return ec, nil
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func ParseAppleUser(raw string) (name, given, family string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", ""
	}
	var body struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		return "", "", ""
	}
	given = strings.TrimSpace(body.Name.FirstName)
	family = strings.TrimSpace(body.Name.LastName)
	name = strings.TrimSpace(given + " " + family)
	return name, given, family
}

func decodeJWTClaimsUnverified(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt parts")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, err
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}
