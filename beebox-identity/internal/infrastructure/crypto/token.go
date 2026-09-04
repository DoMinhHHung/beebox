package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
)

type SessionTokens struct{}

func (SessionTokens) New() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw := domain.SessionTokenPrefix + hex.EncodeToString(buf)
	return raw, HashToken(raw), nil
}

func (SessionTokens) Hash(raw string) string {
	return HashToken(raw)
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
