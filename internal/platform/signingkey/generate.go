package signingkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

var ErrGeneration = errors.New("signing key generation failure")

type Generated struct {
	KeyID      string
	PrivateKey string
	PublicKey  string
}

// Generate creates local configuration material. PrivateKey is intended for
// one-time explicit operator output and must never be logged.
func Generate() (Generated, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { return Generated{}, ErrGeneration }
	kid, err := publicid.NewUUIDv4("key")
	if err != nil { return Generated{}, ErrGeneration }
	return Generated{
		KeyID: kid,
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	}, nil
}

func Parse(g Generated) error {
	privateKey, err := base64.RawURLEncoding.DecodeString(g.PrivateKey); if err != nil || len(privateKey)!=ed25519.PrivateKeySize { return ErrGeneration }
	publicKey, err := base64.RawURLEncoding.DecodeString(g.PublicKey); if err != nil || len(publicKey)!=ed25519.PublicKeySize { return ErrGeneration }
	if len(g.KeyID)==0 { return ErrGeneration }
	derived := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	if !derived.Equal(ed25519.PublicKey(publicKey)) { return ErrGeneration }
	return nil
}
