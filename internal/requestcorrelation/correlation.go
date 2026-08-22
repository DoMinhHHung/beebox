package requestcorrelation

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const (
	PublicHeader            = "X-Request-ID"
	InternalIDHeader        = "X-BeeBox-Internal-Correlation"
	InternalSignatureHeader = "X-BeeBox-Internal-Correlation-Signature"
	KeyEnvironmentVariable  = "BEEBOX_INTERNAL_CORRELATION_KEY"
	macPurpose              = "beebox-internal-correlation-v1\x00"
)

var ErrInvalidKey = errors.New("invalid internal correlation key")

type LookupEnv func(string) (string, bool)

type Key [32]byte
type ID [16]byte

func LoadKey(lookup LookupEnv) (Key, error) {
	if lookup == nil {
		return Key{}, ErrInvalidKey
	}
	raw, ok := lookup(KeyEnvironmentVariable)
	if !ok || raw == "" {
		return Key{}, ErrInvalidKey
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != len(Key{}) {
		return Key{}, ErrInvalidKey
	}
	var key Key
	copy(key[:], decoded)
	var nonZero byte
	for _, b := range key {
		nonZero |= b
	}
	if nonZero == 0 {
		return Key{}, ErrInvalidKey
	}
	return key, nil
}

func NewID() (ID, error) {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		return ID{}, err
	}
	return id, nil
}

func ParseID(value string) (ID, bool) {
	if len(value) != 32 {
		return ID{}, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(ID{}) {
		return ID{}, false
	}
	var id ID
	copy(id[:], decoded)
	var nonZero byte
	for _, b := range id {
		nonZero |= b
	}
	if nonZero == 0 {
		return ID{}, false
	}
	return id, true
}

func (id ID) String() string { return hex.EncodeToString(id[:]) }

func Sign(key Key, id ID) string {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(macPurpose))
	_, _ = mac.Write([]byte(id.String()))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func Verify(key Key, rawID, rawSignature string) (ID, bool) {
	id, ok := ParseID(rawID)
	if !ok {
		return ID{}, false
	}
	provided, err := base64.RawURLEncoding.DecodeString(rawSignature)
	if err != nil || len(provided) != sha256.Size {
		return ID{}, false
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(macPurpose))
	_, _ = mac.Write([]byte(id.String()))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return ID{}, false
	}
	return id, true
}
