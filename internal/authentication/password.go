package authentication

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	maxPasswordBytes = 1024

	argon2Version     = 19
	argon2Time        = uint32(3)
	argon2MemoryKiB   = uint32(64 * 1024)
	argon2Parallelism = uint8(4)
	argon2SaltBytes   = 16
	argon2HashBytes   = uint32(32)

	argon2AlgorithmField = "argon2id"
	argon2VersionField   = "v=19"
	argon2ParamsField    = "m=65536,t=3,p=4"
	encodedSaltLength    = 22
	encodedHashLength    = 43
)

var (
	ErrInvalidPasswordInput = errors.New("invalid password input")
	ErrInvalidPasswordHash  = errors.New("invalid password hash")
	ErrPasswordMismatch     = errors.New("password mismatch")
	ErrPasswordHashing      = errors.New("password hashing failure")
)

// PasswordHash is an internal credential-derived value. Its storage encoding
// is sensitive and is not a public BeeBox contract.
type PasswordHash struct {
	encoded string
}

// StorageEncoding returns the internal persistence encoding. Callers must
// treat the returned value as sensitive credential-derived data.
func (h PasswordHash) StorageEncoding() string {
	return h.encoded
}

// Valid reports whether the hash uses BeeBox's exact supported v1 Argon2id
// envelope. It performs no Argon2 work.
func (h PasswordHash) Valid() bool {
	_, _, err := parsePasswordHash(h.encoded)
	return err == nil
}

// ParsePasswordHash validates an internal stored hash without performing
// expensive Argon2 work.
func ParsePasswordHash(encoded string) (PasswordHash, error) {
	if _, _, err := parsePasswordHash(encoded); err != nil {
		return PasswordHash{}, ErrInvalidPasswordHash
	}
	return PasswordHash{encoded: encoded}, nil
}

// HashPassword derives a BeeBox v1 Argon2id password hash from exact raw
// password bytes. The input is never trimmed or normalized.
func HashPassword(raw []byte) (PasswordHash, error) {
	if len(raw) == 0 || len(raw) > maxPasswordBytes {
		return PasswordHash{}, ErrInvalidPasswordInput
	}

	salt := make([]byte, argon2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return PasswordHash{}, ErrPasswordHashing
	}

	hash := argon2.IDKey(raw, salt, argon2Time, argon2MemoryKiB, argon2Parallelism, argon2HashBytes)
	encoded := "$" + argon2AlgorithmField + "$" + argon2VersionField + "$" + argon2ParamsField + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	return PasswordHash{encoded: encoded}, nil
}

// VerifyPassword verifies exact candidate bytes against a supported BeeBox v1
// stored hash. Candidate bytes are never trimmed or normalized.
func VerifyPassword(stored PasswordHash, candidate []byte) error {
	if len(candidate) == 0 || len(candidate) > maxPasswordBytes {
		return ErrInvalidPasswordInput
	}

	salt, expected, err := parsePasswordHash(stored.encoded)
	if err != nil {
		return ErrInvalidPasswordHash
	}

	actual := argon2.IDKey(candidate, salt, argon2Time, argon2MemoryKiB, argon2Parallelism, argon2HashBytes)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

func parsePasswordHash(encoded string) ([]byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != argon2AlgorithmField || parts[2] != argon2VersionField || parts[3] != argon2ParamsField {
		return nil, nil, ErrInvalidPasswordHash
	}
	if len(parts[4]) != encodedSaltLength || len(parts[5]) != encodedHashLength {
		return nil, nil, ErrInvalidPasswordHash
	}

	encoding := base64.RawStdEncoding.Strict()
	salt, err := encoding.DecodeString(parts[4])
	if err != nil || len(salt) != argon2SaltBytes {
		return nil, nil, ErrInvalidPasswordHash
	}
	hash, err := encoding.DecodeString(parts[5])
	if err != nil || len(hash) != int(argon2HashBytes) {
		return nil, nil, ErrInvalidPasswordHash
	}
	return salt, hash, nil
}
