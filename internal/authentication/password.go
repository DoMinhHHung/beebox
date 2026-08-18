package authentication

import (
	"context"
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

type PasswordHash struct {
	encoded string
}

func (h PasswordHash) StorageEncoding() string {
	return h.encoded
}

func (h PasswordHash) Valid() bool {
	_, _, err := parsePasswordHash(h.encoded)
	return err == nil
}

func ParsePasswordHash(encoded string) (PasswordHash, error) {
	if _, _, err := parsePasswordHash(encoded); err != nil {
		return PasswordHash{}, ErrInvalidPasswordHash
	}
	return PasswordHash{encoded: encoded}, nil
}

func HashPassword(raw []byte) (PasswordHash, error) {
	return HashPasswordContext(context.Background(), raw)
}

func HashPasswordContext(ctx context.Context, raw []byte) (PasswordHash, error) {
	if len(raw) == 0 || len(raw) > maxPasswordBytes {
		return PasswordHash{}, ErrInvalidPasswordInput
	}
	var result PasswordHash
	err := withProcessKDF(ctx, func() error {
		salt := make([]byte, argon2SaltBytes)
		if _, err := rand.Read(salt); err != nil {
			return ErrPasswordHashing
		}
		hash := argon2.IDKey(raw, salt, argon2Time, argon2MemoryKiB, argon2Parallelism, argon2HashBytes)
		result = PasswordHash{
			encoded: "$" + argon2AlgorithmField + "$" + argon2VersionField + "$" + argon2ParamsField + "$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash),
		}
		return nil
	})
	if err != nil {
		return PasswordHash{}, err
	}
	return result, nil
}

func VerifyPassword(stored PasswordHash, candidate []byte) error {
	return VerifyPasswordContext(context.Background(), stored, candidate)
}

func VerifyPasswordContext(ctx context.Context, stored PasswordHash, candidate []byte) error {
	if len(candidate) == 0 || len(candidate) > maxPasswordBytes {
		return ErrInvalidPasswordInput
	}
	salt, expected, err := parsePasswordHash(stored.encoded)
	if err != nil {
		return ErrInvalidPasswordHash
	}
	matched := false
	err = withProcessKDF(ctx, func() error {
		actual := argon2.IDKey(candidate, salt, argon2Time, argon2MemoryKiB, argon2Parallelism, argon2HashBytes)
		matched = subtle.ConstantTimeCompare(actual, expected) == 1
		return nil
	})
	if err != nil {
		return err
	}
	if !matched {
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
