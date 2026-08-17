package authentication

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

const verificationCodeDigits = 6

var (
	ErrInvalidVerificationCode     = errors.New("invalid verification code")
	ErrInvalidVerificationCodeHash = errors.New("invalid verification code hash")
	ErrVerificationCodeGeneration  = errors.New("verification code generation failure")
	ErrVerificationCodeHashing     = errors.New("verification code hashing failure")
	ErrVerificationCodeMismatch    = errors.New("verification code mismatch")
)

// VerificationCodeHash is dedicated sensitive verifier material for an email
// verification code. Its encoding is internal and is not a public contract.
type VerificationCodeHash struct {
	encoded string
}

func GenerateVerificationCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", ErrVerificationCodeGeneration
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func validVerificationCode(raw string) bool {
	if len(raw) != verificationCodeDigits {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
	}
	return true
}

func HashVerificationCode(raw string) (VerificationCodeHash, error) {
	if !validVerificationCode(raw) {
		return VerificationCodeHash{}, ErrInvalidVerificationCode
	}
	passwordHash, err := HashPassword([]byte(raw))
	if err != nil {
		return VerificationCodeHash{}, ErrVerificationCodeHashing
	}
	return VerificationCodeHash{encoded: passwordHash.encoded}, nil
}

func ParseVerificationCodeHash(encoded string) (VerificationCodeHash, error) {
	passwordHash, err := ParsePasswordHash(encoded)
	if err != nil {
		return VerificationCodeHash{}, ErrInvalidVerificationCodeHash
	}
	return VerificationCodeHash{encoded: passwordHash.encoded}, nil
}

func (h VerificationCodeHash) Valid() bool {
	_, err := ParseVerificationCodeHash(h.encoded)
	return err == nil
}

// StorageEncoding exposes only the internal persistence representation. It is
// sensitive verifier material and must not be logged or returned publicly.
func (h VerificationCodeHash) StorageEncoding() string {
	return h.encoded
}

func VerifyVerificationCode(stored VerificationCodeHash, candidate string) error {
	if !validVerificationCode(candidate) {
		return ErrInvalidVerificationCode
	}
	if !stored.Valid() {
		return ErrInvalidVerificationCodeHash
	}
	err := VerifyPassword(PasswordHash{encoded: stored.encoded}, []byte(candidate))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrPasswordMismatch):
		return ErrVerificationCodeMismatch
	case errors.Is(err, ErrInvalidPasswordHash):
		return ErrInvalidVerificationCodeHash
	default:
		return ErrVerificationCodeHashing
	}
}
