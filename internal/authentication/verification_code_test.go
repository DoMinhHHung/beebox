package authentication

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestVerificationCodeGenerationIsSixDecimalDigits(t *testing.T) {
	first, err := GenerateVerificationCode()
	if err != nil {
		t.Fatalf("GenerateVerificationCode() error = %v", err)
	}
	if len(first) != 6 {
		t.Fatalf("generated code length = %d, want 6", len(first))
	}
	for i := range first {
		if first[i] < '0' || first[i] > '9' {
			t.Fatal("generated code contains a non-decimal byte")
		}
	}

	different := false
	for range 8 {
		next, err := GenerateVerificationCode()
		if err != nil {
			t.Fatalf("GenerateVerificationCode() error = %v", err)
		}
		if next != first {
			different = true
			break
		}
	}
	if !different {
		t.Fatal("independent verification codes were deterministically identical")
	}
}

func TestVerificationCodeHashIsDedicatedAndVerifies(t *testing.T) {
	if reflect.TypeOf(VerificationCodeHash{}) == reflect.TypeOf(PasswordHash{}) {
		t.Fatal("verification code hash must remain a distinct semantic type")
	}

	const code = "000042"
	hash, err := HashVerificationCode(code)
	if err != nil {
		t.Fatalf("HashVerificationCode() error = %v", err)
	}
	if strings.Contains(hash.StorageEncoding(), code) {
		t.Fatal("verification code hash contains plaintext code")
	}
	if err := VerifyVerificationCode(hash, code); err != nil {
		t.Fatalf("VerifyVerificationCode(correct) error = %v", err)
	}
	if err := VerifyVerificationCode(hash, "000043"); !errors.Is(err, ErrVerificationCodeMismatch) {
		t.Fatalf("VerifyVerificationCode(wrong) error = %v, want mismatch", err)
	}
}

func TestVerificationCodeRejectsMalformedInputAndHash(t *testing.T) {
	for _, raw := range []string{"", "12345", "1234567", " 12345", "12345 ", "12345a"} {
		if _, err := HashVerificationCode(raw); !errors.Is(err, ErrInvalidVerificationCode) {
			t.Fatalf("HashVerificationCode(malformed) error = %v", err)
		}
	}
	if _, err := ParseVerificationCodeHash("$argon2id$v=19$m=1,t=1,p=1$bad$bad"); !errors.Is(err, ErrInvalidVerificationCodeHash) {
		t.Fatalf("ParseVerificationCodeHash() error = %v", err)
	}
}
