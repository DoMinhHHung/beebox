package authentication

import (
	"errors"
	"regexp"
	"testing"
)

func TestPasswordResetCodeGenerationAndHashing(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9]{8}$`)
	first, err := GeneratePasswordResetCode()
	if err != nil {
		t.Fatalf("GeneratePasswordResetCode() error = %v", err)
	}
	second, err := GeneratePasswordResetCode()
	if err != nil {
		t.Fatalf("GeneratePasswordResetCode() second error = %v", err)
	}
	if !pattern.MatchString(first) || !pattern.MatchString(second) {
		t.Fatal("password reset code is not exactly eight ASCII decimal digits")
	}
	if first == second {
		t.Fatal("two independently generated reset codes unexpectedly matched")
	}
	hash, err := HashPasswordResetCode(first)
	if err != nil {
		t.Fatalf("HashPasswordResetCode() error = %v", err)
	}
	if hash.StorageEncoding() == first || !hash.Valid() {
		t.Fatal("reset verifier persisted plaintext or produced invalid encoding")
	}
	if err := VerifyPasswordResetCode(hash, first); err != nil {
		t.Fatalf("VerifyPasswordResetCode(correct) error = %v", err)
	}
	if err := VerifyPasswordResetCode(hash, "99999999"); !errors.Is(err, ErrPasswordResetFailed) {
		t.Fatalf("VerifyPasswordResetCode(wrong) error = %v", err)
	}
}

func TestPasswordResetCodeRejectsMalformedInput(t *testing.T) {
	for _, input := range []string{"", "1234567", "123456789", "1234 678", "abcdefgh"} {
		if _, err := HashPasswordResetCode(input); !errors.Is(err, ErrInvalidPasswordResetCode) {
			t.Fatalf("HashPasswordResetCode(%q) error = %v", input, err)
		}
	}
}
