package identity

import (
	"errors"
	"testing"
)

func TestNormalizePhoneStrictE164(t *testing.T) {
	for _, raw := range []string{"+84901234567", "+15551234567", "  +84901234567\n"} {
		got, err := NormalizePhone(raw)
		if err != nil {
			t.Fatalf("NormalizePhone(%q) error = %v", raw, err)
		}
		if got.E164 == "" || got.E164[0] != '+' {
			t.Fatalf("NormalizePhone(%q) = %#v", raw, got)
		}
	}
}

func TestNormalizePhoneRejectsNonCanonicalForms(t *testing.T) {
	for _, raw := range []string{
		"0901234567", "84 901234567", "+84 901234567", "tel:+84901234567",
		"+84901234567x123", "0015551234567", "+1", "+0123456789", "+1234567890123456",
		"+1-555-123-4567", "+1(555)1234567", "+１２３４５",
	} {
		if _, err := NormalizePhone(raw); !errors.Is(err, ErrInvalidPhone) {
			t.Fatalf("NormalizePhone(%q) error = %v, want ErrInvalidPhone", raw, err)
		}
	}
}
