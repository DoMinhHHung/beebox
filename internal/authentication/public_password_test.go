package authentication

import (
	"errors"
	"testing"

	"golang.org/x/text/unicode/norm"
)

func TestPreparePublicPasswordPolicy(t *testing.T) {
	valid := "correct horse battery staple"
	prepared, err := PreparePublicPassword(valid)
	if err != nil {
		t.Fatalf("PreparePublicPassword(valid) error = %v", err)
	}
	if string(prepared) != valid {
		t.Fatalf("prepared = %q, want exact accepted input", prepared)
	}

	for _, raw := range []string{
		"short password",
		"passwordpassword",
		"beeboxpassword",
	} {
		if _, err := PreparePublicPassword(raw); !errors.Is(err, ErrPublicPasswordPolicy) {
			t.Fatalf("PreparePublicPassword(%q) error = %v, want policy rejection", raw, err)
		}
	}
}

func TestPreparePublicPasswordNormalizesNFCWithoutTrimmingOrCompositionRules(t *testing.T) {
	decomposed := "Cafe\u0301 password with spaces"
	prepared, err := PreparePublicPassword(decomposed)
	if err != nil {
		t.Fatalf("PreparePublicPassword() error = %v", err)
	}
	if got, want := string(prepared), norm.NFC.String(decomposed); got != want {
		t.Fatalf("prepared = %q, want NFC %q", got, want)
	}

	spaces := "  all lowercase phrase  "
	prepared, err = PreparePublicPassword(spaces)
	if err != nil {
		t.Fatalf("PreparePublicPassword(spaces) error = %v", err)
	}
	if string(prepared) != spaces {
		t.Fatalf("spaces were silently trimmed: %q", prepared)
	}
}

func TestPreparePublicPasswordCodePointBounds(t *testing.T) {
	if _, err := PreparePublicPassword("abcdefghijklmn"); !errors.Is(err, ErrPublicPasswordPolicy) {
		t.Fatalf("14 code points error = %v", err)
	}
	if _, err := PreparePublicPassword("abcdefghijklmno"); err != nil {
		t.Fatalf("15 code points error = %v", err)
	}
	tooLong := ""
	for range PublicPasswordMaxCodePoints + 1 {
		tooLong += "界"
	}
	if _, err := PreparePublicPassword(tooLong); !errors.Is(err, ErrPublicPasswordPolicy) {
		t.Fatalf("129 code points error = %v", err)
	}
}
