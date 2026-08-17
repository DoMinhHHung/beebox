package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeEmailDeterministicPolicy(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantStored string
		wantKey    string
	}{
		{
			name:       "case folds complete mailbox",
			input:      "Alice@Example.COM",
			wantStored: "Alice@Example.COM",
			wantKey:    "alice@example.com",
		},
		{
			name:       "trims surrounding ASCII spaces",
			input:      "  Alice@Example.COM  ",
			wantStored: "Alice@Example.COM",
			wantKey:    "alice@example.com",
		},
		{
			name:       "preserves dots and plus tags",
			input:      "First.Last+News@Example.COM",
			wantStored: "First.Last+News@Example.COM",
			wantKey:    "first.last+news@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, err := NormalizeEmail(tt.input)
			if err != nil {
				t.Fatalf("NormalizeEmail() error = %v", err)
			}
			second, err := NormalizeEmail(tt.input)
			if err != nil {
				t.Fatalf("NormalizeEmail() second error = %v", err)
			}
			if first != second {
				t.Fatalf("NormalizeEmail() is not deterministic: first=%+v second=%+v", first, second)
			}
			if first.EmailAddress != tt.wantStored || first.ComparisonKey != tt.wantKey {
				t.Fatalf("NormalizeEmail() = %+v, want stored=%q key=%q", first, tt.wantStored, tt.wantKey)
			}
		})
	}
}

func TestNormalizeEmailRejectsUnsupportedOrUnsafeInput(t *testing.T) {
	oversizedLocal := strings.Repeat("a", 250) + "@example.test"
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "spaces only", input: "   "},
		{name: "non ascii", input: "álîce@example.test"},
		{name: "carriage return", input: "alice@example.test\r"},
		{name: "line feed", input: "alice@example.test\n"},
		{name: "tab control", input: "alice\t@example.test"},
		{name: "nul control", input: "alice\x00@example.test"},
		{name: "display name", input: "Alice <alice@example.test>"},
		{name: "missing local", input: "@example.test"},
		{name: "missing domain", input: "alice@"},
		{name: "plain text", input: "not-an-email"},
		{name: "internal whitespace", input: "alice @example.test"},
		{name: "oversized", input: oversizedLocal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NormalizeEmail(tt.input); !errors.Is(err, ErrInvalidEmail) {
				t.Fatalf("NormalizeEmail(%q) error = %v, want ErrInvalidEmail", tt.input, err)
			}
		})
	}
}

func TestEmailIdentifierInternalIDValidity(t *testing.T) {
	if EmailIdentifierInternalID(0).Valid() || EmailIdentifierInternalID(-1).Valid() {
		t.Fatal("non-positive email identifier internal ID reported valid")
	}
	if !EmailIdentifierInternalID(1).Valid() {
		t.Fatal("positive email identifier internal ID reported invalid")
	}
}
