package authentication

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAccountIdentifierCursorRoundTripAndKindBinding(t *testing.T) {
	createdAt := time.Unix(1_700_000_000, 123_000_000).UTC()
	original := AccountIdentifierCursor{
		Kind:      "emails",
		CreatedAt: createdAt,
		PublicID:  "eml_123e4567-e89b-42d3-a456-426614174000",
	}
	encoded, err := EncodeAccountIdentifierCursor(original)
	if err != nil {
		t.Fatalf("EncodeAccountIdentifierCursor() error = %v", err)
	}
	decoded, err := DecodeAccountIdentifierCursor(encoded, "emails")
	if err != nil {
		t.Fatalf("DecodeAccountIdentifierCursor() error = %v", err)
	}
	if decoded == nil || decoded.Kind != original.Kind || decoded.PublicID != original.PublicID || !decoded.CreatedAt.Equal(createdAt) {
		t.Fatalf("decoded cursor = %+v, want %+v", decoded, original)
	}
	if _, err := DecodeAccountIdentifierCursor(encoded, "phones"); !errors.Is(err, ErrAccountManagementInvalid) {
		t.Fatalf("cross-kind cursor error = %v, want ErrAccountManagementInvalid", err)
	}
}

func TestAccountIdentifierPaginationBoundsAndMalformedCursor(t *testing.T) {
	limit, cursor, err := accountIdentifierPageInput(0, "", "emails")
	if err != nil || limit != AccountIdentifierListDefaultLimit || cursor != nil {
		t.Fatalf("default page input = limit %d cursor %+v err %v", limit, cursor, err)
	}
	for _, invalid := range []int{-1, AccountIdentifierListMaxLimit + 1} {
		if _, _, err := accountIdentifierPageInput(invalid, "", "emails"); !errors.Is(err, ErrAccountManagementInvalid) {
			t.Fatalf("limit %d error = %v, want ErrAccountManagementInvalid", invalid, err)
		}
	}
	for _, raw := range []string{"!not-base64!", strings.Repeat("a", 513)} {
		if _, err := DecodeAccountIdentifierCursor(raw, "emails"); !errors.Is(err, ErrAccountManagementInvalid) {
			t.Fatalf("cursor %q error = %v, want ErrAccountManagementInvalid", raw, err)
		}
	}
}

func TestNormalizeProfileNameNFCAndUnicodeCodePointBoundary(t *testing.T) {
	decomposed := "Cafe\u0301"
	got, err := normalizeProfileName(&decomposed)
	if err != nil {
		t.Fatalf("normalizeProfileName() error = %v", err)
	}
	if got == nil || *got != "Café" {
		t.Fatalf("normalized name = %v, want Café", got)
	}

	exact := strings.Repeat("界", 100)
	if _, err := normalizeProfileName(&exact); err != nil {
		t.Fatalf("100-code-point name rejected: %v", err)
	}
	tooLong := strings.Repeat("界", 101)
	if _, err := normalizeProfileName(&tooLong); !errors.Is(err, ErrAccountManagementInvalid) {
		t.Fatalf("101-code-point name error = %v, want ErrAccountManagementInvalid", err)
	}
	if got, err := normalizeProfileName(nil); err != nil || got != nil {
		t.Fatalf("nil name = %v err %v", got, err)
	}
}

func TestNormalizeProfileLocaleCanonicalizesAndRejectsUnsafeValues(t *testing.T) {
	locale := "en-us"
	got, err := normalizeProfileLocale(&locale)
	if err != nil {
		t.Fatalf("normalizeProfileLocale() error = %v", err)
	}
	if got == nil || *got != "en-US" {
		t.Fatalf("canonical locale = %v, want en-US", got)
	}
	for _, invalid := range []string{"", " en-US", "en-US ", strings.Repeat("a", 36)} {
		value := invalid
		if _, err := normalizeProfileLocale(&value); !errors.Is(err, ErrAccountManagementInvalid) {
			t.Fatalf("locale %q error = %v, want ErrAccountManagementInvalid", invalid, err)
		}
	}
	if got, err := normalizeProfileLocale(nil); err != nil || got != nil {
		t.Fatalf("nil locale = %v err %v", got, err)
	}
}
