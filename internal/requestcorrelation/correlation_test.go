package requestcorrelation

import (
	"encoding/base64"
	"strings"
	"testing"
)

func testKeyValue() string {
	return base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

func TestLoadKeyRequiresExactDedicatedKey(t *testing.T) {
	for name, value := range map[string]string{
		"missing": "",
		"short":   base64.RawURLEncoding.EncodeToString([]byte("too-short")),
		"zero":    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"invalid": "not base64url***",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadKey(func(key string) (string, bool) {
				if key != KeyEnvironmentVariable || value == "" {
					return "", false
				}
				return value, true
			})
			if err == nil {
				t.Fatal("expected invalid key")
			}
		})
	}
	key, err := LoadKey(func(name string) (string, bool) {
		if name == KeyEnvironmentVariable {
			return testKeyValue(), true
		}
		return "", false
	})
	if err != nil || key == (Key{}) {
		t.Fatalf("valid key failed: %v", err)
	}
}

func TestSignVerifyIsPurposeBoundAndTamperSafe(t *testing.T) {
	key, err := LoadKey(func(string) (string, bool) { return testKeyValue(), true })
	if err != nil {
		t.Fatal(err)
	}
	id, ok := ParseID("00112233445566778899aabbccddeeff")
	if !ok {
		t.Fatal("parse canonical id")
	}
	signature := Sign(key, id)
	verified, ok := Verify(key, id.String(), signature)
	if !ok || verified != id {
		t.Fatal("valid signature rejected")
	}
	if _, ok := Verify(key, "10112233445566778899aabbccddeeff", signature); ok {
		t.Fatal("tampered id accepted")
	}
	if _, ok := Verify(key, id.String(), strings.Repeat("A", len(signature))); ok {
		t.Fatal("tampered signature accepted")
	}
}

func TestNewIDProducesCanonicalNonZeroHex(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if id == (ID{}) || len(id.String()) != 32 {
		t.Fatalf("unexpected id %q", id.String())
	}
	if parsed, ok := ParseID(id.String()); !ok || parsed != id {
		t.Fatalf("generated id is not canonical: %q", id.String())
	}
}
