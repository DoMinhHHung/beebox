package authentication

import (
	"errors"
	"strings"
	"testing"
)

func TestHashPasswordUsesRandomSaltAndVerifiesExactBytes(t *testing.T) {
	raw := []byte(" synthetic password with spaces ")
	first, err := HashPassword(raw)
	if err != nil {
		t.Fatalf("HashPassword(first) error = %v", err)
	}
	second, err := HashPassword(raw)
	if err != nil {
		t.Fatalf("HashPassword(second) error = %v", err)
	}
	if first.StorageEncoding() == second.StorageEncoding() {
		t.Fatal("HashPassword() produced identical encodings; want random per-hash salt")
	}
	if err := VerifyPassword(first, raw); err != nil {
		t.Fatalf("VerifyPassword(first, correct) error = %v", err)
	}
	if err := VerifyPassword(second, raw); err != nil {
		t.Fatalf("VerifyPassword(second, correct) error = %v", err)
	}
	if err := VerifyPassword(first, []byte("synthetic password with spaces")); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("VerifyPassword(trimmed candidate) error = %v, want ErrPasswordMismatch", err)
	}
	if err := VerifyPassword(first, []byte("wrong synthetic password")); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("VerifyPassword(wrong) error = %v, want ErrPasswordMismatch", err)
	}
}

func TestPasswordInputBounds(t *testing.T) {
	for _, input := range [][]byte{nil, {}, make([]byte, maxPasswordBytes+1)} {
		if _, err := HashPassword(input); !errors.Is(err, ErrInvalidPasswordInput) {
			t.Fatalf("HashPassword(invalid length %d) error = %v, want ErrInvalidPasswordInput", len(input), err)
		}
	}

	hash, err := HashPassword([]byte("valid synthetic password"))
	if err != nil {
		t.Fatalf("HashPassword(valid) error = %v", err)
	}
	for _, candidate := range [][]byte{nil, {}, make([]byte, maxPasswordBytes+1)} {
		if err := VerifyPassword(hash, candidate); !errors.Is(err, ErrInvalidPasswordInput) {
			t.Fatalf("VerifyPassword(invalid length %d) error = %v, want ErrInvalidPasswordInput", len(candidate), err)
		}
	}
}

func TestPasswordHashEnvelopeIsStrictAndBounded(t *testing.T) {
	hash, err := HashPassword([]byte("envelope fixture"))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	encoded := hash.StorageEncoding()
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("password envelope field count = %d, want 6", len(parts))
	}
	if parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=4" {
		t.Fatalf("password envelope metadata = %q/%q/%q, want BeeBox v1 Argon2id defaults", parts[1], parts[2], parts[3])
	}
	if len(parts[4]) != encodedSaltLength || len(parts[5]) != encodedHashLength {
		t.Fatalf("password envelope encoded lengths = %d/%d, want %d/%d", len(parts[4]), len(parts[5]), encodedSaltLength, encodedHashLength)
	}
	parsed, err := ParsePasswordHash(encoded)
	if err != nil || !parsed.Valid() {
		t.Fatalf("ParsePasswordHash(valid) error = %v, Valid=%v", err, parsed.Valid())
	}
}

func TestPasswordHashParserRejectsMalformedUnsupportedAndUnsafeMetadata(t *testing.T) {
	valid, err := HashPassword([]byte("parser fixture"))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	parts := strings.Split(valid.StorageEncoding(), "$")

	tests := map[string]string{
		"empty":                 "",
		"unsupported algorithm": "$argon2i$v=19$m=65536,t=3,p=4$" + parts[4] + "$" + parts[5],
		"unsupported version":   "$argon2id$v=16$m=65536,t=3,p=4$" + parts[4] + "$" + parts[5],
		"excessive memory":      "$argon2id$v=19$m=4294967295,t=3,p=4$" + parts[4] + "$" + parts[5],
		"wrong time":            "$argon2id$v=19$m=65536,t=4,p=4$" + parts[4] + "$" + parts[5],
		"wrong parallelism":     "$argon2id$v=19$m=65536,t=3,p=8$" + parts[4] + "$" + parts[5],
		"malformed salt base64": "$argon2id$v=19$m=65536,t=3,p=4$!!!!!!!!!!!!!!!!!!!!!!$" + parts[5],
		"malformed hash base64": "$argon2id$v=19$m=65536,t=3,p=4$" + parts[4] + "$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
		"oversized salt field":  "$argon2id$v=19$m=65536,t=3,p=4$" + strings.Repeat("A", 10000) + "$" + parts[5],
	}

	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePasswordHash(encoded); !errors.Is(err, ErrInvalidPasswordHash) {
				t.Fatalf("ParsePasswordHash() error = %v, want ErrInvalidPasswordHash", err)
			}
		})
	}
}
