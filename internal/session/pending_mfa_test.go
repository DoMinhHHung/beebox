package session

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestPendingMFATokenUsesDomainSeparatedVerifierAndExactSecretLength(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	write, token, err := preparePendingMFA("password", "credential:7", now)
	if err != nil {
		t.Fatal(err)
	}
	publicID, encodedSecret, ok := strings.Cut(token, ".")
	if !ok || publicID != write.PublicID {
		t.Fatalf("token public id=%q write public id=%q", publicID, write.PublicID)
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encodedSecret)
	if err != nil || len(secret) != 32 {
		t.Fatalf("secret length=%d err=%v", len(secret), err)
	}
	if write.TokenHash == sha256.Sum256(secret) {
		t.Fatal("pending MFA verifier is not domain separated")
	}
	parsedID, parsedHash, ok := parsePendingMFAToken(token)
	if !ok || parsedID != write.PublicID || parsedHash != write.TokenHash {
		t.Fatalf("parsed id=%q hash=%x ok=%v", parsedID, parsedHash, ok)
	}
	if !write.ExpiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("expires at=%s", write.ExpiresAt)
	}

	for _, malformed := range []string{
		publicID + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 31)),
		publicID + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 33)),
		publicID + "." + encodedSecret + ".extra",
		publicID + ".not_base64!",
	} {
		if _, _, ok := parsePendingMFAToken(malformed); ok {
			t.Fatalf("malformed pending MFA token accepted: %q", malformed)
		}
	}
}

func TestPendingMFAMethodsAdvertiseRecoveryOnlyWhenUsable(t *testing.T) {
	withoutRecovery := pendingMFAMethods(false)
	if len(withoutRecovery) != 1 || withoutRecovery[0] != "totp" {
		t.Fatalf("without recovery=%v", withoutRecovery)
	}
	withRecovery := pendingMFAMethods(true)
	if len(withRecovery) != 2 || withRecovery[0] != "totp" || withRecovery[1] != "recovery_code" {
		t.Fatalf("with recovery=%v", withRecovery)
	}
}
