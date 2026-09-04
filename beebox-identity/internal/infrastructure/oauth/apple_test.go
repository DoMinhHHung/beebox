package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestAppleClientSecretClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	raw, err := appleClientSecret(Credentials{
		ClientID: "com.beebox.svc",
		Extra: map[string]string{
			"team_id":        "TEAMID01",
			"key_id":         "KEYID001",
			"private_key_p8": p8,
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("parts=%d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "ES256" || header["kid"] != "KEYID001" {
		t.Fatalf("header=%v", header)
	}
	claims, err := decodeJWTClaimsUnverified(raw)
	if err != nil {
		t.Fatal(err)
	}
	if asString(claims["iss"]) != "TEAMID01" {
		t.Fatalf("iss=%v", claims["iss"])
	}
	if asString(claims["sub"]) != "com.beebox.svc" {
		t.Fatalf("sub=%v", claims["sub"])
	}
	if asString(claims["aud"]) != "https://appleid.apple.com" {
		t.Fatalf("aud=%v", claims["aud"])
	}
}

func TestLookupRejectsUnknown(t *testing.T) {
	if _, err := Lookup("nope"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := Lookup("google"); err != nil {
		t.Fatal(err)
	}
}
