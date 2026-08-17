package beebox

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifierFetchesJWKSAndRejectsWrongAudience(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "OKP",
			"crv": "Ed25519",
			"use": "sig",
			"alg": "EdDSA",
			"kid": "k1",
			"x":   base64.RawURLEncoding.EncodeToString(publicKey),
		}}})
	}))
	defer server.Close()
	verifier, err := NewVerifier(server.URL, "app_00000000-0000-4000-8000-000000000001", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	verifier.now = func() time.Time { return now }
	token := signTestToken(t, privateKey, "k1", Claims{
		Issuer:    server.URL,
		Subject:   "usr_00000000-0000-4000-8000-000000000002",
		Audience:  "app_00000000-0000-4000-8000-000000000001",
		SessionID: "ses_00000000-0000-4000-8000-000000000003",
		ExpiresAt: now.Add(time.Minute).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		TokenID:   "tok_00000000-0000-4000-8000-000000000004",
	})
	claims, err := verifier.Verify(context.Background(), token)
	if err != nil || claims.Subject == "" {
		t.Fatalf("Verify() = %#v, %v", claims, err)
	}
	wrong, err := NewVerifier(server.URL, "app_00000000-0000-4000-8000-000000000009", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	wrong.now = verifier.now
	if _, err := wrong.Verify(context.Background(), token); err == nil {
		t.Fatal("wrong audience accepted")
	}
}

func TestVerifierRejectsAlgorithmConfusion(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "OKP",
			"crv": "Ed25519",
			"use": "sig",
			"alg": "EdDSA",
			"kid": "k1",
			"x":   strings.Repeat("A", 43),
		}}})
	}))
	defer server.Close()
	verifier, err := NewVerifier(server.URL, "app_00000000-0000-4000-8000-000000000001", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": "k1"})
	payload, _ := json.Marshal(Claims{})
	token := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".AA"
	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("wrong alg accepted")
	}
}

func signTestToken(t *testing.T, privateKey ed25519.PrivateKey, kid string, claims Claims) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(input)))
}
