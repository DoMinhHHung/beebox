package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testRing(t *testing.T) *KeyRing {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := NewKeyRing(
		"https://auth.example.test",
		"key_active",
		privateKey,
		map[string]ed25519.PublicKey{"key_active": publicKey},
	)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func TestAccessTokenRoundTripAndJWKS(t *testing.T) {
	ring := testRing(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	user := "usr_01234567-89ab-4cde-8fab-0123456789ab"
	app := "app_11234567-89ab-4cde-8fab-0123456789ab"
	sessionID := "ses_21234567-89ab-4cde-8fab-0123456789ab"
	token, err := ring.Sign(user, app, sessionID, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ring.Verify(token, app, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != user || claims.Audience != app || claims.SessionID != sessionID {
		t.Fatalf("claims = %#v", claims)
	}
	if claims.ExpiresAt-claims.IssuedAt != int64(AccessTokenLifetime/time.Second) {
		t.Fatalf("lifetime = %d", claims.ExpiresAt-claims.IssuedAt)
	}
	jwks := ring.JWKS()
	if len(jwks.Keys) != 1 || jwks.Keys[0].Alg != "EdDSA" || jwks.Keys[0].Kty != "OKP" || jwks.Keys[0].Crv != "Ed25519" {
		t.Fatalf("jwks = %#v", jwks)
	}
}

func TestAccessTokenFailsClosed(t *testing.T) {
	ring := testRing(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	app := "app_11234567-89ab-4cde-8fab-0123456789ab"
	token, err := ring.Sign(
		"usr_01234567-89ab-4cde-8fab-0123456789ab",
		app,
		"ses_21234567-89ab-4cde-8fab-0123456789ab",
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Verify(token, "app_31234567-89ab-4cde-8fab-0123456789ab", now); err == nil {
		t.Fatal("wrong audience accepted")
	}
	if _, err := ring.Verify(token, app, now.Add(AccessTokenLifetime+ClockSkew+time.Second)); err == nil {
		t.Fatal("expired token accepted")
	}
	parts := strings.Split(token, ".")
	header := base64.RawURLEncoding.EncodeToString([]byte("{\"alg\":\"HS256\",\"kid\":\"key_active\",\"typ\":\"JWT\"}"))
	if _, err := ring.Verify(header+"."+parts[1]+"."+parts[2], app, now); err == nil {
		t.Fatal("wrong algorithm accepted")
	}
}

func TestAccessTokenTrustContractCanaries(t *testing.T) {
	ring := testRing(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	app := "app_11234567-89ab-4cde-8fab-0123456789ab"
	validHeader := func() map[string]any {
		return map[string]any{"alg": "EdDSA", "kid": "key_active", "typ": "JWT"}
	}
	validClaims := func() map[string]any {
		return map[string]any{
			"iss": ring.issuer,
			"sub": "usr_01234567-89ab-4cde-8fab-0123456789ab",
			"aud": app,
			"sid": "ses_21234567-89ab-4cde-8fab-0123456789ab",
			"exp": now.Add(AccessTokenLifetime).Unix(),
			"nbf": now.Unix(),
			"iat": now.Unix(),
			"jti": "tok_31234567-89ab-4cde-8fab-0123456789ab",
		}
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPublic

	tests := []struct {
		name  string
		build func() string
	}{
		{
			name: "missing kid",
			build: func() string {
				header := validHeader()
				delete(header, "kid")
				return signAccessTokenForTest(t, ring.private, header, validClaims())
			},
		},
		{
			name: "unknown kid",
			build: func() string {
				header := validHeader()
				header["kid"] = "key_unknown"
				return signAccessTokenForTest(t, ring.private, header, validClaims())
			},
		},
		{
			name: "invalid signature",
			build: func() string {
				return signAccessTokenForTest(t, otherPrivate, validHeader(), validClaims())
			},
		},
		{
			name: "wrong issuer",
			build: func() string {
				claims := validClaims()
				claims["iss"] = "https://wrong.example.test"
				return signAccessTokenForTest(t, ring.private, validHeader(), claims)
			},
		},
		{
			name: "premature nbf",
			build: func() string {
				claims := validClaims()
				claims["nbf"] = now.Add(ClockSkew + time.Second).Unix()
				return signAccessTokenForTest(t, ring.private, validHeader(), claims)
			},
		},
		{
			name: "invalid sub public id",
			build: func() string {
				claims := validClaims()
				claims["sub"] = "usr_not-a-uuidv4"
				return signAccessTokenForTest(t, ring.private, validHeader(), claims)
			},
		},
		{
			name: "invalid sid public id",
			build: func() string {
				claims := validClaims()
				claims["sid"] = "ses_not-a-uuidv4"
				return signAccessTokenForTest(t, ring.private, validHeader(), claims)
			},
		},
		{
			name: "invalid jti public id",
			build: func() string {
				claims := validClaims()
				claims["jti"] = "tok_not-a-uuidv4"
				return signAccessTokenForTest(t, ring.private, validHeader(), claims)
			},
		},
		{
			name: "missing exp",
			build: func() string {
				claims := validClaims()
				delete(claims, "exp")
				return signAccessTokenForTest(t, ring.private, validHeader(), claims)
			},
		},
		{
			name: "missing nbf",
			build: func() string {
				claims := validClaims()
				delete(claims, "nbf")
				return signAccessTokenForTest(t, ring.private, validHeader(), claims)
			},
		},
		{
			name: "missing iat",
			build: func() string {
				claims := validClaims()
				delete(claims, "iat")
				return signAccessTokenForTest(t, ring.private, validHeader(), claims)
			},
		},
		{
			name: "malformed exp",
			build: func() string {
				claims := validClaims()
				claims["exp"] = "not-a-number"
				return signAccessTokenForTest(t, ring.private, validHeader(), claims)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ring.Verify(tt.build(), app, now); err != ErrToken {
				t.Fatalf("Verify() error = %v, want ErrToken", err)
			}
		})
	}
}

func signAccessTokenForTest(t *testing.T, privateKey ed25519.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(input)))
}

func TestRefreshSecretIsOpaqueAndHashed(t *testing.T) {
	secret, hash, err := GenerateRefreshSecret()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		t.Fatal("refresh secret encoding invalid")
	}
	if hash != HashRefreshSecret(secret) {
		t.Fatal("refresh verifier hash mismatch")
	}
	if strings.Contains(base64.RawURLEncoding.EncodeToString(hash[:]), secret) {
		t.Fatal("verifier unexpectedly contains plaintext secret")
	}
}
