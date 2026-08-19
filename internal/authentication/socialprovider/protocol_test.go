package socialprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestOIDCProofRejectsInvalidCryptographicClaims(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientID := "fake-client"
	nonce := "fake-nonce"
	nonceHash := sha256.Sum256([]byte(nonce))
	tests := []struct {
		name          string
		signingKey    *rsa.PrivateKey
		alg           string
		expectedNonce [32]byte
		claims        func(string) map[string]any
	}{
		{name: "issuer", signingKey: key, alg: "RS256", expectedNonce: nonceHash, claims: func(issuer string) map[string]any {
			return validContractClaims(issuer+"/wrong", clientID, nonce, time.Now().Add(5*time.Minute))
		}},
		{name: "audience", signingKey: key, alg: "RS256", expectedNonce: nonceHash, claims: func(issuer string) map[string]any {
			return validContractClaims(issuer, "wrong-client", nonce, time.Now().Add(5*time.Minute))
		}},
		{name: "signature", signingKey: otherKey, alg: "RS256", expectedNonce: nonceHash, claims: func(issuer string) map[string]any {
			return validContractClaims(issuer, clientID, nonce, time.Now().Add(5*time.Minute))
		}},
		{name: "expired", signingKey: key, alg: "RS256", expectedNonce: nonceHash, claims: func(issuer string) map[string]any {
			return validContractClaims(issuer, clientID, nonce, time.Now().Add(-time.Minute))
		}},
		{name: "future nbf", signingKey: key, alg: "RS256", expectedNonce: nonceHash, claims: func(issuer string) map[string]any {
			c := validContractClaims(issuer, clientID, nonce, time.Now().Add(5*time.Minute))
			c["nbf"] = time.Now().Add(10 * time.Minute).Unix()
			return c
		}},
		{name: "nonce", signingKey: key, alg: "RS256", expectedNonce: sha256.Sum256([]byte("wrong-nonce")), claims: func(issuer string) map[string]any {
			return validContractClaims(issuer, clientID, nonce, time.Now().Add(5*time.Minute))
		}},
		{name: "missing sub", signingKey: key, alg: "RS256", expectedNonce: nonceHash, claims: func(issuer string) map[string]any {
			c := validContractClaims(issuer, clientID, nonce, time.Now().Add(5*time.Minute))
			delete(c, "sub")
			c["email"] = "fallback@example.test"
			c["name"] = "Fallback"
			return c
		}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
				n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
				e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": "key-a", "use": "sig", "alg": "RS256", "n": n, "e": e}}})
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				raw, signErr := signContractJWT(tt.signingKey, "key-a", tt.claims(server.URL))
				if signErr != nil {
					t.Fatal(signErr)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-access", "token_type": "Bearer", "id_token": raw})
			})
			client := server.Client()
			a := &adapter{provider: authentication.ProviderGoogle, clientID: clientID, clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL + "/token", authStyle: oauth2.AuthStyleInParams, useNonce: true, mode: subjectOIDC, verifier: oidc.NewVerifier(server.URL, oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL+"/jwks"), &oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256"}}), httpClient: client}
			if _, err := a.ExchangeIdentity(context.Background(), "fake-code", "", tt.expectedNonce); err == nil {
				t.Fatalf("expected %s rejection", tt.name)
			}
		})
	}
}

func TestOIDCProofRejectsMalformedAndUnsupportedJWT(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"not-a-jwt", "a.b.c"} {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			client := &http.Client{Timeout: 50 * time.Millisecond}
			a := &adapter{provider: authentication.ProviderGoogle, useNonce: true, mode: subjectOIDC, verifier: oidc.NewVerifier("https://issuer.example.test", oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), "https://issuer.example.test/jwks"), &oidc.Config{ClientID: "fake-client", SupportedSigningAlgs: []string{"RS256"}}), httpClient: client}
			token := (&oauth2.Token{AccessToken: "fake-access"}).WithExtra(map[string]any{"id_token": raw})
			if _, err := a.subjectFromIDToken(context.Background(), token, sha256.Sum256([]byte("fake-nonce"))); err == nil {
				t.Fatal("malformed JWT accepted")
			}
		})
	}
}

func TestProviderBackchannelCancellationTimeoutBoundAndNoRetry(t *testing.T) {
	t.Parallel()
	t.Run("cancellation", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			<-r.Context().Done()
		}))
		defer server.Close()
		a := &adapter{provider: authentication.ProviderDiscord, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, userInfoURL: server.URL, authStyle: oauth2.AuthStyleInParams, mode: subjectTopLevelStringID, httpClient: server.Client()}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := a.ExchangeIdentity(ctx, "fake-code", "", [32]byte{}); err == nil {
			t.Fatal("expected cancellation error")
		}
		if calls.Load() > 1 {
			t.Fatalf("cancelled request retried: %d", calls.Load())
		}
	})
	t.Run("timeout", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			time.Sleep(100 * time.Millisecond)
		}))
		defer server.Close()
		client := server.Client()
		client.Timeout = 10 * time.Millisecond
		a := &adapter{provider: authentication.ProviderDiscord, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, userInfoURL: server.URL, authStyle: oauth2.AuthStyleInParams, mode: subjectTopLevelStringID, httpClient: client}
		if _, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{}); err == nil {
			t.Fatal("expected timeout")
		}
		if calls.Load() != 1 {
			t.Fatalf("timeout calls = %d", calls.Load())
		}
	})
	t.Run("bounded response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "4096")
			_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
		}))
		defer server.Close()
		client := &http.Client{Timeout: time.Second, Transport: &boundedTransport{base: http.DefaultTransport, max: 128}}
		a := &adapter{provider: authentication.ProviderDiscord, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, userInfoURL: server.URL, authStyle: oauth2.AuthStyleInParams, mode: subjectTopLevelStringID, httpClient: client}
		if _, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{}); err == nil {
			t.Fatal("expected oversized response rejection")
		}
	})
}

func validContractClaims(issuer, audience, nonce string, expiry time.Time) map[string]any {
	return map[string]any{"iss": issuer, "aud": audience, "sub": "stable-subject", "nonce": nonce, "iat": time.Now().Add(-time.Minute).Unix(), "exp": expiry.Unix()}
}
