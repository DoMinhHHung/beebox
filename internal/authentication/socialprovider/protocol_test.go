package socialprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestPureOAuthProviderProofMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		provider authentication.Provider
		mode     subjectMode
		profile  string
		subject  string
		pkce     bool
	}{
		{authentication.ProviderGitHub, subjectTopLevelID, `{"id":12345,"email":"ignored@example.test","name":"Ignored"}`, "12345", true},
		{authentication.ProviderGitLab, subjectTopLevelID, `{"id":23456,"email":"ignored@example.test","avatar":"ignored"}`, "23456", true},
		{authentication.ProviderFacebook, subjectTopLevelID, `{"id":"34567","email":"ignored@example.test"}`, "34567", false},
		{authentication.ProviderDiscord, subjectTopLevelID, `{"id":"45678","email":"ignored@example.test"}`, "45678", false},
		{authentication.ProviderX, subjectNestedDataID, `{"data":{"id":"56789"},"email":"ignored@example.test"}`, "56789", true},
	}
	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			t.Parallel()
			var tokenCalls, profileCalls atomic.Int32
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenCalls.Add(1)
				if r.Method != http.MethodPost {
					t.Fatalf("token method = %s", r.Method)
				}
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.Form.Get("code") != "fake-code" || r.Form.Get("redirect_uri") != server.URL+"/callback" {
					t.Fatalf("token form = %v", r.Form)
				}
				if tt.pkce && r.Form.Get("code_verifier") != strings.Repeat("p", 43) {
					t.Fatalf("missing provider PKCE verifier: %v", r.Form)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"fake-provider-access","token_type":"Bearer","expires_in":300}`))
			})
			mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
				profileCalls.Add(1)
				if got := r.Header.Get("Authorization"); got != "Bearer fake-provider-access" {
					t.Fatalf("authorization = %q", got)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.profile))
			})
			adapter := &adapter{
				provider: tt.provider, clientID: "fake-client", clientSecret: "fake-secret",
				redirectURL: server.URL + "/callback", tokenURL: server.URL + "/token", userInfoURL: server.URL + "/profile",
				authStyle: oauth2.AuthStyleInParams, usePKCE: tt.pkce, mode: tt.mode, httpClient: server.Client(),
			}
			verifier := ""
			if tt.pkce {
				verifier = strings.Repeat("p", 43)
			}
			proof, err := adapter.ExchangeIdentity(context.Background(), "fake-code", verifier, [32]byte{})
			if err != nil {
				t.Fatal(err)
			}
			if proof.Provider != tt.provider || proof.Subject != tt.subject {
				t.Fatalf("proof = %#v", proof)
			}
			if tokenCalls.Load() != 1 || profileCalls.Load() != 1 {
				t.Fatalf("unexpected retries token=%d profile=%d", tokenCalls.Load(), profileCalls.Load())
			}
		})
	}
}

func TestOIDCProviderProofMatrix(t *testing.T) {
	t.Parallel()
	providers := []authentication.Provider{
		authentication.ProviderGoogle,
		authentication.ProviderApple,
		authentication.ProviderMicrosoft,
		authentication.ProviderLinkedIn,
	}
	for _, provider := range providers {
		t.Run(string(provider), func(t *testing.T) {
			t.Parallel()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			var tokenCalls, jwksCalls atomic.Int32
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			nonce := "fake-oidc-nonce"
			nonceHash := sha256.Sum256([]byte(nonce))
			clientID := "fake-client"
			mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
				jwksCalls.Add(1)
				n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
				e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": "fake-key", "use": "sig", "alg": "RS256", "n": n, "e": e}}})
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenCalls.Add(1)
				claims := map[string]any{
					"iss": server.URL, "aud": clientID, "sub": "stable-oidc-subject", "nonce": nonce,
					"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
					"email": "ignored@example.test", "name": "Ignored", "picture": "https://ignored.example.test/avatar",
				}
				raw, signErr := signRS256JWT(key, claims)
				if signErr != nil {
					t.Fatal(signErr)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-access", "token_type": "Bearer", "expires_in": 300, "id_token": raw})
			})
			client := server.Client()
			verifier := oidc.NewVerifier(server.URL, oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL+"/jwks"), &oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256"}})
			adapter := &adapter{
				provider: provider, clientID: clientID, clientSecret: "fake-secret", redirectURL: server.URL + "/callback",
				tokenURL: server.URL + "/token", authStyle: oauth2.AuthStyleInParams, useNonce: true,
				mode: subjectOIDC, verifier: verifier, httpClient: client,
			}
			proof, err := adapter.ExchangeIdentity(context.Background(), "fake-code", "", nonceHash)
			if err != nil {
				t.Fatal(err)
			}
			if proof.Provider != provider || proof.Subject != "stable-oidc-subject" {
				t.Fatalf("proof = %#v", proof)
			}
			if tokenCalls.Load() != 1 || jwksCalls.Load() == 0 {
				t.Fatalf("token=%d jwks=%d", tokenCalls.Load(), jwksCalls.Load())
			}
		})
	}
}

func TestOIDCProofRejectsIssuerAudienceSignatureExpiryAndNonce(t *testing.T) {
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
		name      string
		claims    func(string) map[string]any
		signingKey *rsa.PrivateKey
		expectedNonce [32]byte
	}{
		{name: "issuer", signingKey: key, expectedNonce: nonceHash, claims: func(issuer string) map[string]any { return validOIDCClaims(issuer+"/wrong", clientID, nonce, time.Now().Add(5*time.Minute)) }},
		{name: "audience", signingKey: key, expectedNonce: nonceHash, claims: func(issuer string) map[string]any { return validOIDCClaims(issuer, "wrong-client", nonce, time.Now().Add(5*time.Minute)) }},
		{name: "signature", signingKey: otherKey, expectedNonce: nonceHash, claims: func(issuer string) map[string]any { return validOIDCClaims(issuer, clientID, nonce, time.Now().Add(5*time.Minute)) }},
		{name: "expired", signingKey: key, expectedNonce: nonceHash, claims: func(issuer string) map[string]any { return validOIDCClaims(issuer, clientID, nonce, time.Now().Add(-time.Minute)) }},
		{name: "nonce", signingKey: key, expectedNonce: sha256.Sum256([]byte("wrong-nonce")), claims: func(issuer string) map[string]any { return validOIDCClaims(issuer, clientID, nonce, time.Now().Add(5*time.Minute)) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
				n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
				e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": "fake-key", "use": "sig", "alg": "RS256", "n": n, "e": e}}})
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				raw, signErr := signRS256JWT(tt.signingKey, tt.claims(server.URL))
				if signErr != nil {
					t.Fatal(signErr)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-access", "token_type": "Bearer", "id_token": raw})
			})
			client := server.Client()
			adapter := &adapter{
				provider: authentication.ProviderGoogle, clientID: clientID, clientSecret: "fake-secret", redirectURL: server.URL + "/callback",
				tokenURL: server.URL + "/token", authStyle: oauth2.AuthStyleInParams, useNonce: true, mode: subjectOIDC,
				verifier: oidc.NewVerifier(server.URL, oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL+"/jwks"), &oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256"}}), httpClient: client,
			}
			if _, err := adapter.ExchangeIdentity(context.Background(), "fake-code", "", tt.expectedNonce); err == nil {
				t.Fatalf("expected %s rejection", tt.name)
			}
		})
	}
}

func TestTikTokProofUsesOpenIDAndDiscardsOtherTokenFields(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("client_key") != "fake-client" || r.Form.Get("client_secret") != "fake-secret" || r.Form.Get("code") != "fake-code" {
			t.Fatalf("form = %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fake-provider-access","refresh_token":"fake-provider-refresh","open_id":"stable-tiktok-open-id"}`))
	}))
	defer server.Close()
	adapter := &adapter{provider: authentication.ProviderTikTok, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, mode: subjectTikTokOpenID, tikTok: true, httpClient: server.Client()}
	proof, err := adapter.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if proof != (authentication.ExternalIdentityProof{Provider: authentication.ProviderTikTok, Subject: "stable-tiktok-open-id"}) {
		t.Fatalf("proof = %#v", proof)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestProviderBackchannelCancellationTimeoutBoundAndNoRetry(t *testing.T) {
	t.Parallel()
	t.Run("cancellation", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); <-r.Context().Done() }))
		defer server.Close()
		adapter := &adapter{provider: authentication.ProviderDiscord, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, userInfoURL: server.URL, authStyle: oauth2.AuthStyleInParams, mode: subjectTopLevelID, httpClient: server.Client()}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := adapter.ExchangeIdentity(ctx, "fake-code", "", [32]byte{}); err == nil {
			t.Fatal("expected cancellation error")
		}
		if calls.Load() > 1 {
			t.Fatalf("retried cancelled request: %d", calls.Load())
		}
	})
	t.Run("timeout", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); time.Sleep(100 * time.Millisecond) }))
		defer server.Close()
		client := server.Client()
		client.Timeout = 10 * time.Millisecond
		adapter := &adapter{provider: authentication.ProviderDiscord, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, userInfoURL: server.URL, authStyle: oauth2.AuthStyleInParams, mode: subjectTopLevelID, httpClient: client}
		if _, err := adapter.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{}); err == nil {
			t.Fatal("expected timeout")
		}
		if calls.Load() != 1 {
			t.Fatalf("timeout calls = %d", calls.Load())
		}
	})
	t.Run("bounded body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "4096")
			_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
		}))
		defer server.Close()
		transport := &boundedTransport{base: http.DefaultTransport, max: 128}
		client := &http.Client{Timeout: time.Second, Transport: transport}
		adapter := &adapter{provider: authentication.ProviderDiscord, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, userInfoURL: server.URL, authStyle: oauth2.AuthStyleInParams, mode: subjectTopLevelID, httpClient: client}
		if _, err := adapter.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{}); err == nil {
			t.Fatal("expected oversized response rejection")
		}
	})
}

func validOIDCClaims(issuer, audience, nonce string, expiry time.Time) map[string]any {
	return map[string]any{"iss": issuer, "aud": audience, "sub": "stable-subject", "nonce": nonce, "iat": time.Now().Add(-time.Minute).Unix(), "exp": expiry.Unix()}
}

func signRS256JWT(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "fake-key", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, 0, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func TestRawIDRejectsMalformedSubjects(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`""`, `-1`, `1.5`, `{}`, `null`} {
		if subject, err := rawID(json.RawMessage(raw)); err == nil {
			t.Fatalf("rawID(%s) = %q", raw, subject)
		}
	}
	if subject, err := rawID(json.RawMessage(`"opaque-id"`)); err != nil || subject != "opaque-id" {
		t.Fatalf("string subject = %q, %v", subject, err)
	}
	if subject, err := rawID(json.RawMessage(`123`)); err != nil || subject != "123" {
		t.Fatalf("numeric subject = %q, %v", subject, err)
	}
}

func TestProviderErrorIsBeeBoxOwned(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "vendor-secret-error-text", http.StatusBadRequest)
	}))
	defer server.Close()
	adapter := &adapter{provider: authentication.ProviderGitHub, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, userInfoURL: server.URL, authStyle: oauth2.AuthStyleInParams, mode: subjectTopLevelID, httpClient: server.Client()}
	_, err := adapter.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{})
	if err == nil || strings.Contains(err.Error(), "vendor-secret-error-text") {
		t.Fatalf("unsafe provider error = %v", err)
	}
}

var _ = fmt.Sprintf
var _ = url.Values{}
