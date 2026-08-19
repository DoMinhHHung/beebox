package socialprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

type oidcWireContract struct {
	name      string
	provider  authentication.Provider
	pkce      bool
	tokenBody func(string) string
}

func TestOIDCProviderWireContracts(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	contracts := []oidcWireContract{
		{"google", authentication.ProviderGoogle, true, func(idToken string) string {
			return `{"access_token":"fake-google-access","expires_in":3599,"scope":"openid profile","token_type":"Bearer","id_token":"` + idToken + `"}`
		}},
		{"apple", authentication.ProviderApple, false, func(idToken string) string {
			return `{"access_token":"fake-apple-access","token_type":"bearer","expires_in":3600,"refresh_token":"fake-apple-refresh-discarded","id_token":"` + idToken + `"}`
		}},
		{"microsoft", authentication.ProviderMicrosoft, true, func(idToken string) string {
			return `{"token_type":"Bearer","scope":"openid","expires_in":3599,"access_token":"fake-microsoft-access","id_token":"` + idToken + `"}`
		}},
		{"linkedin", authentication.ProviderLinkedIn, false, func(idToken string) string {
			return `{"access_token":"fake-linkedin-access","expires_in":5184000,"scope":"openid","token_type":"Bearer","id_token":"` + idToken + `"}`
		}},
	}
	for _, contract := range contracts {
		contract := contract
		t.Run(contract.name, func(t *testing.T) {
			t.Parallel()
			var tokenCalls, jwksCalls atomic.Int32
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			clientID := "fake-client"
			nonce := "fake-nonce"
			nonceHash := sha256.Sum256([]byte(nonce))
			mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
				jwksCalls.Add(1)
				writeContractJWKS(w, "key-a", &key.PublicKey)
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenCalls.Add(1)
				assertContractTokenRequest(t, r, server.URL+"/callback", oauth2.AuthStyleInParams, contract.pkce)
				claims := map[string]any{
					"iss":     server.URL,
					"aud":     clientID,
					"sub":     "stable-" + contract.name + "-subject",
					"nonce":   nonce,
					"iat":     time.Now().Add(-time.Minute).Unix(),
					"exp":     time.Now().Add(5 * time.Minute).Unix(),
					"email":   "ignored@example.test",
					"name":    "Ignored",
					"picture": "https://ignored.example.test/avatar",
				}
				raw, signErr := signContractJWT(key, "key-a", claims)
				if signErr != nil {
					t.Fatal(signErr)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(contract.tokenBody(raw)))
			})
			client := server.Client()
			a := &adapter{
				provider:     contract.provider,
				clientID:     clientID,
				clientSecret: "fake-client-secret-jwt",
				redirectURL:  server.URL + "/callback",
				tokenURL:     server.URL + "/token",
				authStyle:    oauth2.AuthStyleInParams,
				usePKCE:      contract.pkce,
				useNonce:     true,
				mode:         subjectOIDC,
				verifier:     oidc.NewVerifier(server.URL, oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL+"/jwks"), &oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256"}}),
				httpClient:   client,
			}
			verifier := ""
			if contract.pkce {
				verifier = strings.Repeat("p", 43)
			}
			proof, err := a.ExchangeIdentity(context.Background(), "fake-code", verifier, nonceHash)
			if err != nil {
				t.Fatal(err)
			}
			if proof.Provider != contract.provider || proof.Subject != "stable-"+contract.name+"-subject" {
				t.Fatalf("proof = %#v", proof)
			}
			if tokenCalls.Load() != 1 || jwksCalls.Load() < 1 {
				t.Fatalf("requests token=%d jwks=%d", tokenCalls.Load(), jwksCalls.Load())
			}
		})
	}
}

func TestOIDCProviderTokenErrorsAreBeeBoxOwned(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		provider authentication.Provider
		body     string
	}{
		{"google", authentication.ProviderGoogle, `{"error":"invalid_grant","error_description":"vendor-secret-description"}`},
		{"apple", authentication.ProviderApple, `{"error":"invalid_grant"}`},
		{"microsoft", authentication.ProviderMicrosoft, `{"error":"invalid_grant","error_description":"AADSTS70000: vendor-secret-description","error_codes":[70000],"timestamp":"2026-01-01 00:00:00Z","trace_id":"fake-trace","correlation_id":"fake-correlation"}`},
		{"linkedin", authentication.ProviderLinkedIn, `{"error":"invalid_request","error_description":"vendor-secret-description"}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			a := &adapter{provider: tc.provider, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, authStyle: oauth2.AuthStyleInParams, mode: subjectOIDC, httpClient: server.Client()}
			_, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{})
			if err != authentication.ErrSocialProviderProof || strings.Contains(err.Error(), "vendor-secret-description") || strings.Contains(err.Error(), "fake-secret") || strings.Contains(err.Error(), "fake-code") {
				t.Fatalf("unsafe provider error = %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("token request retried: %d", calls.Load())
			}
		})
	}
}

func TestMicrosoftTenantIssuerIsolation(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	clientID := "fake-client"
	nonce := "fake-nonce"
	nonceHash := sha256.Sum256([]byte(nonce))
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { writeContractJWKS(w, "key-a", &key.PublicKey) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]any{"iss": server.URL + "/tenant-b/v2.0", "aud": clientID, "sub": "stable-microsoft-subject", "nonce": nonce, "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
		raw, _ := signContractJWT(key, "key-a", claims)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fake-microsoft-access","token_type":"Bearer","id_token":"` + raw + `"}`))
	})
	client := server.Client()
	a := &adapter{provider: authentication.ProviderMicrosoft, clientID: clientID, clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL + "/token", authStyle: oauth2.AuthStyleInParams, useNonce: true, mode: subjectOIDC, verifier: oidc.NewVerifier(server.URL+"/tenant-a/v2.0", oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL+"/jwks"), &oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256"}}), httpClient: client}
	if _, err := a.ExchangeIdentity(context.Background(), "fake-code", "", nonceHash); err == nil {
		t.Fatal("Microsoft tenant A verifier accepted tenant B issuer")
	}
}
