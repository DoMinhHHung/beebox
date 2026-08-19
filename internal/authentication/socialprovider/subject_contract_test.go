package socialprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestOIDCSubjectContractForEachProvider(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	providers := []authentication.Provider{
		authentication.ProviderGoogle,
		authentication.ProviderApple,
		authentication.ProviderMicrosoft,
		authentication.ProviderLinkedIn,
	}
	cases := []struct {
		name    string
		subject any
		present bool
		wantOK  bool
	}{
		{name: "valid", subject: "stable-subject", present: true, wantOK: true},
		{name: "missing", present: false},
		{name: "empty", subject: "", present: true},
		{name: "wrong type", subject: 12345, present: true},
		{name: "oversized", subject: strings.Repeat("s", 513), present: true},
	}
	for _, provider := range providers {
		provider := provider
		t.Run(string(provider), func(t *testing.T) {
			for _, tc := range cases {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					mux := http.NewServeMux()
					server := httptest.NewServer(mux)
					defer server.Close()
					clientID := "fake-client"
					nonce := "fake-nonce"
					nonceHash := sha256.Sum256([]byte(nonce))
					mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
						writeContractJWKS(w, "key-a", &key.PublicKey)
					})
					mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
						claims := map[string]any{
							"iss":   server.URL,
							"aud":   clientID,
							"nonce": nonce,
							"iat":   time.Now().Add(-time.Minute).Unix(),
							"exp":   time.Now().Add(5 * time.Minute).Unix(),
							"email": "fallback@example.test",
							"name":  "Fallback",
						}
						if tc.present {
							claims["sub"] = tc.subject
						}
						raw, signErr := signContractJWT(key, "key-a", claims)
						if signErr != nil {
							t.Fatal(signErr)
						}
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-access", "token_type": "Bearer", "id_token": raw})
					})
					client := server.Client()
					a := &adapter{
						provider:     provider,
						clientID:     clientID,
						clientSecret: "fake-secret",
						redirectURL:  server.URL + "/callback",
						tokenURL:     server.URL + "/token",
						authStyle:    oauth2.AuthStyleInParams,
						useNonce:     true,
						mode:         subjectOIDC,
						verifier:     oidc.NewVerifier(server.URL, oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL+"/jwks"), &oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256"}}),
						httpClient:   client,
					}
					proof, err := a.ExchangeIdentity(context.Background(), "fake-code", "", nonceHash)
					if tc.wantOK {
						if err != nil || proof.Provider != provider || proof.Subject != "stable-subject" {
							t.Fatalf("proof=%#v err=%v", proof, err)
						}
						return
					}
					if err == nil {
						t.Fatalf("accepted invalid %s subject %#v", provider, tc.subject)
					}
				})
			}
		})
	}
}

func TestPureOAuthSubjectContractForEachProvider(t *testing.T) {
	t.Parallel()
	providers := []struct {
		provider authentication.Provider
		mode     subjectMode
		valid    string
		missing  string
		empty    string
		wrong    string
		oversize string
	}{
		{authentication.ProviderGitHub, subjectTopLevelNumericID, `{"id":12345}`, `{}`, `{"id":""}`, `{"id":"12345"}`, `{"id":1234567890123456789012345678901234567890}`},
		{authentication.ProviderGitLab, subjectTopLevelNumericID, `{"id":23456}`, `{}`, `{"id":""}`, `{"id":"23456"}`, `{"id":1234567890123456789012345678901234567890}`},
		{authentication.ProviderFacebook, subjectTopLevelStringID, `{"id":"34567"}`, `{}`, `{"id":""}`, `{"id":34567}`, `{"id":"` + strings.Repeat("f", 513) + `"}`},
		{authentication.ProviderDiscord, subjectTopLevelStringID, `{"id":"45678"}`, `{}`, `{"id":""}`, `{"id":45678}`, `{"id":"` + strings.Repeat("d", 513) + `"}`},
		{authentication.ProviderX, subjectNestedStringID, `{"data":{"id":"56789"}}`, `{"data":{}}`, `{"data":{"id":""}}`, `{"data":{"id":56789}}`, `{"data":{"id":"` + strings.Repeat("x", 513) + `"}}`},
	}
	for _, provider := range providers {
		provider := provider
		t.Run(string(provider.provider), func(t *testing.T) {
			cases := []struct {
				name   string
				body   string
				wantOK bool
			}{
				{name: "valid", body: provider.valid, wantOK: true},
				{name: "missing", body: provider.missing},
				{name: "empty", body: provider.empty},
				{name: "wrong type", body: provider.wrong},
				{name: "oversized", body: provider.oversize},
			}
			for _, tc := range cases {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					mux := http.NewServeMux()
					server := httptest.NewServer(mux)
					defer server.Close()
					mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"access_token":"fake-provider-access","token_type":"Bearer"}`))
					})
					mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(tc.body))
					})
					a := &adapter{provider: provider.provider, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL + "/token", userInfoURL: server.URL + "/profile", authStyle: oauth2.AuthStyleInParams, mode: provider.mode, httpClient: server.Client()}
					proof, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{})
					if tc.wantOK {
						if err != nil || proof.Provider != provider.provider || proof.Subject == "" {
							t.Fatalf("proof=%#v err=%v", proof, err)
						}
						return
					}
					if err == nil {
						t.Fatalf("accepted invalid %s subject body %s", provider.provider, tc.body)
					}
				})
			}
		})
	}
}

func TestTikTokSubjectContract(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		body   string
		wantOK bool
	}{
		{name: "valid", body: `{"access_token":"fake-access","open_id":"stable-open-id","token_type":"Bearer"}`, wantOK: true},
		{name: "missing", body: `{"access_token":"fake-access","email":"fallback@example.test"}`},
		{name: "empty", body: `{"access_token":"fake-access","open_id":""}`},
		{name: "wrong type", body: `{"access_token":"fake-access","open_id":12345}`},
		{name: "oversized", body: `{"access_token":"fake-access","open_id":"` + strings.Repeat("t", 513) + `"}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			a := &adapter{provider: authentication.ProviderTikTok, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, mode: subjectTikTokOpenID, tikTok: true, httpClient: server.Client()}
			proof, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{})
			if tc.wantOK {
				if err != nil || proof.Subject != "stable-open-id" {
					t.Fatalf("proof=%#v err=%v", proof, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted invalid TikTok subject body %s", tc.body)
			}
		})
	}
}
