package socialprovider

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"golang.org/x/oauth2"
)

func TestStandardProviderTokenResponsesRequireAccessTokenAndValidBody(t *testing.T) {
	t.Parallel()
	providers := []struct {
		provider    authentication.Provider
		authStyle   oauth2.AuthStyle
		pkce        bool
		nonce       bool
		contentType string
		missingBody string
	}{
		{authentication.ProviderGoogle, oauth2.AuthStyleInParams, true, true, "application/json", `{"token_type":"Bearer","id_token":"ignored-without-access-token"}`},
		{authentication.ProviderApple, oauth2.AuthStyleInParams, false, true, "application/json", `{"token_type":"bearer","id_token":"ignored-without-access-token"}`},
		{authentication.ProviderMicrosoft, oauth2.AuthStyleInParams, true, true, "application/json", `{"token_type":"Bearer","id_token":"ignored-without-access-token"}`},
		{authentication.ProviderGitHub, oauth2.AuthStyleInParams, true, false, "application/x-www-form-urlencoded", "token_type=bearer"},
		{authentication.ProviderGitLab, oauth2.AuthStyleInParams, true, false, "application/json", `{"token_type":"bearer","expires_in":7200}`},
		{authentication.ProviderDiscord, oauth2.AuthStyleInParams, false, false, "application/json", `{"token_type":"Bearer","scope":"identify"}`},
		{authentication.ProviderLinkedIn, oauth2.AuthStyleInParams, false, true, "application/json", `{"token_type":"Bearer","scope":"openid"}`},
		{authentication.ProviderX, oauth2.AuthStyleInHeader, true, false, "application/json", `{"token_type":"bearer","scope":"tweet.read users.read"}`},
	}
	for _, provider := range providers {
		provider := provider
		t.Run(string(provider.provider), func(t *testing.T) {
			for _, tc := range []struct {
				name string
				body string
			}{
				{name: "missing access token", body: provider.missingBody},
				{name: "malformed body", body: "{not-valid-provider-token-response"},
			} {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					var tokenCalls, profileCalls atomic.Int32
					mux := http.NewServeMux()
					server := httptest.NewServer(mux)
					defer server.Close()
					mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
						tokenCalls.Add(1)
						w.Header().Set("Content-Type", provider.contentType)
						_, _ = w.Write([]byte(tc.body))
					})
					mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) { profileCalls.Add(1) })
					a := &adapter{
						provider:     provider.provider,
						clientID:     "fake-client",
						clientSecret: "fake-secret",
						redirectURL:  server.URL + "/callback",
						tokenURL:     server.URL + "/token",
						userInfoURL:  server.URL + "/profile",
						authStyle:    provider.authStyle,
						usePKCE:      provider.pkce,
						useNonce:     provider.nonce,
						mode:         subjectOIDC,
						httpClient:   server.Client(),
					}
					verifier := ""
					if provider.pkce {
						verifier = strings.Repeat("p", 43)
					}
					nonceHash := [32]byte{}
					if provider.nonce {
						nonceHash = sha256.Sum256([]byte("fake-nonce"))
					}
					if _, err := a.ExchangeIdentity(context.Background(), "fake-code", verifier, nonceHash); err != authentication.ErrSocialProviderProof {
						t.Fatalf("token failure error = %v", err)
					}
					if tokenCalls.Load() != 1 || profileCalls.Load() != 0 {
						t.Fatalf("requests token=%d profile=%d", tokenCalls.Load(), profileCalls.Load())
					}
				})
			}
		})
	}
}

func TestTikTokTokenResponseRequiresAccessTokenAndOpenID(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "missing access token", body: `{"open_id":"stable-open-id","token_type":"Bearer"}`},
		{name: "missing open id", body: `{"access_token":"fake-access","token_type":"Bearer"}`},
		{name: "malformed body", body: "{not-valid-tiktok-token-response"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			a := &adapter{provider: authentication.ProviderTikTok, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, mode: subjectTikTokOpenID, tikTok: true, httpClient: server.Client()}
			if _, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{}); err != authentication.ErrSocialProviderProof {
				t.Fatalf("TikTok token failure error = %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("TikTok token request retried: %d", calls.Load())
			}
		})
	}
}
