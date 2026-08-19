package socialprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

func TestSlackAuthorizationContract(t *testing.T) {
	t.Parallel()
	const redirectURL = "https://auth.example.test/v1/social-auth/callback/slack"
	a, err := newAdapter(adapterConfig{
		provider:     authentication.ProviderSlack,
		clientID:     "fake-client",
		clientSecret: "fake-secret",
		redirectURL:  redirectURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.UsesPKCE() || !a.UsesNonce() {
		t.Fatalf("Slack PKCE=%v nonce=%v", a.UsesPKCE(), a.UsesNonce())
	}
	raw, err := a.AuthorizationURL("fake-state", "fake-nonce", "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "slack.com" || u.Path != "/openid/connect/authorize" {
		t.Fatalf("Slack authorization endpoint = %s", u.String())
	}
	q := u.Query()
	want := map[string]string{
		"client_id":     "fake-client",
		"redirect_uri":  redirectURL,
		"response_mode": "query",
		"response_type": "code",
		"scope":         "openid",
		"state":         "fake-state",
		"nonce":         "fake-nonce",
	}
	if len(q) != len(want) {
		t.Fatalf("Slack authorization query = %v", q)
	}
	for key, value := range want {
		if got := q.Get(key); got != value {
			t.Fatalf("Slack authorization %s = %q, want %q", key, got, value)
		}
	}
	for _, forbidden := range []string{"email", "profile", "identity.basic", "identity.email", "identity.team", "identity.avatar"} {
		if strings.Contains(q.Get("scope"), forbidden) {
			t.Fatalf("Slack authorization requested forbidden scope %q", forbidden)
		}
	}
	for _, forbidden := range []string{"team", "code_challenge", "code_challenge_method"} {
		if q.Get(forbidden) != "" {
			t.Fatalf("Slack authorization sent forbidden parameter %q", forbidden)
		}
	}
}

func TestSlackOIDCExchangeUsesBasicAuthAndIDTokenSubjectOnly(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var tokenCalls, jwksCalls, userInfoCalls atomic.Int32
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	const clientID = "fake-client"
	const nonce = "fake-nonce"
	nonceHash := sha256.Sum256([]byte(nonce))
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwksCalls.Add(1)
		writeContractJWKS(w, "key-a", &key.PublicKey)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		assertContractTokenRequest(t, r, server.URL+"/callback", oauth2.AuthStyleInHeader, false)
		claims := map[string]any{
			"iss":            server.URL,
			"aud":            clientID,
			"sub":            "stable-slack-subject",
			"nonce":          nonce,
			"iat":            time.Now().Add(-time.Minute).Unix(),
			"exp":            time.Now().Add(5 * time.Minute).Unix(),
			"email":          "ignored@example.test",
			"email_verified": true,
			"name":           "Ignored",
			"team_id":        "T-ignored",
			"user_id":        "U-ignored",
			"profile":        map[string]any{"image_48": "https://ignored.example.test/avatar"},
		}
		raw, signErr := signContractJWT(key, "key-a", claims)
		if signErr != nil {
			t.Fatal(signErr)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"access_token":"fake-slack-access","token_type":"Bearer","id_token":"` + raw + `"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		userInfoCalls.Add(1)
		http.Error(w, "userinfo must not be called", http.StatusInternalServerError)
	})

	client := server.Client()
	a := &adapter{
		provider:     authentication.ProviderSlack,
		clientID:     clientID,
		clientSecret: "fake-secret",
		redirectURL:  server.URL + "/callback",
		tokenURL:     server.URL + "/token",
		userInfoURL:  server.URL + "/userinfo",
		authStyle:    oauth2.AuthStyleInHeader,
		useNonce:     true,
		mode:         subjectOIDC,
		verifier: oidc.NewVerifier(server.URL, oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL+"/jwks"), &oidc.Config{
			ClientID:             clientID,
			SupportedSigningAlgs: []string{"RS256"},
		}),
		httpClient: client,
	}
	proof, err := a.ExchangeIdentity(context.Background(), "fake-code", "", nonceHash)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Provider != authentication.ProviderSlack || proof.Subject != "stable-slack-subject" {
		t.Fatalf("Slack proof = %#v", proof)
	}
	if tokenCalls.Load() != 1 || jwksCalls.Load() < 1 || userInfoCalls.Load() != 0 {
		t.Fatalf("Slack calls token=%d jwks=%d userinfo=%d", tokenCalls.Load(), jwksCalls.Load(), userInfoCalls.Load())
	}
}

func TestSlackTokenFailuresAreSafeAndDoNotRetryOrFetchUserInfo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "Slack error", body: `{"ok":false,"error":"invalid_code"}`},
		{name: "missing access token", body: `{"ok":true,"token_type":"Bearer","id_token":"ignored"}`},
		{name: "malformed response", body: `{not-json`},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var tokenCalls, userInfoCalls atomic.Int32
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenCalls.Add(1)
				assertContractTokenRequest(t, r, server.URL+"/callback", oauth2.AuthStyleInHeader, false)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
				userInfoCalls.Add(1)
			})
			a := &adapter{
				provider:     authentication.ProviderSlack,
				clientID:     "fake-client",
				clientSecret: "fake-secret",
				redirectURL:  server.URL + "/callback",
				tokenURL:     server.URL + "/token",
				userInfoURL:  server.URL + "/userinfo",
				authStyle:    oauth2.AuthStyleInHeader,
				useNonce:     true,
				mode:         subjectOIDC,
				httpClient:   server.Client(),
			}
			_, err := a.ExchangeIdentity(context.Background(), "fake-code", "", sha256.Sum256([]byte("fake-nonce")))
			if err != authentication.ErrSocialProviderProof {
				t.Fatalf("Slack error = %v", err)
			}
			if strings.Contains(err.Error(), "invalid_code") || strings.Contains(err.Error(), "fake-secret") || strings.Contains(err.Error(), "fake-code") {
				t.Fatalf("Slack provider detail leaked: %v", err)
			}
			if tokenCalls.Load() != 1 || userInfoCalls.Load() != 0 {
				t.Fatalf("Slack failure calls token=%d userinfo=%d", tokenCalls.Load(), userInfoCalls.Load())
			}
		})
	}
}
