package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCustomOIDCDiscoveryAndUserinfo(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"userinfo_endpoint":      srv.URL + "/userinfo",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("code") != "good" || r.FormValue("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "tok",
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":            "user-1",
			"email":          "a@example.com",
			"email_verified": true,
			"name":           "Ann",
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	p := specProvider{slug: SlugOIDC, http: srv.Client()}
	auth, state, err := p.AuthURL(AuthRequest{
		ClientID:    "cid",
		RedirectURI: "https://app.example/cb",
		State:       "st",
		Verifier:    "verifier-value-32-bytes-minimum-ok",
		Extra:       map[string]string{"issuer": srv.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	if state != "st" || auth == "" {
		t.Fatalf("auth=%q state=%q", auth, state)
	}
	prof, err := p.Exchange(context.Background(), "good", "verifier-value-32-bytes-minimum-ok", "https://app.example/cb", Credentials{
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURI:  "https://app.example/cb",
		Extra:        map[string]string{"issuer": srv.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	if prof.Subject != "user-1" || prof.Email != "a@example.com" || !prof.EmailVerified {
		t.Fatalf("%+v", prof)
	}
}

func TestAuthURLHosts(t *testing.T) {
	cases := []struct {
		slug  string
		host  string
		extra map[string]string
	}{
		{SlugGoogle, "accounts.google.com/o/oauth2/v2/auth", nil},
		{SlugMicrosoft, "login.microsoftonline.com/common/oauth2/v2.0/authorize", nil},
		{SlugApple, "appleid.apple.com/auth/authorize", nil},
		{SlugGitHub, "github.com/login/oauth/authorize", nil},
		{SlugX, "x.com/i/oauth2/authorize", nil},
		{SlugLinkedIn, "linkedin.com/oauth/v2/authorization", nil},
		{SlugSlack, "slack.com/openid/connect/authorize", nil},
		{SlugTwitch, "id.twitch.tv/oauth2/authorize", nil},
		{SlugGitLab, "gitlab.com/oauth/authorize", nil},
		{SlugFacebook, "facebook.com/v21.0/dialog/oauth", nil},
	}
	for _, tc := range cases {
		t.Run(tc.slug, func(t *testing.T) {
			p := specProvider{slug: tc.slug}
			raw, _, err := p.AuthURL(AuthRequest{
				ClientID:    "cid",
				RedirectURI: "https://app.example/cb",
				State:       "st",
				Verifier:    "ver",
				Extra:       tc.extra,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(raw, tc.host) || !strings.Contains(raw, "code_challenge_method=S256") {
				t.Fatalf("url=%s want host %s", raw, tc.host)
			}
			if tc.slug == SlugApple && !strings.Contains(raw, "response_mode=form_post") {
				t.Fatalf("apple missing form_post: %s", raw)
			}
		})
	}
}
