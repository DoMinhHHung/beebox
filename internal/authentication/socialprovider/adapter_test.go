package socialprovider

import (
	"net/url"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/authentication"
)

func TestAuthorizationURLProviderMatrix(t *testing.T) {
	t.Parallel()
	const redirect = "https://beebox.example.test/v1/social-auth/callback/provider"
	const state = "fake-state"
	const nonce = "fake-nonce"
	const challenge = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	tests := []struct {
		provider authentication.Provider
		tenant   string
		host     string
		path     string
		scopes   []string
		pkce     bool
		nonce    bool
	}{
		{authentication.ProviderGoogle, "", "accounts.google.com", "/o/oauth2/v2/auth", []string{"openid", "profile"}, true, true},
		{authentication.ProviderApple, "", "appleid.apple.com", "/auth/authorize", nil, false, true},
		{authentication.ProviderMicrosoft, "11111111-1111-4111-8111-111111111111", "login.microsoftonline.com", "/11111111-1111-4111-8111-111111111111/oauth2/v2.0/authorize", []string{"openid"}, true, true},
		{authentication.ProviderGitHub, "", "github.com", "/login/oauth/authorize", nil, true, false},
		{authentication.ProviderGitLab, "", "gitlab.com", "/oauth/authorize", []string{"read_user"}, true, false},
		{authentication.ProviderFacebook, "", "www.facebook.com", "/dialog/oauth", nil, false, false},
		{authentication.ProviderDiscord, "", "discord.com", "/oauth2/authorize", []string{"identify"}, false, false},
		{authentication.ProviderLinkedIn, "", "www.linkedin.com", "/oauth/v2/authorization", []string{"openid"}, false, true},
		{authentication.ProviderX, "", "x.com", "/i/oauth2/authorize", []string{"tweet.read", "users.read"}, true, false},
		{authentication.ProviderTikTok, "", "www.tiktok.com", "/v2/auth/authorize/", []string{"user.info.basic"}, false, false},
	}

	if len(tests) != len(authentication.Providers) {
		t.Fatalf("matrix providers = %d, vocabulary = %d", len(tests), len(authentication.Providers))
	}
	for _, tt := range tests {
		t := tt
		t.Run(string(tt.provider), func(t *testing.T) {
			t.Parallel()
			adapter, err := newAdapter(adapterConfig{
				provider:        tt.provider,
				clientID:        "fake-client-id",
				clientSecret:    "fake-client-secret",
				microsoftTenant: tt.tenant,
				redirectURL:     redirect,
			})
			if err != nil {
				t.Fatal(err)
			}
			if adapter.UsesPKCE() != tt.pkce || adapter.UsesNonce() != tt.nonce {
				t.Fatalf("security flags pkce=%v nonce=%v", adapter.UsesPKCE(), adapter.UsesNonce())
			}
			raw, err := adapter.AuthorizationURL(state, nonce, challenge)
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if u.Scheme != "https" || u.Host != tt.host || u.Path != tt.path {
				t.Fatalf("authorization endpoint = %s://%s%s", u.Scheme, u.Host, u.Path)
			}
			q := u.Query()
			if q.Get("state") != state || q.Get("redirect_uri") != redirect || q.Get("response_type") != "code" {
				t.Fatalf("missing common auth binding: %s", u.RawQuery)
			}
			clientID := q.Get("client_id")
			if tt.provider == authentication.ProviderTikTok {
				clientID = q.Get("client_key")
			}
			if clientID != "fake-client-id" {
				t.Fatalf("client id missing: %s", u.RawQuery)
			}
			if tt.pkce {
				if q.Get("code_challenge") != challenge || q.Get("code_challenge_method") != "S256" {
					t.Fatalf("PKCE missing: %s", u.RawQuery)
				}
			} else if q.Get("code_challenge") != "" || q.Get("code_challenge_method") != "" {
				t.Fatalf("unexpected PKCE: %s", u.RawQuery)
			}
			if tt.nonce {
				if q.Get("nonce") != nonce {
					t.Fatalf("nonce missing: %s", u.RawQuery)
				}
			} else if q.Get("nonce") != "" {
				t.Fatalf("unexpected nonce: %s", u.RawQuery)
			}
			actualScopes := strings.Fields(q.Get("scope"))
			if tt.provider == authentication.ProviderTikTok {
				actualScopes = strings.Split(q.Get("scope"), ",")
			}
			if strings.Contains(strings.ToLower(q.Get("scope")), "email") {
				t.Fatalf("provider email scope requested: %q", q.Get("scope"))
			}
			if strings.Join(actualScopes, " ") != strings.Join(tt.scopes, " ") {
				t.Fatalf("scopes = %v, want %v", actualScopes, tt.scopes)
			}
		})
	}
}

func TestProviderSpecsUseFixedHTTPSBackchannels(t *testing.T) {
	t.Parallel()
	for _, provider := range authentication.Providers {
		tenant := ""
		if provider == authentication.ProviderMicrosoft {
			tenant = "11111111-1111-4111-8111-111111111111"
		}
		spec, err := specFor(provider, tenant)
		if err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		for name, raw := range map[string]string{"authorization": spec.authURL, "token": spec.tokenURL} {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				t.Fatalf("%s %s endpoint = %q", provider, name, raw)
			}
		}
		if spec.userInfoURL != "" {
			u, err := url.Parse(spec.userInfoURL)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				t.Fatalf("%s userinfo endpoint = %q", provider, spec.userInfoURL)
			}
		}
		if spec.mode == subjectOIDC {
			for name, raw := range map[string]string{"issuer": spec.issuer, "jwks": spec.jwksURL} {
				u, err := url.Parse(raw)
				if err != nil || u.Scheme != "https" || u.Host == "" {
					t.Fatalf("%s %s endpoint = %q", provider, name, raw)
				}
			}
		}
	}
}
