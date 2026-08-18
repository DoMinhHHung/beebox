package socialprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"golang.org/x/oauth2"
)

type pureOAuthContract struct {
	name        string
	provider    authentication.Provider
	mode        subjectMode
	authStyle   oauth2.AuthStyle
	pkce        bool
	tokenType   string
	tokenBody   string
	profilePath string
	profileBody string
	subject     string
}

func TestPureOAuthProviderWireContracts(t *testing.T) {
	t.Parallel()
	contracts := []pureOAuthContract{
		{"github", authentication.ProviderGitHub, subjectTopLevelNumericID, oauth2.AuthStyleInParams, true, "application/x-www-form-urlencoded", "access_token=fake-github-token&scope=&token_type=bearer", "/user", `{"id":12345,"login":"ignored-login","email":"ignored@example.test"}`, "12345"},
		{"gitlab", authentication.ProviderGitLab, subjectTopLevelNumericID, oauth2.AuthStyleInParams, true, "application/json", `{"access_token":"fake-gitlab-token","token_type":"bearer","expires_in":7200,"refresh_token":"fake-refresh-discarded","created_at":1607635748}`, "/api/v4/user", `{"id":23456,"username":"ignored-user","email":"ignored@example.test","name":"Ignored","avatar_url":"https://ignored.example.test/a"}`, "23456"},
		{"discord", authentication.ProviderDiscord, subjectTopLevelStringID, oauth2.AuthStyleInParams, false, "application/json", `{"access_token":"fake-discord-token","token_type":"Bearer","expires_in":604800,"refresh_token":"fake-refresh-discarded","scope":"identify"}`, "/api/v10/users/@me", `{"id":"45678","username":"ignored-user","global_name":"Ignored","avatar":"ignored","email":"ignored@example.test"}`, "45678"},
		{"x", authentication.ProviderX, subjectNestedStringID, oauth2.AuthStyleInHeader, true, "application/json", `{"token_type":"bearer","expires_in":7200,"access_token":"fake-x-token","scope":"tweet.read users.read"}`, "/2/users/me", `{"data":{"id":"56789","name":"Ignored","username":"ignored-user"}}`, "56789"},
	}
	for _, contract := range contracts {
		contract := contract
		t.Run(contract.name, func(t *testing.T) {
			t.Parallel()
			var tokenCalls, profileCalls atomic.Int32
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenCalls.Add(1)
				assertContractTokenRequest(t, r, server.URL+"/callback", contract.authStyle, contract.pkce)
				if contract.provider == authentication.ProviderGitHub && r.Header.Get("Accept") != "" {
					t.Fatalf("GitHub token Accept = %q; default documented response must remain form-urlencoded", r.Header.Get("Accept"))
				}
				w.Header().Set("Content-Type", contract.tokenType)
				_, _ = w.Write([]byte(contract.tokenBody))
			})
			mux.HandleFunc(contract.profilePath, func(w http.ResponseWriter, r *http.Request) {
				profileCalls.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != contract.profilePath {
					t.Fatalf("profile request = %s %s", r.Method, r.URL.String())
				}
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer fake-") {
					t.Fatalf("profile Authorization = %q", r.Header.Get("Authorization"))
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(contract.profileBody))
			})
			a := &adapter{provider: contract.provider, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL + "/token", userInfoURL: server.URL + contract.profilePath, authStyle: contract.authStyle, usePKCE: contract.pkce, mode: contract.mode, httpClient: server.Client()}
			verifier := ""
			if contract.pkce {
				verifier = strings.Repeat("p", 43)
			}
			proof, err := a.ExchangeIdentity(context.Background(), "fake-code", verifier, [32]byte{})
			if err != nil {
				t.Fatal(err)
			}
			if proof.Provider != contract.provider || proof.Subject != contract.subject {
				t.Fatalf("proof = %#v", proof)
			}
			if tokenCalls.Load() != 1 || profileCalls.Load() != 1 {
				t.Fatalf("requests token=%d profile=%d", tokenCalls.Load(), profileCalls.Load())
			}
		})
	}
}

func TestPureOAuthSubjectTypesAndFallbacks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		provider authentication.Provider
		mode     subjectMode
		body     string
	}{
		{"github-string-id", authentication.ProviderGitHub, subjectTopLevelNumericID, `{"id":"12345","email":"fallback@example.test"}`},
		{"gitlab-string-id", authentication.ProviderGitLab, subjectTopLevelNumericID, `{"id":"23456","username":"fallback"}`},
		{"discord-numeric-id", authentication.ProviderDiscord, subjectTopLevelStringID, `{"id":45678,"username":"fallback"}`},
		{"x-numeric-id", authentication.ProviderX, subjectNestedStringID, `{"data":{"id":56789,"username":"fallback"}}`},
		{"github-missing-id", authentication.ProviderGitHub, subjectTopLevelNumericID, `{"login":"fallback","email":"fallback@example.test"}`},
		{"gitlab-missing-id", authentication.ProviderGitLab, subjectTopLevelNumericID, `{"username":"fallback","email":"fallback@example.test"}`},
		{"discord-missing-id", authentication.ProviderDiscord, subjectTopLevelStringID, `{"username":"fallback","global_name":"Fallback","email":"fallback@example.test"}`},
		{"x-missing-id", authentication.ProviderX, subjectNestedStringID, `{"data":{"username":"fallback","name":"Fallback"}}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			a := &adapter{provider: tc.provider, userInfoURL: server.URL, mode: tc.mode, httpClient: server.Client()}
			if _, err := a.subjectFromUserInfo(context.Background(), "fake-token"); err == nil {
				t.Fatal("provider fallback/wrong-type subject accepted")
			}
		})
	}
}

func TestPureOAuthProviderErrorsAreSafeAndDoNotFetchProfile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		provider    authentication.Provider
		authStyle   oauth2.AuthStyle
		pkce        bool
		contentType string
		body        string
	}{
		{"github", authentication.ProviderGitHub, oauth2.AuthStyleInParams, true, "application/x-www-form-urlencoded", "error=incorrect_client_credentials&error_description=vendor-secret-description"},
		{"gitlab", authentication.ProviderGitLab, oauth2.AuthStyleInParams, true, "application/json", `{"error":"invalid_grant","error_description":"vendor-secret-description"}`},
		{"discord", authentication.ProviderDiscord, oauth2.AuthStyleInParams, false, "application/json", `{"error":"invalid_grant","error_description":"vendor-secret-description"}`},
		{"x", authentication.ProviderX, oauth2.AuthStyleInHeader, true, "application/json", `{"error":"invalid_request","error_description":"vendor-secret-description"}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var tokenCalls, profileCalls atomic.Int32
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenCalls.Add(1)
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(tc.body))
			})
			mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) { profileCalls.Add(1) })
			a := &adapter{provider: tc.provider, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL + "/token", userInfoURL: server.URL + "/profile", authStyle: tc.authStyle, usePKCE: tc.pkce, mode: subjectTopLevelStringID, httpClient: server.Client()}
			verifier := ""
			if tc.pkce {
				verifier = strings.Repeat("p", 43)
			}
			_, err := a.ExchangeIdentity(context.Background(), "fake-code", verifier, [32]byte{})
			if err != authentication.ErrSocialProviderProof || strings.Contains(err.Error(), "vendor-secret-description") || strings.Contains(err.Error(), "fake-secret") || strings.Contains(err.Error(), "fake-code") {
				t.Fatalf("unsafe provider error = %v", err)
			}
			if tokenCalls.Load() != 1 || profileCalls.Load() != 0 {
				t.Fatalf("requests token=%d profile=%d", tokenCalls.Load(), profileCalls.Load())
			}
		})
	}
}
