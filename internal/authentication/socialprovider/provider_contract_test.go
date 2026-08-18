package socialprovider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type verifiedProductionContract struct {
	provider authentication.Provider
	tenant   string
	authURL  string
	tokenURL string
	userinfo string
	scopes   []string
	auth     oauth2.AuthStyle
	pkce     bool
	nonce    bool
	mode     subjectMode
	issuer   string
	jwks     string
}

func TestVerifiedProductionProviderContracts(t *testing.T) {
	t.Parallel()
	contracts := []verifiedProductionContract{
		{authentication.ProviderGoogle, "", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "", []string{"openid", "profile"}, oauth2.AuthStyleInParams, true, true, subjectOIDC, "https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs"},
		{authentication.ProviderApple, "", "https://appleid.apple.com/auth/authorize", "https://appleid.apple.com/auth/token", "", nil, oauth2.AuthStyleInParams, false, true, subjectOIDC, "https://appleid.apple.com", "https://appleid.apple.com/auth/keys"},
		{authentication.ProviderMicrosoft, "11111111-1111-4111-8111-111111111111", "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/oauth2/v2.0/authorize", "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/oauth2/v2.0/token", "", []string{"openid"}, oauth2.AuthStyleInParams, true, true, subjectOIDC, "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0", "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/discovery/v2.0/keys"},
		{authentication.ProviderGitHub, "", "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", "https://api.github.com/user", nil, oauth2.AuthStyleInParams, true, false, subjectTopLevelNumericID, "", ""},
		{authentication.ProviderGitLab, "", "https://gitlab.com/oauth/authorize", "https://gitlab.com/oauth/token", "https://gitlab.com/api/v4/user", []string{"read_user"}, oauth2.AuthStyleInParams, true, false, subjectTopLevelNumericID, "", ""},
		{authentication.ProviderDiscord, "", "https://discord.com/oauth2/authorize", "https://discord.com/api/v10/oauth2/token", "https://discord.com/api/v10/users/@me", []string{"identify"}, oauth2.AuthStyleInParams, false, false, subjectTopLevelStringID, "", ""},
		{authentication.ProviderLinkedIn, "", "https://www.linkedin.com/oauth/v2/authorization", "https://www.linkedin.com/oauth/v2/accessToken", "", []string{"openid"}, oauth2.AuthStyleInParams, false, true, subjectOIDC, "https://www.linkedin.com", "https://www.linkedin.com/oauth/openid/jwks"},
		{authentication.ProviderX, "", "https://x.com/i/oauth2/authorize", "https://api.x.com/2/oauth2/token", "https://api.x.com/2/users/me", []string{"tweet.read", "users.read"}, oauth2.AuthStyleInHeader, true, false, subjectNestedStringID, "", ""},
		{authentication.ProviderTikTok, "", "https://www.tiktok.com/v2/auth/authorize/", "https://open.tiktokapis.com/v2/oauth/token/", "", []string{"user.info.basic"}, oauth2.AuthStyle(0), false, false, subjectTikTokOpenID, "", ""},
	}
	for _, contract := range contracts {
		contract := contract
		t.Run(string(contract.provider), func(t *testing.T) {
			t.Parallel()
			spec, err := specFor(contract.provider, contract.tenant)
			if err != nil {
				t.Fatal(err)
			}
			if spec.authURL != contract.authURL || spec.tokenURL != contract.tokenURL || spec.userInfoURL != contract.userinfo || spec.authStyle != contract.auth || spec.usePKCE != contract.pkce || spec.useNonce != contract.nonce || spec.mode != contract.mode || spec.issuer != contract.issuer || spec.jwksURL != contract.jwks || !reflect.DeepEqual(spec.scopes, contract.scopes) {
				t.Fatalf("production contract drift for %s: %#v", contract.provider, spec)
			}
		})
	}
}

func TestGoogleAuthorizationUsesOpenIDProfileWithoutEmail(t *testing.T) {
	t.Parallel()
	a, err := newAdapter(adapterConfig{provider: authentication.ProviderGoogle, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: "https://beebox.example.test/v1/social-auth/callback/google"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := a.AuthorizationURL("fake-state", "fake-nonce", strings.Repeat("a", 43))
	if err != nil {
		t.Fatal(err)
	}
	q := mustURL(t, raw).Query()
	if got := strings.Fields(q.Get("scope")); !reflect.DeepEqual(got, []string{"openid", "profile"}) {
		t.Fatalf("Google scopes = %v", got)
	}
	if strings.Contains(q.Get("scope"), "email") {
		t.Fatal("Google authorization requested email scope")
	}
}

func TestXAuthorizationUsesExactMinimalUserScopes(t *testing.T) {
	t.Parallel()
	a, err := newAdapter(adapterConfig{provider: authentication.ProviderX, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: "https://beebox.example.test/v1/social-auth/callback/x"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := a.AuthorizationURL("fake-state", "", strings.Repeat("a", 43))
	if err != nil {
		t.Fatal(err)
	}
	scopes := strings.Fields(mustURL(t, raw).Query().Get("scope"))
	if !reflect.DeepEqual(scopes, []string{"tweet.read", "users.read"}) {
		t.Fatalf("X scopes = %v", scopes)
	}
	for _, forbidden := range []string{"users.email", "offline.access", "tweet.write"} {
		if contains(scopes, forbidden) {
			t.Fatalf("X requested forbidden scope %q", forbidden)
		}
	}
}

func TestPureOAuthProviderWireContracts(t *testing.T) {
	t.Parallel()
	tests := []struct {
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
	}{
		{"github", authentication.ProviderGitHub, subjectTopLevelNumericID, oauth2.AuthStyleInParams, true, "application/x-www-form-urlencoded", "access_token=fake-github-token&scope=&token_type=bearer", "/user", `{"id":12345,"login":"ignored-login","email":"ignored@example.test"}`, "12345"},
		{"gitlab", authentication.ProviderGitLab, subjectTopLevelNumericID, oauth2.AuthStyleInParams, true, "application/json", `{"access_token":"fake-gitlab-token","token_type":"bearer","expires_in":7200,"refresh_token":"fake-refresh-discarded","created_at":1607635748}`, "/api/v4/user", `{"id":23456,"username":"ignored-user","email":"ignored@example.test","name":"Ignored","avatar_url":"https://ignored.example.test/a"}`, "23456"},
		{"discord", authentication.ProviderDiscord, subjectTopLevelStringID, oauth2.AuthStyleInParams, false, "application/json", `{"access_token":"fake-discord-token","token_type":"Bearer","expires_in":604800,"refresh_token":"fake-refresh-discarded","scope":"identify"}`, "/api/v10/users/@me", `{"id":"45678","username":"ignored-user","global_name":"Ignored","avatar":"ignored","email":"ignored@example.test"}`, "45678"},
		{"x", authentication.ProviderX, subjectNestedStringID, oauth2.AuthStyleInHeader, true, "application/json", `{"token_type":"bearer","expires_in":7200,"access_token":"fake-x-token","scope":"tweet.read users.read"}`, "/2/users/me", `{"data":{"id":"56789","name":"Ignored","username":"ignored-user"}}`, "56789"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var tokenCalls, profileCalls atomic.Int32
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenCalls.Add(1)
				assertTokenRequest(t, r, server.URL+"/callback", tt.authStyle, tt.pkce)
				if tt.name == "github" && r.Header.Get("Accept") != "" {
					t.Fatalf("GitHub token Accept = %q; default documented response should be form-urlencoded", r.Header.Get("Accept"))
				}
				w.Header().Set("Content-Type", tt.tokenType)
				_, _ = w.Write([]byte(tt.tokenBody))
			})
			mux.HandleFunc(tt.profilePath, func(w http.ResponseWriter, r *http.Request) {
				profileCalls.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != tt.profilePath {
					t.Fatalf("profile request = %s %s", r.Method, r.URL.String())
				}
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer fake-") {
					t.Fatalf("profile Authorization = %q", r.Header.Get("Authorization"))
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.profileBody))
			})
			a := &adapter{provider: tt.provider, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL + "/token", userInfoURL: server.URL + tt.profilePath, authStyle: tt.authStyle, usePKCE: tt.pkce, mode: tt.mode, httpClient: server.Client()}
			verifier := ""
			if tt.pkce {
				verifier = strings.Repeat("p", 43)
			}
			proof, err := a.ExchangeIdentity(context.Background(), "fake-code", verifier, [32]byte{})
			if err != nil {
				t.Fatal(err)
			}
			if proof.Provider != tt.provider || proof.Subject != tt.subject {
				t.Fatalf("proof = %#v", proof)
			}
			if tokenCalls.Load() != 1 || profileCalls.Load() != 1 {
				t.Fatalf("requests token=%d profile=%d", tokenCalls.Load(), profileCalls.Load())
			}
		})
	}
}

func TestPureOAuthProviderSubjectTypesAreProviderSpecific(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		provider authentication.Provider
		mode     subjectMode
		body     string
	}{
		{"github-string-id", authentication.ProviderGitHub, subjectTopLevelNumericID, `{"id":"12345","email":"fallback@example.test"}`},
		{"gitlab-string-id", authentication.ProviderGitLab, subjectTopLevelNumericID, `{"id":"23456","username":"fallback"}`},
		{"discord-numeric-id", authentication.ProviderDiscord, subjectTopLevelStringID, `{"id":45678,"username":"fallback"}`},
		{"x-numeric-id", authentication.ProviderX, subjectNestedStringID, `{"data":{"id":56789,"username":"fallback"}}`},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			a := &adapter{provider: tt.provider, userInfoURL: server.URL, mode: tt.mode, httpClient: server.Client()}
			if _, err := a.subjectFromUserInfo(context.Background(), "fake-token"); err == nil {
				t.Fatal("accepted provider subject with wrong documented JSON type")
			}
		})
	}
}

func TestPureOAuthMissingSubjectCannotFallBackToProfileClaims(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		provider authentication.Provider
		mode     subjectMode
		body     string
	}{
		{authentication.ProviderGitHub, subjectTopLevelNumericID, `{"login":"fallback","email":"fallback@example.test"}`},
		{authentication.ProviderGitLab, subjectTopLevelNumericID, `{"username":"fallback","email":"fallback@example.test"}`},
		{authentication.ProviderDiscord, subjectTopLevelStringID, `{"username":"fallback","global_name":"Fallback","email":"fallback@example.test"}`},
		{authentication.ProviderX, subjectNestedStringID, `{"data":{"username":"fallback","name":"Fallback"}}`},
	} {
		tt := tt
		t.Run(string(tt.provider), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			a := &adapter{provider: tt.provider, userInfoURL: server.URL, mode: tt.mode, httpClient: server.Client()}
			if _, err := a.subjectFromUserInfo(context.Background(), "fake-token"); err == nil {
				t.Fatal("profile claims substituted for stable subject")
			}
		})
	}
}

func TestPureOAuthProviderErrorsAreSafeAndDoNotFetchProfile(t *testing.T) {
	t.Parallel()
	tests := []struct {
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
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var tokenCalls, profileCalls atomic.Int32
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenCalls.Add(1)
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(tt.body))
			})
			mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) { profileCalls.Add(1) })
			a := &adapter{provider: tt.provider, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL + "/token", userInfoURL: server.URL + "/profile", authStyle: tt.authStyle, usePKCE: tt.pkce, mode: subjectTopLevelStringID, httpClient: server.Client()}
			verifier := ""
			if tt.pkce {
				verifier = strings.Repeat("p", 43)
			}
			_, err := a.ExchangeIdentity(context.Background(), "fake-code", verifier, [32]byte{})
			if err == nil || err != authentication.ErrSocialProviderProof || strings.Contains(err.Error(), "vendor-secret-description") || strings.Contains(err.Error(), "fake-secret") || strings.Contains(err.Error(), "fake-code") {
				t.Fatalf("unsafe provider error = %v", err)
			}
			if tokenCalls.Load() != 1 || profileCalls.Load() != 0 {
				t.Fatalf("requests token=%d profile=%d", tokenCalls.Load(), profileCalls.Load())
			}
		})
	}
}

func TestOIDCProviderWireContracts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		provider  authentication.Provider
		pkce      bool
		tokenBody func(string) string
	}{
		{"google", authentication.ProviderGoogle, true, func(idToken string) string {
			return `{"access_token":"fake-google-access","expires_in":3599,"scope":"openid profile","token_type":"Bearer","id_token":"` + idToken + `"}`
		}},
		{"apple", authentication.ProviderApple, false, func(idToken string) string {
			return `{"access_token":"fake-apple-access","token_type":"Bearer","expires_in":3600,"refresh_token":"fake-apple-refresh-discarded","id_token":"` + idToken + `"}`
		}},
		{"microsoft", authentication.ProviderMicrosoft, true, func(idToken string) string {
			return `{"token_type":"Bearer","scope":"openid","expires_in":3599,"access_token":"fake-ms-access","id_token":"` + idToken + `"}`
		}},
		{"linkedin", authentication.ProviderLinkedIn, false, func(idToken string) string {
			return `{"access_token":"fake-linkedin-access","expires_in":5183999,"scope":"openid","token_type":"Bearer","id_token":"` + idToken + `"}`
		}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			var tokenCalls, jwksCalls atomic.Int32
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			clientID := "fake-client"
			nonce := "fake-nonce"
			nonceHash := sha256.Sum256([]byte(nonce))
			mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
				jwksCalls.Add(1)
				writeJWKS(w, "key-a", &key.PublicKey)
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenCalls.Add(1)
				assertTokenRequest(t, r, server.URL+"/callback", oauth2.AuthStyleInParams, tt.pkce)
				claims := map[string]any{"iss": server.URL, "aud": clientID, "sub": "stable-" + tt.name + "-subject", "nonce": nonce, "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "email": "ignored@example.test", "name": "Ignored", "picture": "https://ignored.example.test/avatar"}
				raw, signErr := signContractJWT(key, "key-a", claims)
				if signErr != nil {
					t.Fatal(signErr)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.tokenBody(raw)))
			})
			client := server.Client()
			a := &adapter{provider: tt.provider, clientID: clientID, clientSecret: "fake-client-secret-jwt", redirectURL: server.URL + "/callback", tokenURL: server.URL + "/token", authStyle: oauth2.AuthStyleInParams, usePKCE: tt.pkce, useNonce: true, mode: subjectOIDC, verifier: oidc.NewVerifier(server.URL, oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL+"/jwks"), &oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256"}}), httpClient: client}
			verifier := ""
			if tt.pkce {
				verifier = strings.Repeat("p", 43)
			}
			proof, err := a.ExchangeIdentity(context.Background(), "fake-code", verifier, nonceHash)
			if err != nil {
				t.Fatal(err)
			}
			if proof.Subject != "stable-"+tt.name+"-subject" || proof.Provider != tt.provider {
				t.Fatalf("proof = %#v", proof)
			}
			if tokenCalls.Load() != 1 || jwksCalls.Load() < 1 {
				t.Fatalf("requests token=%d jwks=%d", tokenCalls.Load(), jwksCalls.Load())
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
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { writeJWKS(w, "key-a", &key.PublicKey) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]any{"iss": server.URL + "/tenant-b/v2.0", "aud": clientID, "sub": "stable-ms-subject", "nonce": nonce, "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
		raw, _ := signContractJWT(key, "key-a", claims)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fake-ms-access","token_type":"Bearer","id_token":"` + raw + `"}`))
	})
	client := server.Client()
	a := &adapter{provider: authentication.ProviderMicrosoft, clientID: clientID, clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL + "/token", authStyle: oauth2.AuthStyleInParams, useNonce: true, mode: subjectOIDC, verifier: oidc.NewVerifier(server.URL+"/tenant-a/v2.0", oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL+"/jwks"), &oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256"}}), httpClient: client}
	if _, err := a.ExchangeIdentity(context.Background(), "fake-code", "", nonceHash); err == nil {
		t.Fatal("Microsoft tenant A verifier accepted tenant B issuer")
	}
}

func TestOIDCJWKSRotationAndMissesAreBounded(t *testing.T) {
	t.Parallel()
	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)
	var current atomic.Pointer[rsa.PublicKey]
	var kid atomic.Value
	current.Store(&keyA.PublicKey)
	kid.Store("key-a")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJWKS(w, kid.Load().(string), current.Load())
	}))
	defer server.Close()
	client := server.Client()
	verifier := oidc.NewVerifier("https://issuer.example.test", oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), server.URL), &oidc.Config{ClientID: "fake-client", SupportedSigningAlgs: []string{"RS256"}})
	verify := func(key *rsa.PrivateKey, tokenKid string) error {
		raw, err := signContractJWT(key, tokenKid, map[string]any{"iss": "https://issuer.example.test", "aud": "fake-client", "sub": "subject", "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()})
		if err != nil {
			return err
		}
		_, err = verifier.Verify(oidc.ClientContext(context.Background(), client), raw)
		return err
	}
	if err := verify(keyA, "key-a"); err != nil {
		t.Fatal(err)
	}
	current.Store(&keyB.PublicKey)
	kid.Store("key-b")
	if err := verify(keyB, "key-b"); err != nil {
		t.Fatalf("rotated key was not accepted: %v", err)
	}
	before := calls.Load()
	for i := 0; i < 3; i++ {
		unknown, _ := rsa.GenerateKey(rand.Reader, 2048)
		if err := verify(unknown, "unknown-kid"); err == nil {
			t.Fatal("unknown JWKS kid accepted")
		}
	}
	if delta := calls.Load() - before; delta > 3 {
		t.Fatalf("unknown kid caused unbounded JWKS requests: %d", delta)
	}
}

func TestTikTokTokenContract(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Accept") != "application/json" {
			t.Fatalf("TikTok token request headers method=%s content-type=%q accept=%q", r.Method, r.Header.Get("Content-Type"), r.Header.Get("Accept"))
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		want := url.Values{"client_key": {"fake-client"}, "client_secret": {"fake-secret"}, "code": {"fake-code"}, "grant_type": {"authorization_code"}, "redirect_uri": {server.URL + "/callback"}}
		if !reflect.DeepEqual(r.Form, want) {
			t.Fatalf("TikTok token form = %v, want %v", r.Form, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fake-tiktok-access","expires_in":86400,"open_id":"fake-open-id","refresh_expires_in":31536000,"refresh_token":"fake-refresh-discarded","scope":"user.info.basic","token_type":"Bearer"}`))
	}))
	defer server.Close()
	a := &adapter{provider: authentication.ProviderTikTok, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, mode: subjectTikTokOpenID, tikTok: true, httpClient: server.Client()}
	proof, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if proof.Subject != "fake-open-id" || proof.Provider != authentication.ProviderTikTok || calls.Load() != 1 {
		t.Fatalf("TikTok proof=%#v calls=%d", proof, calls.Load())
	}
}

func TestTikTokDocumentedErrorIsSafe(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"vendor-secret-description","log_id":"fake-log-id"}`))
	}))
	defer server.Close()
	a := &adapter{provider: authentication.ProviderTikTok, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, mode: subjectTikTokOpenID, tikTok: true, httpClient: server.Client()}
	_, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{})
	if err == nil || err != authentication.ErrSocialProviderProof || strings.Contains(err.Error(), "vendor-secret-description") || strings.Contains(err.Error(), "fake-secret") || strings.Contains(err.Error(), "fake-code") {
		t.Fatalf("unsafe TikTok error = %v", err)
	}
}

func TestFacebookGraphSubjectFixtureUsesOnlyID(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("fields") != "id" {
			t.Fatalf("Facebook fields = %q", r.URL.Query().Get("fields"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"34567","name":"Ignored","email":"ignored@example.test"}`))
	}))
	defer server.Close()
	a := &adapter{provider: authentication.ProviderFacebook, userInfoURL: server.URL + "?fields=id", mode: subjectTopLevelStringID, httpClient: server.Client()}
	subject, err := a.subjectFromUserInfo(context.Background(), "fake-facebook-token")
	if err != nil || subject != "34567" {
		t.Fatalf("Facebook subject=%q err=%v", subject, err)
	}
}

func assertTokenRequest(t *testing.T, r *http.Request, redirect string, authStyle oauth2.AuthStyle, pkce bool) {
	t.Helper()
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("token request method=%s content-type=%q", r.Method, r.Header.Get("Content-Type"))
	}
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "fake-code" || r.Form.Get("redirect_uri") != redirect {
		t.Fatalf("token form = %v", r.Form)
	}
	if pkce {
		if r.Form.Get("code_verifier") != strings.Repeat("p", 43) {
			t.Fatalf("code_verifier = %q", r.Form.Get("code_verifier"))
		}
	} else if r.Form.Get("code_verifier") != "" {
		t.Fatalf("unexpected code_verifier = %q", r.Form.Get("code_verifier"))
	}
	switch authStyle {
	case oauth2.AuthStyleInParams:
		if r.Form.Get("client_id") != "fake-client" || r.Form.Get("client_secret") == "" || r.Header.Get("Authorization") != "" {
			t.Fatalf("parameter client auth form=%v header=%q", r.Form, r.Header.Get("Authorization"))
		}
	case oauth2.AuthStyleInHeader:
		user, pass, ok := r.BasicAuth()
		if !ok || user != "fake-client" || pass != "fake-secret" || r.Form.Get("client_id") != "" || r.Form.Get("client_secret") != "" {
			t.Fatalf("Basic client auth user=%q ok=%v form=%v", user, ok, r.Form)
		}
	}
}

func signContractJWT(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func writeJWKS(w http.ResponseWriter, kid string, key *rsa.PublicKey) {
	w.Header().Set("Content-Type", "application/json")
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n, "e": e}}})
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
