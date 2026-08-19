//go:build integration

package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	authpostgres "github.com/DoMinhHHung/beebox/internal/authentication/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type socialHTTPE2EProvider struct {
	provider      authentication.Provider
	exchangeCalls int
}

func (p *socialHTTPE2EProvider) Provider() authentication.Provider { return p.provider }

func (*socialHTTPE2EProvider) UsesPKCE() bool { return false }

func (*socialHTTPE2EProvider) UsesNonce() bool { return false }

func (*socialHTTPE2EProvider) AuthorizationURL(state, _, _ string) (string, error) {
	u := &url.URL{Scheme: "https", Host: "provider.example.test", Path: "/authorize"}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (p *socialHTTPE2EProvider) ExchangeIdentity(_ context.Context, code, _ string, _ [32]byte) (authentication.ExternalIdentityProof, error) {
	p.exchangeCalls++
	if code == "" {
		return authentication.ExternalIdentityProof{}, authentication.ErrSocialProviderProof
	}
	return authentication.ExternalIdentityProof{Provider: p.provider, Subject: "social-http-provider-subject"}, nil
}

type socialHTTPE2ERegistry struct {
	appID    applicationinstance.PublicID
	provider *socialHTTPE2EProvider
}

func (r socialHTTPE2ERegistry) Resolve(appID applicationinstance.PublicID, provider authentication.Provider) (authentication.SocialProvider, bool) {
	if r.provider == nil || appID != r.appID || provider != r.provider.provider {
		return nil, false
	}
	return r.provider, true
}

func TestSocialAuthHTTPLifecycleOverPostgreSQL(t *testing.T) {
	pool := exitPool(t, "beebox_social_http_exit")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	apps := applicationpostgres.New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	integrationStore := applicationpostgres.NewIntegrationStore(pool)
	integrations := applicationinstance.NewIntegrationService(integrationStore)
	_, publishableA, err := integrations.CreateCredential(ctx, appA.InternalID, applicationinstance.CredentialKindPublishable)
	if err != nil {
		t.Fatal(err)
	}
	_, publishableB, err := integrations.CreateCredential(ctx, appB.InternalID, applicationinstance.CredentialKindPublishable)
	if err != nil {
		t.Fatal(err)
	}

	const originA = "https://app-a.example"
	const originB = "https://app-b.example"
	const redirectA = "https://app-a.example/auth/complete"
	const foreignRedirect = "https://app-a.example/foreign-owned-by-b"
	if _, err := integrations.AddAllowedOrigin(ctx, appA.InternalID, originA); err != nil {
		t.Fatal(err)
	}
	if _, err := integrations.AddAllowedOrigin(ctx, appB.InternalID, originB); err != nil {
		t.Fatal(err)
	}
	if _, err := integrations.AddAllowedRedirectURL(ctx, appA.InternalID, redirectA); err != nil {
		t.Fatal(err)
	}
	// This redirect deliberately has app A's browser origin but belongs only to
	// app B. It proves redirect ownership is application scoped after the HTTP
	// origin-equality gate has already passed.
	if _, err := integrations.AddAllowedRedirectURL(ctx, appB.InternalID, foreignRedirect); err != nil {
		t.Fatal(err)
	}

	authStore := authpostgres.New(pool)
	provider := &socialHTTPE2EProvider{provider: authentication.ProviderGitHub}
	social := authentication.NewSocialService(
		authStore,
		integrationStore,
		authStore,
		socialHTTPE2ERegistry{appID: appA.PublicID, provider: provider},
		nil,
	)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := session.NewKeyRing("https://auth.example.test", "active", privateKey, map[string]ed25519.PublicKey{"active": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	completion := session.NewSocialCompletionService(authStore, authStore, ring)
	handler := WithSocialAuth(http.NotFoundHandler(), integrations, integrationStore, social, completion)

	verifier := strings.Repeat("v", 43)
	challenge, ok := authentication.S256Challenge(verifier)
	if !ok {
		t.Fatal("failed to create client S256 challenge")
	}

	t.Run("initiation enforces origin redirect ownership provider and S256", func(t *testing.T) {
		wrongOriginRedirect := socialE2EPost(t, handler, publishableA, originA, "/v1/social-auth/attempts", `{"provider":"github","redirect_url":"https://app-b.example/auth/complete","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`)
		assertSocialError(t, wrongOriginRedirect, http.StatusUnprocessableEntity, "invalid_redirect")

		crossAppRedirect := socialE2EPost(t, handler, publishableA, originA, "/v1/social-auth/attempts", `{"provider":"github","redirect_url":"`+foreignRedirect+`","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`)
		assertSocialError(t, crossAppRedirect, http.StatusUnprocessableEntity, "invalid_request")
		if crossAppRedirect.Header().Get("Access-Control-Allow-Origin") != originA {
			t.Fatalf("cross-app redirect error CORS origin = %q", crossAppRedirect.Header().Get("Access-Control-Allow-Origin"))
		}

		invalidChallenge := socialE2EPost(t, handler, publishableA, originA, "/v1/social-auth/attempts", `{"provider":"github","redirect_url":"`+redirectA+`","code_challenge":"short","code_challenge_method":"S256"}`)
		assertSocialError(t, invalidChallenge, http.StatusUnprocessableEntity, "invalid_request")

		invalidMethod := socialE2EPost(t, handler, publishableA, originA, "/v1/social-auth/attempts", `{"provider":"github","redirect_url":"`+redirectA+`","code_challenge":"`+challenge+`","code_challenge_method":"plain"}`)
		assertSocialError(t, invalidMethod, http.StatusUnprocessableEntity, "invalid_request")

		invalidProvider := socialE2EPost(t, handler, publishableA, originA, "/v1/social-auth/attempts", `{"provider":"not-a-provider","redirect_url":"`+redirectA+`","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`)
		assertSocialError(t, invalidProvider, http.StatusUnprocessableEntity, "unsupported_provider")
	})

	db := pool.OpenSQLDB()
	defer db.Close()

	// Provider denial consumes the real stored state and can only return the
	// trusted redirect with BeeBox's generic failure marker. No provider proof
	// or ordinary session is created.
	denialState := socialE2ECreateAttempt(t, handler, publishableA, originA, redirectA, challenge)
	denial := httptest.NewRecorder()
	handler.ServeHTTP(denial, httptest.NewRequest(http.MethodGet,
		"/v1/social-auth/callback/github?state="+url.QueryEscape(denialState)+"&error=access_denied&error_description=provider-secret&application_id="+url.QueryEscape(string(appB.PublicID))+"&redirect_uri=https%3A%2F%2Fevil.example%2Fsteal", nil))
	if denial.Code != http.StatusSeeOther {
		t.Fatalf("provider denial status/body = %d %s", denial.Code, denial.Body.String())
	}
	assertSocialStoredRedirect(t, denial, redirectA, "beebox_error", "social_auth_failed")
	if provider.exchangeCalls != 0 {
		t.Fatalf("provider denial called backchannel %d times", provider.exchangeCalls)
	}
	assertSocialSessionCount(t, db, appA.InternalID, 0)

	// A fresh attempt proves callback provider binding, trusted stored redirect,
	// one-time state, and that callback finalization creates only a completion
	// grant—not an ordinary BeeBox session.
	state := socialE2ECreateAttempt(t, handler, publishableA, originA, redirectA, challenge)
	wrongProvider := httptest.NewRecorder()
	handler.ServeHTTP(wrongProvider, httptest.NewRequest(http.MethodGet,
		"/v1/social-auth/callback/gitlab?state="+url.QueryEscape(state)+"&code=provider-code&redirect_uri=https%3A%2F%2Fevil.example%2Fsteal", nil))
	assertSocialError(t, wrongProvider, http.StatusBadRequest, "invalid_social_state")
	if wrongProvider.Header().Get("Location") != "" {
		t.Fatalf("wrong provider callback redirected to %q", wrongProvider.Header().Get("Location"))
	}

	callback := httptest.NewRecorder()
	handler.ServeHTTP(callback, httptest.NewRequest(http.MethodGet,
		"/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&code=provider-code&application_id="+url.QueryEscape(string(appB.PublicID))+"&redirect_uri=https%3A%2F%2Fevil.example%2Fsteal", nil))
	if callback.Code != http.StatusSeeOther {
		t.Fatalf("callback status/body = %d %s", callback.Code, callback.Body.String())
	}
	completionCode := assertSocialStoredRedirect(t, callback, redirectA, "beebox_code", "")
	if completionCode == "" {
		t.Fatal("callback did not expose opaque BeeBox completion code")
	}
	if provider.exchangeCalls != 1 {
		t.Fatalf("provider proof calls = %d want 1", provider.exchangeCalls)
	}
	for _, forbidden := range []string{"provider-code", "social-http-provider-subject", "evil.example", string(appB.PublicID), "access_token", "refresh_token", "session_id", "provider_token"} {
		if strings.Contains(callback.Header().Get("Location"), forbidden) || strings.Contains(callback.Body.String(), forbidden) {
			t.Fatalf("callback leaked %q: location=%q body=%s", forbidden, callback.Header().Get("Location"), callback.Body.String())
		}
	}
	assertSocialSessionCount(t, db, appA.InternalID, 0)

	replayCallback := httptest.NewRecorder()
	handler.ServeHTTP(replayCallback, httptest.NewRequest(http.MethodGet,
		"/v1/social-auth/callback/github?state="+url.QueryEscape(state)+"&code=provider-code&redirect_uri=https%3A%2F%2Fevil.example%2Fsteal", nil))
	assertSocialError(t, replayCallback, http.StatusBadRequest, "invalid_social_state")
	if replayCallback.Header().Get("Location") != "" || strings.Contains(replayCallback.Body.String(), "evil.example") {
		t.Fatalf("callback replay used untrusted input: location=%q body=%s", replayCallback.Header().Get("Location"), replayCallback.Body.String())
	}

	// Exchange re-resolves application + exact Origin. App B cannot consume app
	// A's grant; an allowed Origin from another app is also insufficient.
	wrongApp := socialE2EPost(t, handler, publishableB, originB, "/v1/social-auth/exchange", `{"code":"`+completionCode+`","code_verifier":"`+verifier+`"}`)
	assertSocialError(t, wrongApp, http.StatusUnauthorized, "invalid_social_completion")
	assertSocialSessionCount(t, db, appA.InternalID, 0)
	assertSocialSessionCount(t, db, appB.InternalID, 0)

	wrongOrigin := socialE2EPost(t, handler, publishableA, originB, "/v1/social-auth/exchange", `{"code":"`+completionCode+`","code_verifier":"`+verifier+`"}`)
	assertSocialError(t, wrongOrigin, http.StatusForbidden, "origin_not_allowed")
	assertSocialSessionCount(t, db, appA.InternalID, 0)

	wrongVerifier := socialE2EPost(t, handler, publishableA, originA, "/v1/social-auth/exchange", `{"code":"`+completionCode+`","code_verifier":"`+strings.Repeat("w", 43)+`"}`)
	assertSocialError(t, wrongVerifier, http.StatusUnauthorized, "invalid_social_completion")
	assertSocialSessionCount(t, db, appA.InternalID, 0)

	validExchange := socialE2EPost(t, handler, publishableA, originA, "/v1/social-auth/exchange", `{"code":"`+completionCode+`","code_verifier":"`+verifier+`"}`)
	if validExchange.Code != http.StatusOK {
		t.Fatalf("valid exchange status/body = %d %s", validExchange.Code, validExchange.Body.String())
	}
	assertSocialSecurityHeaders(t, validExchange, originA)
	var tokenBody map[string]any
	if err := json.Unmarshal(validExchange.Body.Bytes(), &tokenBody); err != nil {
		t.Fatal(err)
	}
	if tokenBody["access_token"] == nil || tokenBody["session_id"] == nil || tokenBody["refresh_token"] != nil {
		t.Fatalf("social exchange token body = %#v", tokenBody)
	}
	for _, forbidden := range []string{"provider_token", "provider_subject", "profile", "social-http-provider-subject", "provider-code"} {
		if strings.Contains(validExchange.Body.String(), forbidden) {
			t.Fatalf("social exchange leaked provider material %q: %s", forbidden, validExchange.Body.String())
		}
	}
	cookies := validExchange.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != refreshCookieName(appA.PublicID) || cookies[0].Value == "" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" {
		t.Fatalf("social exchange refresh cookie = %#v", cookies)
	}
	assertSocialSessionCount(t, db, appA.InternalID, 1)

	replayExchange := socialE2EPost(t, handler, publishableA, originA, "/v1/social-auth/exchange", `{"code":"`+completionCode+`","code_verifier":"`+verifier+`"}`)
	assertSocialError(t, replayExchange, http.StatusUnauthorized, "invalid_social_completion")
	assertSocialSessionCount(t, db, appA.InternalID, 1)
}

func socialE2ECreateAttempt(t *testing.T, handler http.Handler, publishable, origin, redirect, challenge string) string {
	t.Helper()
	res := socialE2EPost(t, handler, publishable, origin, "/v1/social-auth/attempts", `{"provider":"github","redirect_url":"`+redirect+`","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("create social attempt status/body = %d %s", res.Code, res.Body.String())
	}
	assertSocialSecurityHeaders(t, res, origin)
	var payload socialAttemptResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(payload.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("authorization URL omitted state: %q", payload.AuthorizationURL)
	}
	return state
}

func socialE2EPost(t *testing.T, handler http.Handler, publishable, origin, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if publishable != "" {
		req.Header.Set(PublishableKeyHeader, publishable)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func assertSocialStoredRedirect(t *testing.T, res *httptest.ResponseRecorder, storedRedirect, key, wantValue string) string {
	t.Helper()
	assertNoStore(t, res)
	location := parseSocialRedirect(t, res.Header().Get("Location"))
	if location.Scheme+"://"+location.Host+location.Path != storedRedirect {
		t.Fatalf("social callback redirect = %q want stored %q", location.String(), storedRedirect)
	}
	if len(location.Query()) != 1 {
		t.Fatalf("social callback query = %v", location.Query())
	}
	value := location.Query().Get(key)
	if wantValue != "" && value != wantValue {
		t.Fatalf("social callback %s = %q want %q", key, value, wantValue)
	}
	if value == "" {
		t.Fatalf("social callback omitted %s", key)
	}
	return value
}

func assertSocialSessionCount(t *testing.T, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, appID applicationinstance.InternalID, want int) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(appID)).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("sessions for application %d = %d want %d", appID, got, want)
	}
}
