package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type socialHTTPApps struct {
	key   string
	app   applicationinstance.Instance
	calls int
	seen  []string
}

func (f *socialHTTPApps) ResolvePublishable(_ context.Context, key string) (applicationinstance.Instance, error) {
	f.calls++
	f.seen = append(f.seen, key)
	if key != f.key {
		return applicationinstance.Instance{}, applicationinstance.ErrCredentialNotFound
	}
	return f.app, nil
}

type socialHTTPOrigins struct {
	appID  applicationinstance.InternalID
	origin string
}

func (f socialHTTPOrigins) IsAllowedOrigin(_ context.Context, appID applicationinstance.InternalID, origin string) (bool, error) {
	return appID == f.appID && origin == f.origin, nil
}

func (f socialHTTPOrigins) AnyAllowedOrigin(_ context.Context, origin string) (bool, error) {
	return origin == f.origin, nil
}

type fakeSocialHTTPService struct {
	createCalls     int
	createApp       applicationinstance.Instance
	createProvider  authentication.Provider
	createRedirect  string
	createChallenge string
	createMethod    string
	createResult    authentication.SocialAttemptResult
	createErr       error

	completeCalls    int
	completeProvider authentication.Provider
	completeState    string
	completeCode     string
	completeDenied   bool
	completeResult   authentication.SocialCallbackResult
	completeErr      error
	completeFunc     func(authentication.Provider, string, string, bool) (authentication.SocialCallbackResult, error)
}

func (f *fakeSocialHTTPService) CreateAttempt(_ context.Context, app applicationinstance.Instance, provider authentication.Provider, redirectURL, challenge, method string) (authentication.SocialAttemptResult, error) {
	f.createCalls++
	f.createApp = app
	f.createProvider = provider
	f.createRedirect = redirectURL
	f.createChallenge = challenge
	f.createMethod = method
	if f.createErr != nil {
		return authentication.SocialAttemptResult{}, f.createErr
	}
	return f.createResult, nil
}

func (f *fakeSocialHTTPService) CompleteCallback(_ context.Context, provider authentication.Provider, state, code string, denied bool, _ audit.CorrelationID) (authentication.SocialCallbackResult, error) {
	f.completeCalls++
	f.completeProvider = provider
	f.completeState = state
	f.completeCode = code
	f.completeDenied = denied
	if f.completeFunc != nil {
		return f.completeFunc(provider, state, code, denied)
	}
	if f.completeErr != nil {
		return authentication.SocialCallbackResult{}, f.completeErr
	}
	return f.completeResult, nil
}

type fakeSocialHTTPExchange struct {
	calls    int
	appID    applicationinstance.InternalID
	code     string
	verifier string
	pair     session.TokenPair
	err      error
	fn       func(applicationinstance.InternalID, string, string) (session.TokenPair, error)
}

func (f *fakeSocialHTTPExchange) Exchange(_ context.Context, appID applicationinstance.InternalID, code, verifier string, _ audit.CorrelationID) (session.TokenPair, error) {
	f.calls++
	f.appID = appID
	f.code = code
	f.verifier = verifier
	if f.fn != nil {
		return f.fn(appID, code, verifier)
	}
	return f.pair, f.err
}

func TestSocialAttemptHTTPTrustBoundary(t *testing.T) {
	appPublicID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	app := applicationinstance.Instance{InternalID: 42, PublicID: appPublicID}
	const key = "bb_pk_fixture"
	const origin = "https://app.example"
	const redirect = "https://app.example/auth/complete"
	verifier := strings.Repeat("v", 43)
	challenge, ok := authentication.S256Challenge(verifier)
	if !ok {
		t.Fatal("failed to build fixture S256 challenge")
	}

	t.Run("valid key and exact origin resolve trusted application", func(t *testing.T) {
		apps := &socialHTTPApps{key: key, app: app}
		social := &fakeSocialHTTPService{createResult: authentication.SocialAttemptResult{AuthorizationURL: "https://provider.example/authorize", ExpiresIn: 600}}
		handler := WithSocialAuth(http.NotFoundHandler(), apps, socialHTTPOrigins{appID: app.InternalID, origin: origin}, social, &fakeSocialHTTPExchange{})
		res := socialAttemptHTTP(t, handler, key, []string{origin}, `{"provider":"github","redirect_url":"`+redirect+`","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`)
		if res.Code != http.StatusCreated {
			t.Fatalf("status/body = %d %s", res.Code, res.Body.String())
		}
		if apps.calls != 1 || len(apps.seen) != 1 || apps.seen[0] != key {
			t.Fatalf("publishable resolution calls/keys = %d %#v", apps.calls, apps.seen)
		}
		if social.createCalls != 1 || social.createApp.InternalID != app.InternalID || social.createApp.PublicID != app.PublicID {
			t.Fatalf("social attempt application = %#v calls=%d", social.createApp, social.createCalls)
		}
		if social.createProvider != authentication.ProviderGitHub || social.createRedirect != redirect || social.createChallenge != challenge || social.createMethod != "S256" {
			t.Fatalf("social attempt inputs provider=%q redirect=%q challenge=%q method=%q", social.createProvider, social.createRedirect, social.createChallenge, social.createMethod)
		}
		assertSocialSecurityHeaders(t, res, origin)
		var payload socialAttemptResponse
		if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.AuthorizationURL != "https://provider.example/authorize" || payload.ExpiresIn != 600 {
			t.Fatalf("attempt response = %#v", payload)
		}
	})

	t.Run("publishable key failures do not dispatch", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			set  func(*http.Request)
		}{
			{name: "missing"},
			{name: "invalid", set: func(r *http.Request) { r.Header.Set(PublishableKeyHeader, "wrong") }},
			{name: "duplicate", set: func(r *http.Request) {
				r.Header.Add(PublishableKeyHeader, key)
				r.Header.Add(PublishableKeyHeader, key)
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				apps := &socialHTTPApps{key: key, app: app}
				social := &fakeSocialHTTPService{}
				handler := WithSocialAuth(http.NotFoundHandler(), apps, socialHTTPOrigins{appID: app.InternalID, origin: origin}, social, &fakeSocialHTTPExchange{})
				req := httptest.NewRequest(http.MethodPost, "/v1/social-auth/attempts", strings.NewReader(`{"provider":"github","redirect_url":"`+redirect+`","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", origin)
				if tc.set != nil {
					tc.set(req)
				}
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)
				assertSocialError(t, res, http.StatusUnauthorized, "invalid_application")
				if social.createCalls != 0 {
					t.Fatalf("social attempt dispatched %d times", social.createCalls)
				}
			})
		}
	})

	t.Run("origin failures do not dispatch", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			origins []string
		}{
			{name: "missing"},
			{name: "duplicate", origins: []string{origin, origin}},
			{name: "non canonical", origins: []string{"https://APP.example"}},
			{name: "disallowed", origins: []string{"https://evil.example"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				social := &fakeSocialHTTPService{}
				handler := WithSocialAuth(http.NotFoundHandler(), &socialHTTPApps{key: key, app: app}, socialHTTPOrigins{appID: app.InternalID, origin: origin}, social, &fakeSocialHTTPExchange{})
				res := socialAttemptHTTP(t, handler, key, tc.origins, `{"provider":"github","redirect_url":"`+redirect+`","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`)
				assertSocialError(t, res, http.StatusForbidden, "origin_not_allowed")
				if social.createCalls != 0 {
					t.Fatalf("social attempt dispatched %d times", social.createCalls)
				}
			})
		}
	})

	t.Run("redirect origin cannot substitute browser origin", func(t *testing.T) {
		social := &fakeSocialHTTPService{}
		handler := WithSocialAuth(http.NotFoundHandler(), &socialHTTPApps{key: key, app: app}, socialHTTPOrigins{appID: app.InternalID, origin: origin}, social, &fakeSocialHTTPExchange{})
		res := socialAttemptHTTP(t, handler, key, []string{origin}, `{"provider":"github","redirect_url":"https://other.example/auth/complete","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`)
		assertSocialError(t, res, http.StatusUnprocessableEntity, "invalid_redirect")
		if social.createCalls != 0 {
			t.Fatalf("redirect mismatch dispatched %d attempts", social.createCalls)
		}
	})

	t.Run("invalid provider is not remapped", func(t *testing.T) {
		social := &fakeSocialHTTPService{createErr: authentication.ErrSocialUnsupportedProvider}
		handler := WithSocialAuth(http.NotFoundHandler(), &socialHTTPApps{key: key, app: app}, socialHTTPOrigins{appID: app.InternalID, origin: origin}, social, &fakeSocialHTTPExchange{})
		res := socialAttemptHTTP(t, handler, key, []string{origin}, `{"provider":"not-a-provider","redirect_url":"`+redirect+`","code_challenge":"`+challenge+`","code_challenge_method":"S256"}`)
		assertSocialError(t, res, http.StatusUnprocessableEntity, "unsupported_provider")
		if social.createCalls != 1 || social.createProvider != authentication.Provider("not-a-provider") {
			t.Fatalf("invalid provider dispatch = %q calls=%d", social.createProvider, social.createCalls)
		}
	})

	t.Run("invalid S256 challenge and method map to stable error", func(t *testing.T) {
		for _, body := range []string{
			`{"provider":"github","redirect_url":"` + redirect + `","code_challenge":"short","code_challenge_method":"S256"}`,
			`{"provider":"github","redirect_url":"` + redirect + `","code_challenge":"` + challenge + `","code_challenge_method":"plain"}`,
		} {
			social := &fakeSocialHTTPService{createErr: authentication.ErrSocialInvalidRequest}
			handler := WithSocialAuth(http.NotFoundHandler(), &socialHTTPApps{key: key, app: app}, socialHTTPOrigins{appID: app.InternalID, origin: origin}, social, &fakeSocialHTTPExchange{})
			res := socialAttemptHTTP(t, handler, key, []string{origin}, body)
			assertSocialError(t, res, http.StatusUnprocessableEntity, "invalid_request")
			if social.createCalls != 1 {
				t.Fatalf("invalid S256 request calls = %d", social.createCalls)
			}
		}
	})
}

func TestSocialCallbackHTTPTrustBoundary(t *testing.T) {
	const storedRedirect = "https://app.example/auth/complete"

	t.Run("success uses stored redirect and exposes only completion code", func(t *testing.T) {
		social := &fakeSocialHTTPService{completeResult: authentication.SocialCallbackResult{RedirectURL: storedRedirect, CompletionCode: "opaque-completion"}}
		exchange := &fakeSocialHTTPExchange{}
		handler := WithSocialAuth(http.NotFoundHandler(), nil, nil, social, exchange)
		req := httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state=opaque-state&code=provider-code&application_id=attacker&redirect_uri=https%3A%2F%2Fevil.example%2Fsteal", nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusSeeOther {
			t.Fatalf("status/body = %d %s", res.Code, res.Body.String())
		}
		location := parseSocialRedirect(t, res.Header().Get("Location"))
		if location.Scheme+"://"+location.Host+location.Path != storedRedirect {
			t.Fatalf("callback redirect = %q", location.String())
		}
		if len(location.Query()) != 1 || location.Query().Get("beebox_code") != "opaque-completion" {
			t.Fatalf("callback query = %v", location.Query())
		}
		for _, forbidden := range []string{"provider-code", "attacker", "evil.example", "access_token", "refresh_token", "session_id", "provider_token"} {
			if strings.Contains(res.Header().Get("Location"), forbidden) || strings.Contains(res.Body.String(), forbidden) {
				t.Fatalf("callback leaked %q: location=%q body=%s", forbidden, res.Header().Get("Location"), res.Body.String())
			}
		}
		if social.completeCalls != 1 || social.completeProvider != authentication.ProviderGitHub || social.completeState != "opaque-state" || social.completeCode != "provider-code" || social.completeDenied {
			t.Fatalf("callback dispatch provider=%q state=%q code=%q denied=%v calls=%d", social.completeProvider, social.completeState, social.completeCode, social.completeDenied, social.completeCalls)
		}
		if exchange.calls != 0 {
			t.Fatalf("callback crossed ordinary session exchange boundary: calls=%d", exchange.calls)
		}
		assertNoStore(t, res)
	})

	t.Run("provider denial is generic on stored redirect", func(t *testing.T) {
		social := &fakeSocialHTTPService{completeResult: authentication.SocialCallbackResult{RedirectURL: storedRedirect, Failed: true}}
		handler := WithSocialAuth(http.NotFoundHandler(), nil, nil, social, &fakeSocialHTTPExchange{})
		req := httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state=opaque-state&error=access_denied&error_description=provider-secret&redirect_uri=https%3A%2F%2Fevil.example%2Fsteal", nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusSeeOther {
			t.Fatalf("status/body = %d %s", res.Code, res.Body.String())
		}
		location := parseSocialRedirect(t, res.Header().Get("Location"))
		if location.Scheme+"://"+location.Host+location.Path != storedRedirect || len(location.Query()) != 1 || location.Query().Get("beebox_error") != "social_auth_failed" {
			t.Fatalf("denial redirect = %q", location.String())
		}
		for _, forbidden := range []string{"access_denied", "provider-secret", "evil.example", "error_description"} {
			if strings.Contains(res.Header().Get("Location"), forbidden) || strings.Contains(res.Body.String(), forbidden) {
				t.Fatalf("provider denial leaked %q", forbidden)
			}
		}
		if social.completeCalls != 1 || !social.completeDenied || social.completeCode != "" {
			t.Fatalf("provider denial dispatch = calls=%d denied=%v code=%q", social.completeCalls, social.completeDenied, social.completeCode)
		}
		assertNoStore(t, res)
	})

	t.Run("query and provider path validation fail closed", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			path string
		}{
			{name: "missing state", path: "/v1/social-auth/callback/github?code=x"},
			{name: "duplicate state", path: "/v1/social-auth/callback/github?state=a&state=b&code=x"},
			{name: "duplicate code", path: "/v1/social-auth/callback/github?state=a&code=x&code=y"},
			{name: "malformed provider path", path: "/v1/social-auth/callback/github/extra?state=a&code=x"},
			{name: "invalid provider", path: "/v1/social-auth/callback/not-a-provider?state=a&code=x"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				social := &fakeSocialHTTPService{}
				handler := WithSocialAuth(http.NotFoundHandler(), nil, nil, social, &fakeSocialHTTPExchange{})
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, tc.path, nil))
				assertSocialError(t, res, http.StatusBadRequest, "invalid_social_state")
				if res.Header().Get("Location") != "" {
					t.Fatalf("invalid callback redirected to %q", res.Header().Get("Location"))
				}
				if social.completeCalls != 0 {
					t.Fatalf("invalid callback dispatched %d times", social.completeCalls)
				}
			})
		}
	})

	t.Run("wrong provider state and replay fail without untrusted redirect", func(t *testing.T) {
		consumed := false
		social := &fakeSocialHTTPService{completeFunc: func(provider authentication.Provider, state, _ string, _ bool) (authentication.SocialCallbackResult, error) {
			if provider != authentication.ProviderGitHub || state != "bound-state" || consumed {
				return authentication.SocialCallbackResult{}, authentication.ErrSocialInvalidState
			}
			consumed = true
			return authentication.SocialCallbackResult{RedirectURL: storedRedirect, CompletionCode: "one-time-code"}, nil
		}}
		handler := WithSocialAuth(http.NotFoundHandler(), nil, nil, social, &fakeSocialHTTPExchange{})

		wrong := httptest.NewRecorder()
		handler.ServeHTTP(wrong, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/gitlab?state=bound-state&code=x&redirect_uri=https%3A%2F%2Fevil.example", nil))
		assertSocialError(t, wrong, http.StatusBadRequest, "invalid_social_state")
		if wrong.Header().Get("Location") != "" {
			t.Fatalf("wrong provider/state redirected to %q", wrong.Header().Get("Location"))
		}

		first := httptest.NewRecorder()
		handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state=bound-state&code=x", nil))
		if first.Code != http.StatusSeeOther {
			t.Fatalf("first callback status/body = %d %s", first.Code, first.Body.String())
		}

		replay := httptest.NewRecorder()
		handler.ServeHTTP(replay, httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state=bound-state&code=x&redirect_uri=https%3A%2F%2Fevil.example", nil))
		assertSocialError(t, replay, http.StatusBadRequest, "invalid_social_state")
		if replay.Header().Get("Location") != "" || strings.Contains(replay.Body.String(), "evil.example") {
			t.Fatalf("replay used untrusted redirect: location=%q body=%s", replay.Header().Get("Location"), replay.Body.String())
		}
	})
}

func TestSocialExchangeHTTPTrustBoundary(t *testing.T) {
	appPublicID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	app := applicationinstance.Instance{InternalID: 42, PublicID: appPublicID}
	const key = "bb_pk_fixture"
	const origin = "https://app.example"
	const completionCode = "completion-code"
	verifier := strings.Repeat("v", 43)
	pair := session.TokenPair{
		AccessToken:  "beebox-access-token",
		RefreshToken: "beebox-refresh-token",
		ExpiresIn:    300,
		SessionID:    "ses_21234567-89ab-4cde-8fab-0123456789ab",
	}

	t.Run("success resolves application again and issues session transport only here", func(t *testing.T) {
		apps := &socialHTTPApps{key: key, app: app}
		exchange := &fakeSocialHTTPExchange{pair: pair}
		handler := WithSocialAuth(http.NotFoundHandler(), apps, socialHTTPOrigins{appID: app.InternalID, origin: origin}, &fakeSocialHTTPService{}, exchange)
		res := socialExchangeHTTP(t, handler, key, []string{origin}, `{"code":"`+completionCode+`","code_verifier":"`+verifier+`"}`)
		if res.Code != http.StatusOK {
			t.Fatalf("status/body = %d %s", res.Code, res.Body.String())
		}
		if apps.calls != 1 || exchange.calls != 1 || exchange.appID != app.InternalID || exchange.code != completionCode || exchange.verifier != verifier {
			t.Fatalf("exchange boundary apps=%d calls=%d app=%d code=%q verifier=%q", apps.calls, exchange.calls, exchange.appID, exchange.code, exchange.verifier)
		}
		if !strings.Contains(res.Body.String(), pair.AccessToken) || !strings.Contains(res.Body.String(), pair.SessionID) || strings.Contains(res.Body.String(), pair.RefreshToken) {
			t.Fatalf("browser exchange transport = %s", res.Body.String())
		}
		for _, forbidden := range []string{"provider_token", "provider_subject", "profile", "stable-subject"} {
			if strings.Contains(res.Body.String(), forbidden) {
				t.Fatalf("exchange response leaked provider material %q: %s", forbidden, res.Body.String())
			}
		}
		cookies := res.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != refreshCookieName(app.PublicID) || cookies[0].Value != pair.RefreshToken || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" {
			t.Fatalf("social refresh cookie = %#v", cookies)
		}
		assertSocialSecurityHeaders(t, res, origin)
	})

	t.Run("wrong origin and application fail before exchange", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			requestKey string
			origin     string
			status     int
			code       string
		}{
			{name: "wrong origin", requestKey: key, origin: "https://evil.example", status: http.StatusForbidden, code: "origin_not_allowed"},
			{name: "wrong application key", requestKey: "wrong", origin: origin, status: http.StatusUnauthorized, code: "invalid_application"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				exchange := &fakeSocialHTTPExchange{pair: pair}
				handler := WithSocialAuth(http.NotFoundHandler(), &socialHTTPApps{key: key, app: app}, socialHTTPOrigins{appID: app.InternalID, origin: origin}, &fakeSocialHTTPService{}, exchange)
				res := socialExchangeHTTP(t, handler, tc.requestKey, []string{tc.origin}, `{"code":"`+completionCode+`","code_verifier":"`+verifier+`"}`)
				assertSocialError(t, res, tc.status, tc.code)
				if exchange.calls != 0 {
					t.Fatalf("rejected exchange dispatched %d times", exchange.calls)
				}
			})
		}
	})

	t.Run("invalid completion and replay map to stable error", func(t *testing.T) {
		used := false
		exchange := &fakeSocialHTTPExchange{fn: func(_ applicationinstance.InternalID, code, verifier string) (session.TokenPair, error) {
			if code != completionCode || verifier != strings.Repeat("v", 43) || used {
				return session.TokenPair{}, session.ErrInvalidCredentials
			}
			used = true
			return pair, nil
		}}
		handler := WithSocialAuth(http.NotFoundHandler(), &socialHTTPApps{key: key, app: app}, socialHTTPOrigins{appID: app.InternalID, origin: origin}, &fakeSocialHTTPService{}, exchange)

		wrongVerifier := socialExchangeHTTP(t, handler, key, []string{origin}, `{"code":"`+completionCode+`","code_verifier":"`+strings.Repeat("w", 43)+`"}`)
		assertSocialError(t, wrongVerifier, http.StatusUnauthorized, "invalid_social_completion")

		valid := socialExchangeHTTP(t, handler, key, []string{origin}, `{"code":"`+completionCode+`","code_verifier":"`+verifier+`"}`)
		if valid.Code != http.StatusOK {
			t.Fatalf("valid exchange status/body = %d %s", valid.Code, valid.Body.String())
		}

		replay := socialExchangeHTTP(t, handler, key, []string{origin}, `{"code":"`+completionCode+`","code_verifier":"`+verifier+`"}`)
		assertSocialError(t, replay, http.StatusUnauthorized, "invalid_social_completion")
	})
}

func socialAttemptHTTP(t *testing.T, handler http.Handler, key string, origins []string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/social-auth/attempts", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set(PublishableKeyHeader, key)
	}
	for _, origin := range origins {
		req.Header.Add("Origin", origin)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func socialExchangeHTTP(t *testing.T, handler http.Handler, key string, origins []string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/social-auth/exchange", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set(PublishableKeyHeader, key)
	}
	for _, origin := range origins {
		req.Header.Add("Origin", origin)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func assertSocialError(t *testing.T, res *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if res.Code != status {
		t.Fatalf("status = %d want %d body=%s", res.Code, status, res.Body.String())
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(res.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error body: %v body=%s", err, res.Body.String())
	}
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		t.Fatalf("error = %#v want code=%q", envelope.Error, code)
	}
	assertNoStore(t, res)
}

func assertNoStore(t *testing.T, res *httptest.ResponseRecorder) {
	t.Helper()
	if res.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", res.Header().Get("Cache-Control"))
	}
}

func assertSocialSecurityHeaders(t *testing.T, res *httptest.ResponseRecorder, origin string) {
	t.Helper()
	assertNoStore(t, res)
	if res.Header().Get("Access-Control-Allow-Origin") != origin || res.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("CORS headers origin=%q credentials=%q", res.Header().Get("Access-Control-Allow-Origin"), res.Header().Get("Access-Control-Allow-Credentials"))
	}
	if res.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatal("credentialed social CORS used wildcard")
	}
}

func parseSocialRedirect(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", raw, err)
	}
	return u
}

var _ = errors.Is
