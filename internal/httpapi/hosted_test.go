package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type hostedTestApplications struct{}

func (hostedTestApplications) ResolvePublishable(context.Context, string) (applicationinstance.Instance, error) {
	return applicationinstance.Instance{
		InternalID: 1,
		PublicID:   applicationinstance.PublicID("app_123e4567-e89b-42d3-a456-426614174100"),
	}, nil
}

type hostedTestConfirmer struct {
	calls int
	pair  session.TokenPair
}

func (c *hostedTestConfirmer) Confirm(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.EmailLinkConfirmResult, error) {
	c.calls++
	return session.EmailLinkConfirmResult{TokenPair: c.pair, CompletionURL: "https://app.example/return"}, nil
}

type hostedTestRedirects struct {
	allowed map[string]bool
}

func (p hostedTestRedirects) IsAllowedRedirectURL(_ context.Context, _ applicationinstance.InternalID, raw string) (bool, error) {
	return p.allowed[raw], nil
}

type hostedTestSocialAttempts struct {
	calls       int
	app         applicationinstance.Instance
	provider    authentication.Provider
	redirectURL string
	challenge   string
	method      string
}

func (s *hostedTestSocialAttempts) CreateAttempt(_ context.Context, app applicationinstance.Instance, provider authentication.Provider, redirectURL, challenge, method string) (authentication.SocialAttemptResult, error) {
	s.calls++
	s.app = app
	s.provider = provider
	s.redirectURL = redirectURL
	s.challenge = challenge
	s.method = method
	return authentication.SocialAttemptResult{AuthorizationURL: "https://provider.example/authorize?state=opaque", ExpiresIn: 600}, nil
}

type hostedTestSocialExchange struct {
	calls    int
	appID    applicationinstance.InternalID
	code     string
	verifier string
	pair     session.TokenPair
}

func (s *hostedTestSocialExchange) Exchange(_ context.Context, appID applicationinstance.InternalID, code, verifier string, _ audit.CorrelationID) (session.TokenPair, error) {
	s.calls++
	s.appID = appID
	s.code = code
	s.verifier = verifier
	return s.pair, nil
}

func hostedHandler(base http.Handler, redirects authentication.EmailLinkRedirectPolicy, confirmer EmailLinkConfirmService, socialAttempts HostedSocialAttemptService, socialExchange HostedSocialExchangeService, protector *authentication.SocialStateProtector) http.Handler {
	return WithHostedAuth(base, "https://auth.example", hostedTestApplications{}, redirects, confirmer, nil, nil, nil, nil, socialAttempts, socialExchange, protector)
}

func hostedCSRF(t *testing.T, h http.Handler, path string) (string, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://auth.example"+path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("page status=%d body=%s", rr.Code, rr.Body.String())
	}
	match := regexp.MustCompile(`name="csrf-token" content="([^"]+)"`).FindStringSubmatch(rr.Body.String())
	if len(match) != 2 {
		t.Fatal("missing CSRF token")
	}
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == hostedCSRFCookie {
			return match[1], cookie
		}
	}
	t.Fatal("missing CSRF cookie")
	return "", nil
}

func addHostedMutationHeaders(req *http.Request, csrf string, csrfCookie *http.Cookie) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://auth.example")
	req.Header.Set("X-BeeBox-CSRF", csrf)
	req.AddCookie(csrfCookie)
}

func TestHostedPageSetsHardenedHeadersAndCSRF(t *testing.T) {
	h := hostedHandler(http.NotFoundHandler(), nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "https://auth.example/auth?lang=vi&theme=dark", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", res.StatusCode)
	}
	for name, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := res.Header.Get(name); got != want {
			t.Fatalf("%s=%q want %q", name, got, want)
		}
	}
	csp := res.Header.Get("Content-Security-Policy")
	for _, required := range []string{"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, required) {
			t.Fatalf("CSP missing %q: %q", required, csp)
		}
	}
	body, _ := io.ReadAll(res.Body)
	text := string(body)
	if !strings.Contains(text, `lang="vi"`) || !strings.Contains(text, `data-theme="dark"`) {
		t.Fatalf("locale/theme not rendered: %s", text[:min(len(text), 200)])
	}
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%d want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != hostedCSRFCookie || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("CSRF cookie flags=%+v", cookie)
	}
	if !strings.Contains(text, `name="csrf-token"`) || !strings.Contains(text, cookie.Value) {
		t.Fatal("synchronizer CSRF token missing from hosted document")
	}
}

func TestHostedMutationRejectsMissingOriginOrCSRF(t *testing.T) {
	called := false
	base := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	h := hostedHandler(base, nil, nil, nil, nil, nil)
	for _, tc := range []struct {
		name   string
		origin string
		header string
		cookie string
	}{
		{name: "missing all"},
		{name: "wrong origin", origin: "https://evil.example", header: strings.Repeat("A", 43), cookie: strings.Repeat("A", 43)},
		{name: "wrong csrf", origin: "https://auth.example", header: strings.Repeat("A", 43), cookie: strings.Repeat("B", 43)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://auth.example/auth/api/v1/sign-ins", strings.NewReader(`{}`))
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.header != "" {
				req.Header.Set("X-BeeBox-CSRF", tc.header)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: hostedCSRFCookie, Value: tc.cookie})
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status=%d want 403", rr.Code)
			}
		})
	}
	if called {
		t.Fatal("rejected hosted mutation reached canonical handler")
	}
}

func TestHostedEmailLinkGETNeverConsumesSecretAndAssetRemovesFragment(t *testing.T) {
	confirmer := &hostedTestConfirmer{}
	h := hostedHandler(http.NotFoundHandler(), nil, confirmer, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "https://auth.example/auth/email-link?challenge=eln_123e4567-e89b-42d3-a456-426614174101&pk=pk_test#secret=sensitive", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || confirmer.calls != 0 {
		t.Fatalf("GET status=%d confirmer calls=%d", rr.Code, confirmer.calls)
	}

	assetReq := httptest.NewRequest(http.MethodGet, "https://auth.example/auth/app.js", nil)
	assetRR := httptest.NewRecorder()
	h.ServeHTTP(assetRR, assetReq)
	js := assetRR.Body.String()
	if !strings.Contains(js, "history.replaceState") {
		t.Fatal("hosted JS does not remove one-time credentials from history")
	}
	if strings.Contains(js, "localStorage") || strings.Contains(js, "sessionStorage") {
		t.Fatal("hosted JS persists authentication authority in browser storage")
	}
	if strings.Contains(js, "socialVerifier") || strings.Contains(js, "code_verifier") {
		t.Fatal("hosted JS retains social PKCE verifier in browser authority")
	}
}

func TestHostedEmailLinkMFAUsesValidHostCookieWithoutTokenJSON(t *testing.T) {
	confirmer := &hostedTestConfirmer{pair: session.TokenPair{PendingMFA: &session.PendingMFA{
		Token:            "mfp_123e4567-e89b-42d3-a456-426614174102.secret-material",
		ExpiresAt:        time.Now().UTC().Add(time.Minute),
		AvailableMethods: []string{"totp", "recovery_code"},
	}}}
	h := hostedHandler(http.NotFoundHandler(), nil, confirmer, nil, nil, nil)
	csrf, csrfCookie := hostedCSRF(t, h, "/auth/email-link")

	req := httptest.NewRequest(http.MethodPost, "https://auth.example/auth/api/email-link/confirm", strings.NewReader(`{"challenge_id":"eln_123e4567-e89b-42d3-a456-426614174103","secret":"raw-secret"}`))
	addHostedMutationHeaders(req, csrf, csrfCookie)
	req.Header.Set(PublishableKeyHeader, "pk_test")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "secret-material") || strings.Contains(rr.Body.String(), "pending_mfa_token") {
		t.Fatalf("pending MFA token leaked in JSON: %s", rr.Body.String())
	}
	var found bool
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == hostedMFACookie {
			found = true
			if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" {
				t.Fatalf("MFA __Host cookie flags=%+v", cookie)
			}
		}
	}
	if !found {
		t.Fatal("hosted MFA cookie not set")
	}
}

func TestHostedSocialRoundTripKeepsPKCEAndDestinationServerProtected(t *testing.T) {
	protector, err := authentication.NewSocialStateProtector([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	redirects := hostedTestRedirects{allowed: map[string]bool{
		"https://auth.example/auth/social/callback": true,
		"https://app.example/complete":              true,
	}}
	attempts := &hostedTestSocialAttempts{}
	exchange := &hostedTestSocialExchange{pair: session.TokenPair{
		AccessToken: "access-token", RefreshToken: "refresh-token",
		SessionID: "ses_123e4567-e89b-42d3-a456-426614174110", ExpiresIn: 300,
	}}
	h := hostedHandler(http.NotFoundHandler(), redirects, nil, attempts, exchange, protector)
	csrf, csrfCookie := hostedCSRF(t, h, "/auth")

	startReq := httptest.NewRequest(http.MethodPost, "https://auth.example/auth/api/social/start", strings.NewReader(`{"provider":"google","completion_url":"https://app.example/complete"}`))
	addHostedMutationHeaders(startReq, csrf, csrfCookie)
	startReq.Header.Set(PublishableKeyHeader, "pk_test")
	startRR := httptest.NewRecorder()
	h.ServeHTTP(startRR, startReq)
	if startRR.Code != http.StatusOK {
		t.Fatalf("start status=%d body=%s", startRR.Code, startRR.Body.String())
	}
	if attempts.calls != 1 || attempts.provider != authentication.ProviderGoogle || attempts.redirectURL != "https://auth.example/auth/social/callback" || attempts.method != "S256" {
		t.Fatalf("attempt=%+v", attempts)
	}
	var startBody hostedSocialStartResponse
	if err := json.Unmarshal(startRR.Body.Bytes(), &startBody); err != nil {
		t.Fatal(err)
	}
	if startBody.AuthorizationURL == "" || strings.Contains(startRR.Body.String(), "https://app.example/complete") {
		t.Fatalf("start body leaked destination or lacked authorization URL: %s", startRR.Body.String())
	}
	var socialCookie *http.Cookie
	for _, cookie := range startRR.Result().Cookies() {
		if cookie.Name == hostedSocialCookie {
			socialCookie = cookie
		}
	}
	if socialCookie == nil {
		t.Fatal("social context cookie missing")
	}
	if !socialCookie.Secure || !socialCookie.HttpOnly || socialCookie.SameSite != http.SameSiteLaxMode || socialCookie.Path != "/" || socialCookie.Domain != "" {
		t.Fatalf("social __Host cookie flags=%+v", socialCookie)
	}
	context, err := protector.OpenHostedContext(socialCookie.Value, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if context.ApplicationInstanceID != 1 || context.CompletionURL != "https://app.example/complete" || !authentication.ValidPKCEVerifier(context.PKCEVerifier) {
		t.Fatalf("sealed context=%+v", context)
	}
	wantChallenge, ok := authentication.S256Challenge(context.PKCEVerifier)
	if !ok || attempts.challenge != wantChallenge {
		t.Fatalf("challenge=%q want=%q", attempts.challenge, wantChallenge)
	}

	callbackReq := httptest.NewRequest(http.MethodGet, "https://auth.example/auth/social/callback?beebox_code=completion-code", nil)
	callbackRR := httptest.NewRecorder()
	h.ServeHTTP(callbackRR, callbackReq)
	if callbackRR.Code != http.StatusOK || exchange.calls != 0 {
		t.Fatalf("scanner GET status=%d exchange calls=%d", callbackRR.Code, exchange.calls)
	}

	callbackCSRF, callbackCSRFCookie := hostedCSRF(t, h, "/auth/social/callback")
	exchangeReq := httptest.NewRequest(http.MethodPost, "https://auth.example/auth/api/social/exchange", strings.NewReader(`{"code":"completion-code"}`))
	addHostedMutationHeaders(exchangeReq, callbackCSRF, callbackCSRFCookie)
	exchangeReq.AddCookie(socialCookie)
	exchangeRR := httptest.NewRecorder()
	h.ServeHTTP(exchangeRR, exchangeReq)
	if exchangeRR.Code != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", exchangeRR.Code, exchangeRR.Body.String())
	}
	if exchange.calls != 1 || exchange.appID != 1 || exchange.code != "completion-code" || exchange.verifier != context.PKCEVerifier {
		t.Fatalf("exchange=%+v", exchange)
	}
	if !strings.Contains(exchangeRR.Body.String(), `"completion_url":"https://app.example/complete"`) {
		t.Fatalf("exchange body=%s", exchangeRR.Body.String())
	}
}

func TestHostedSocialTamperedContextFailsClosedBeforeExchange(t *testing.T) {
	protector, err := authentication.NewSocialStateProtector([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	exchange := &hostedTestSocialExchange{}
	h := hostedHandler(http.NotFoundHandler(), hostedTestRedirects{allowed: map[string]bool{"https://app.example/complete": true}}, nil, nil, exchange, protector)
	csrf, csrfCookie := hostedCSRF(t, h, "/auth/social/callback")
	verifier, err := authentication.NewSocialPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sealed, err := protector.SealHostedContext(authentication.HostedSocialContext{
		ApplicationInstanceID: 1,
		ApplicationPublicID:   applicationinstance.PublicID("app_123e4567-e89b-42d3-a456-426614174100"),
		PKCEVerifier:          verifier,
		CompletionURL:         "https://app.example/complete",
		IssuedAt:              now,
		ExpiresAt:             now.Add(authentication.SocialAttemptTTL),
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(sealed)
	if tampered[len(tampered)-1] == 'A' {
		tampered[len(tampered)-1] = 'B'
	} else {
		tampered[len(tampered)-1] = 'A'
	}
	req := httptest.NewRequest(http.MethodPost, "https://auth.example/auth/api/social/exchange", strings.NewReader(`{"code":"completion-code"}`))
	addHostedMutationHeaders(req, csrf, csrfCookie)
	req.AddCookie(&http.Cookie{Name: hostedSocialCookie, Value: string(tampered)})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || exchange.calls != 0 {
		t.Fatalf("status=%d exchange calls=%d body=%s", rr.Code, exchange.calls, rr.Body.String())
	}
}
