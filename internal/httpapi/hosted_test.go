package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
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

func TestHostedPageSetsHardenedHeadersAndCSRF(t *testing.T) {
	h := WithHostedAuth(http.NotFoundHandler(), "https://auth.example", nil, nil, nil, nil, nil, nil, nil)
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
	h := WithHostedAuth(base, "https://auth.example", nil, nil, nil, nil, nil, nil, nil)
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
	h := WithHostedAuth(http.NotFoundHandler(), "https://auth.example", hostedTestApplications{}, nil, confirmer, nil, nil, nil, nil)
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
		t.Fatal("hosted JS does not remove email-link fragment from history")
	}
	if strings.Contains(js, "localStorage") || strings.Contains(js, "sessionStorage") {
		t.Fatal("hosted JS persists authentication authority in browser storage")
	}
}

func TestHostedEmailLinkMFAUsesHttpOnlyCookieWithoutTokenJSON(t *testing.T) {
	confirmer := &hostedTestConfirmer{pair: session.TokenPair{PendingMFA: &session.PendingMFA{
		Token:            "mfp_123e4567-e89b-42d3-a456-426614174102.secret-material",
		ExpiresAt:        time.Now().UTC().Add(time.Minute),
		AvailableMethods: []string{"totp", "recovery_code"},
	}}}
	h := WithHostedAuth(http.NotFoundHandler(), "https://auth.example", hostedTestApplications{}, nil, confirmer, nil, nil, nil, nil)

	pageReq := httptest.NewRequest(http.MethodGet, "https://auth.example/auth/email-link", nil)
	pageRR := httptest.NewRecorder()
	h.ServeHTTP(pageRR, pageReq)
	pageBody := pageRR.Body.String()
	match := regexp.MustCompile(`name="csrf-token" content="([^"]+)"`).FindStringSubmatch(pageBody)
	if len(match) != 2 {
		t.Fatal("missing CSRF token")
	}
	csrf := match[1]

	req := httptest.NewRequest(http.MethodPost, "https://auth.example/auth/api/email-link/confirm", strings.NewReader(`{"challenge_id":"eln_123e4567-e89b-42d3-a456-426614174103","secret":"raw-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://auth.example")
	req.Header.Set("X-BeeBox-CSRF", csrf)
	req.Header.Set(PublishableKeyHeader, "pk_test")
	req.AddCookie(&http.Cookie{Name: hostedCSRFCookie, Value: csrf})
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
			if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/auth" || cookie.Domain != "" {
				t.Fatalf("MFA cookie flags=%+v", cookie)
			}
		}
	}
	if !found {
		t.Fatal("hosted MFA cookie not set")
	}
}
