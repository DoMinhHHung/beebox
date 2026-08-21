package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/session"
)

const testSessionAppPublicID = applicationinstance.PublicID("app_11234567-89ab-4cde-8fab-0123456789ab")

type fakeSessions struct {
	signInPair   session.TokenPair
	refreshPair  session.TokenPair
	refreshValue string
}

func (f *fakeSessions) SignIn(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error) {
	return f.signInPair, nil
}

func (f *fakeSessions) Refresh(_ context.Context, _ applicationinstance.InternalID, refresh string, _ audit.CorrelationID) (session.TokenPair, error) {
	f.refreshValue = refresh
	return f.refreshPair, nil
}

func TestBrowserSignInReturnsAppSpecificHostRefreshCookie(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	sessions := &fakeSessions{signInPair: session.TokenPair{
		AccessToken:  "access-token",
		RefreshToken: "refresh-secret",
		ExpiresIn:    300,
		SessionID:    "ses_21234567-89ab-4cde-8fab-0123456789ab",
	}}
	base := New(http.NotFoundHandler(), fakeApps{}, fakeOrigins{}, nil, nil)
	handler := WithSessions(
		base,
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID, PublicID: testSessionAppPublicID}},
		fakeOrigins{appID: appID, origin: "https://app.example"},
		sessions,
		nil,
	)
	req := httptest.NewRequest(http.MethodPost, "/v1/sign-ins", strings.NewReader("{\"email\":\"user@example.com\",\"password\":\"password\"}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "key")
	req.Header.Set("Origin", "https://app.example")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	cookies := res.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != refreshCookieName(testSessionAppPublicID) || cookie.Value != "refresh-secret" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("refresh cookie = %#v", cookie)
	}
	if strings.Contains(res.Body.String(), "refresh-secret") {
		t.Fatal("browser token response exposed refresh credential in JSON")
	}
	var body tokenResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "authenticated" || body.Session == nil || body.Session.ID != sessions.signInPair.SessionID || body.AccessToken != sessions.signInPair.AccessToken {
		t.Fatalf("authenticated result=%+v", body)
	}
}

func TestPendingMFAResultContainsNoSessionAuthority(t *testing.T) {
	expiresAt := time.Unix(1_700_000_300, 0).UTC()
	pair := session.TokenPair{
		AccessToken:  "must-not-leak-access",
		RefreshToken: "must-not-leak-refresh",
		ExpiresIn:    300,
		SessionID:    "ses_21234567-89ab-4cde-8fab-0123456789ab",
		PendingMFA: &session.PendingMFA{
			Token:            "mfp_21234567-89ab-4cde-8fab-0123456789ab.secret",
			ExpiresAt:        expiresAt,
			AvailableMethods: []string{"totp"},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/sign-ins", nil)
	res := httptest.NewRecorder()
	writeAuthenticationTokenPair(res, req, pair, testSessionAppPublicID)

	var body tokenResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "mfa_required" || body.PendingMFAToken != pair.PendingMFA.Token || body.ExpiresAt == nil || !body.ExpiresAt.Equal(expiresAt) || len(body.AvailableMethods) != 1 || body.AvailableMethods[0] != "totp" {
		t.Fatalf("pending MFA result=%+v", body)
	}
	if body.Session != nil || body.AccessToken != "" || body.RefreshToken != "" || body.SessionID != "" || body.TokenType != "" || body.ExpiresIn != 0 {
		t.Fatalf("pending MFA result leaked authority=%+v", body)
	}
	if len(res.Result().Cookies()) != 0 {
		t.Fatalf("pending MFA result set cookies=%v", res.Result().Cookies())
	}
}

func TestCookieRefreshRequiresExactOrigin(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	cookieName := refreshCookieName(testSessionAppPublicID)
	sessions := &fakeSessions{refreshPair: session.TokenPair{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		ExpiresIn:    300,
		SessionID:    "ses_21234567-89ab-4cde-8fab-0123456789ab",
	}}
	base := New(http.NotFoundHandler(), fakeApps{}, fakeOrigins{}, nil, nil)
	handler := WithSessions(
		base,
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID, PublicID: testSessionAppPublicID}},
		fakeOrigins{appID: appID, origin: "https://app.example"},
		sessions,
		nil,
	)

	missingOrigin := httptest.NewRequest(http.MethodPost, "/v1/sessions/refresh", nil)
	missingOrigin.Header.Set(PublishableKeyHeader, "key")
	missingOrigin.AddCookie(&http.Cookie{Name: cookieName, Value: "old-refresh"})
	missingOriginRes := httptest.NewRecorder()
	handler.ServeHTTP(missingOriginRes, missingOrigin)
	if missingOriginRes.Code != http.StatusForbidden {
		t.Fatalf("missing-origin refresh status = %d", missingOriginRes.Code)
	}

	allowed := httptest.NewRequest(http.MethodPost, "/v1/sessions/refresh", nil)
	allowed.Header.Set(PublishableKeyHeader, "key")
	allowed.Header.Set("Origin", "https://app.example")
	allowed.AddCookie(&http.Cookie{Name: cookieName, Value: "old-refresh"})
	allowedRes := httptest.NewRecorder()
	handler.ServeHTTP(allowedRes, allowed)
	if allowedRes.Code != http.StatusOK {
		t.Fatalf("allowed refresh status = %d body=%s", allowedRes.Code, allowedRes.Body.String())
	}
	if sessions.refreshValue != "old-refresh" {
		t.Fatalf("refresh value = %q", sessions.refreshValue)
	}
	if got := allowedRes.Result().Cookies()[0].Name; got != cookieName {
		t.Fatalf("rotated cookie name = %q, want %q", got, cookieName)
	}
}

func TestSessionPreflightRequiresStoredExactOrigin(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	base := New(http.NotFoundHandler(), fakeApps{}, fakeOrigins{}, nil, nil)
	handler := WithSessions(
		base,
		fakeApps{},
		fakeOrigins{appID: appID, origin: "https://app.example"},
		&fakeSessions{},
		nil,
	)

	allowed := httptest.NewRequest(http.MethodOptions, "/v1/sign-ins", nil)
	allowed.Header.Set("Origin", "https://app.example")
	allowed.Header.Set("Access-Control-Request-Method", http.MethodPost)
	allowed.Header.Set("Access-Control-Request-Headers", "content-type,x-beebox-publishable-key")
	allowedRes := httptest.NewRecorder()
	handler.ServeHTTP(allowedRes, allowed)
	if allowedRes.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d body=%s", allowedRes.Code, allowedRes.Body.String())
	}
	if allowedRes.Header().Get("Access-Control-Allow-Origin") != "https://app.example" || allowedRes.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("preflight CORS headers = %#v", allowedRes.Header())
	}
	if allowedRes.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatal("credentialed preflight used wildcard origin")
	}

	foreign := httptest.NewRequest(http.MethodOptions, "/v1/sessions/refresh", nil)
	foreign.Header.Set("Origin", "https://evil.example")
	foreign.Header.Set("Access-Control-Request-Method", http.MethodPost)
	foreignRes := httptest.NewRecorder()
	handler.ServeHTTP(foreignRes, foreign)
	if foreignRes.Code != http.StatusForbidden {
		t.Fatalf("foreign preflight status = %d", foreignRes.Code)
	}
}
