package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/session"
)

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

func TestBrowserSignInReturnsHostRefreshCookie(t *testing.T) {
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
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID}},
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
	if cookie.Name != refreshCookieName || cookie.Value != "refresh-secret" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("refresh cookie = %#v", cookie)
	}
	if strings.Contains(res.Body.String(), "refresh-secret") {
		t.Fatal("browser token response exposed refresh credential in JSON")
	}
}

func TestCookieRefreshRequiresExactOrigin(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	sessions := &fakeSessions{refreshPair: session.TokenPair{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		ExpiresIn:    300,
		SessionID:    "ses_21234567-89ab-4cde-8fab-0123456789ab",
	}}
	base := New(http.NotFoundHandler(), fakeApps{}, fakeOrigins{}, nil, nil)
	handler := WithSessions(
		base,
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID}},
		fakeOrigins{appID: appID, origin: "https://app.example"},
		sessions,
		nil,
	)

	missingOrigin := httptest.NewRequest(http.MethodPost, "/v1/sessions/refresh", nil)
	missingOrigin.Header.Set(PublishableKeyHeader, "key")
	missingOrigin.AddCookie(&http.Cookie{Name: refreshCookieName, Value: "old-refresh"})
	missingOriginRes := httptest.NewRecorder()
	handler.ServeHTTP(missingOriginRes, missingOrigin)
	if missingOriginRes.Code != http.StatusForbidden {
		t.Fatalf("missing-origin refresh status = %d", missingOriginRes.Code)
	}

	allowed := httptest.NewRequest(http.MethodPost, "/v1/sessions/refresh", nil)
	allowed.Header.Set(PublishableKeyHeader, "key")
	allowed.Header.Set("Origin", "https://app.example")
	allowed.AddCookie(&http.Cookie{Name: refreshCookieName, Value: "old-refresh"})
	allowedRes := httptest.NewRecorder()
	handler.ServeHTTP(allowedRes, allowed)
	if allowedRes.Code != http.StatusOK {
		t.Fatalf("allowed refresh status = %d body=%s", allowedRes.Code, allowedRes.Body.String())
	}
	if sessions.refreshValue != "old-refresh" {
		t.Fatalf("refresh value = %q", sessions.refreshValue)
	}
}
