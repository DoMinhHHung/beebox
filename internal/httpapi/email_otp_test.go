package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type fakeEmailOTPIssuer struct {
	err   error
	email string
}

func (f *fakeEmailOTPIssuer) RequestWithCorrelation(_ context.Context, _ applicationinstance.InternalID, email string, _ audit.CorrelationID) error {
	f.email = email
	return f.err
}

type fakeEmailOTPConfirmer struct {
	pair session.TokenPair
	err  error
}

func (f *fakeEmailOTPConfirmer) Confirm(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error) {
	return f.pair, f.err
}

func TestEmailOTPIssueCollapsesAccountDependentDeliveryFailure(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	issuer := &fakeEmailOTPIssuer{err: authentication.ErrEmailOTPDelivery}
	handler := WithEmailOTP(
		http.NotFoundHandler(),
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID, PublicID: testSessionAppPublicID}},
		fakeOrigins{appID: appID, origin: "https://app.example"},
		issuer,
		&fakeEmailOTPConfirmer{},
	)
	req := httptest.NewRequest(http.MethodPost, "/v1/sign-ins/email-otp", strings.NewReader(`{"email":"user@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "key")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted || res.Body.String() != "{\"status\":\"accepted\"}\n" {
		t.Fatalf("status/body = %d %s", res.Code, res.Body.String())
	}
	if issuer.email != "user@example.com" {
		t.Fatalf("issuer email = %q", issuer.email)
	}
	if res.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control = %q", res.Header().Get("Cache-Control"))
	}
}

func TestEmailOTPConfirmBrowserUsesRefreshCookie(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	confirmer := &fakeEmailOTPConfirmer{pair: session.TokenPair{
		AccessToken: "access", RefreshToken: "refresh-secret", ExpiresIn: 300,
		SessionID: "ses_21234567-89ab-4cde-8fab-0123456789ab",
	}}
	handler := WithEmailOTP(
		http.NotFoundHandler(),
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID, PublicID: testSessionAppPublicID}},
		fakeOrigins{appID: appID, origin: "https://app.example"},
		&fakeEmailOTPIssuer{}, confirmer,
	)
	req := httptest.NewRequest(http.MethodPost, "/v1/sign-ins/email-otp/confirm", strings.NewReader(`{"email":"user@example.com","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "key")
	req.Header.Set("Origin", "https://app.example")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "refresh-secret") {
		t.Fatal("browser response leaked refresh token")
	}
	cookies := res.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != refreshCookieName(testSessionAppPublicID) || cookies[0].Value != "refresh-secret" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" {
		t.Fatalf("refresh cookie = %#v", cookies)
	}
}

func TestEmailOTPConfirmNonBrowserReturnsRefreshToken(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	confirmer := &fakeEmailOTPConfirmer{pair: session.TokenPair{
		AccessToken: "access", RefreshToken: "refresh-secret", ExpiresIn: 300,
		SessionID: "ses_21234567-89ab-4cde-8fab-0123456789ab",
	}}
	handler := WithEmailOTP(
		http.NotFoundHandler(),
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID, PublicID: testSessionAppPublicID}},
		fakeOrigins{}, &fakeEmailOTPIssuer{}, confirmer,
	)
	req := httptest.NewRequest(http.MethodPost, "/v1/sign-ins/email-otp/confirm", strings.NewReader(`{"email":"user@example.com","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "key")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"refresh_token":"refresh-secret"`) {
		t.Fatalf("status/body = %d %s", res.Code, res.Body.String())
	}
}

func TestEmailOTPConfirmCollapsesCredentialState(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	for _, err := range []error{session.ErrInvalidCredentials, errors.New("wrapped: invalid credentials")} {
		if err != session.ErrInvalidCredentials {
			err = session.ErrInvalidCredentials
		}
		confirmer := &fakeEmailOTPConfirmer{err: err}
		handler := WithEmailOTP(http.NotFoundHandler(), fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID, PublicID: testSessionAppPublicID}}, fakeOrigins{}, &fakeEmailOTPIssuer{}, confirmer)
		req := httptest.NewRequest(http.MethodPost, "/v1/sign-ins/email-otp/confirm", strings.NewReader(`{"email":"unknown@example.com","code":"000000"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(PublishableKeyHeader, "key")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), `"code":"invalid_credentials"`) {
			t.Fatalf("status/body = %d %s", res.Code, res.Body.String())
		}
	}
}
