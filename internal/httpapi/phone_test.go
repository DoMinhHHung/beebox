package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type fakePhoneIssuer struct {
	calls int
	phone string
	err   error
}

func (f *fakePhoneIssuer) RequestWithCorrelation(_ context.Context, _ applicationinstance.InternalID, phone string, _ audit.CorrelationID) error {
	f.calls++
	f.phone = phone
	return f.err
}

type fakePhoneConfirmer struct {
	pair session.TokenPair
	err  error
}

func (f *fakePhoneConfirmer) Confirm(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error) {
	return f.pair, f.err
}

func TestPhoneIssueDisabledReturnsUniformUnavailableBeforePhoneService(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	handler := WithPhoneSMS(
		http.NotFoundHandler(),
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID, PublicID: testSessionAppPublicID}},
		fakeOrigins{}, nil, &fakePhoneConfirmer{}, nil, &fakePhoneConfirmer{},
	)
	for _, path := range []string{"/v1/sign-ups/phone", "/v1/sign-ins/phone-otp"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"phone":"+84901234567"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(PublishableKeyHeader, "key")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), `"code":"service_unavailable"`) {
			t.Fatalf("%s status/body = %d %s", path, res.Code, res.Body.String())
		}
	}
}

func TestPhoneIssueCollapsesProviderFailureAndRejectsInvalidPhone(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{name: "provider failure generic", err: authentication.ErrPhoneSignupDelivery, want: http.StatusAccepted},
		{name: "invalid phone", err: identity.ErrInvalidPhone, want: http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &fakePhoneIssuer{err: tc.err}
			handler := WithPhoneSMS(
				http.NotFoundHandler(),
				fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID, PublicID: testSessionAppPublicID}},
				fakeOrigins{}, issuer, &fakePhoneConfirmer{}, issuer, &fakePhoneConfirmer{},
			)
			req := httptest.NewRequest(http.MethodPost, "/v1/sign-ups/phone", strings.NewReader(`{"phone":"+84901234567"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(PublishableKeyHeader, "key")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want {
				t.Fatalf("status/body = %d %s", res.Code, res.Body.String())
			}
			if issuer.calls != 1 || issuer.phone != "+84901234567" {
				t.Fatalf("issuer calls=%d phone=%q", issuer.calls, issuer.phone)
			}
		})
	}
}

func TestPhoneConfirmBrowserAndNonBrowserReuseSessionTransport(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	pair := session.TokenPair{
		AccessToken: "access", RefreshToken: "refresh-fixture", ExpiresIn: 300,
		SessionID: "ses_21234567-89ab-4cde-8fab-0123456789ab",
	}
	for _, tc := range []struct {
		name   string
		origin string
	}{
		{name: "browser", origin: "https://app.example"},
		{name: "non-browser"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := WithPhoneSMS(
				http.NotFoundHandler(),
				fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID, PublicID: testSessionAppPublicID}},
				fakeOrigins{appID: appID, origin: "https://app.example"},
				&fakePhoneIssuer{}, &fakePhoneConfirmer{pair: pair}, &fakePhoneIssuer{}, &fakePhoneConfirmer{pair: pair},
			)
			req := httptest.NewRequest(http.MethodPost, "/v1/sign-ups/phone/confirm", strings.NewReader(`{"phone":"+84901234567","code":"123456"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(PublishableKeyHeader, "key")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("status/body = %d %s", res.Code, res.Body.String())
			}
			if tc.origin != "" {
				if strings.Contains(res.Body.String(), pair.RefreshToken) {
					t.Fatal("browser response leaked refresh token")
				}
				cookies := res.Result().Cookies()
				if len(cookies) != 1 || cookies[0].Name != refreshCookieName(testSessionAppPublicID) || cookies[0].Value != pair.RefreshToken || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" {
					t.Fatalf("refresh cookie = %#v", cookies)
				}
			} else if !strings.Contains(res.Body.String(), `"refresh_token":"refresh-fixture"`) {
				t.Fatalf("non-browser body = %s", res.Body.String())
			}
		})
	}
}
