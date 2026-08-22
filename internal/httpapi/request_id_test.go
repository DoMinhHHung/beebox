package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRepresentativeHTTPWrappersEmitExactlyOneRequestID(t *testing.T) {
	var handler http.Handler = http.NotFoundHandler()
	handler = WithSessions(handler, nil, nil, nil, nil)
	handler = WithEmailOTP(handler, nil, nil, nil, nil)
	handler = WithSessionManagement(handler, nil, nil, nil)
	handler = WithAccountManagement(handler, nil, nil, nil, nil)
	handler = WithPasskeys(handler, nil, nil, nil, nil, nil)
	handler = WithTOTP(handler, nil, nil, nil, nil, nil)
	handler = WithRecoveryCodes(handler, nil, nil, nil, nil, nil)
	handler = WithSocialAuth(handler, nil, nil, nil, nil)
	handler = WithTrustedRequestCorrelation(handler, correlationTestKey(t))

	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "password", method: http.MethodPost, path: "/v1/sign-ins"},
		{name: "email-otp", method: http.MethodPost, path: "/v1/sign-ins/email-otp"},
		{name: "session", method: http.MethodGet, path: "/v1/sessions/current"},
		{name: "account", method: http.MethodGet, path: "/v1/profile"},
		{name: "passkey", method: http.MethodPost, path: "/v1/passkeys/authentication/attempts"},
		{name: "totp", method: http.MethodGet, path: "/v1/mfa/totp"},
		{name: "recovery", method: http.MethodGet, path: "/v1/mfa/recovery-codes"},
		{name: "social", method: http.MethodPost, path: "/v1/social-auth/attempts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			values := res.Header().Values(RequestIDHeader)
			if len(values) != 1 || len(values[0]) != 32 {
				t.Fatalf("request IDs=%#v status=%d body=%s", values, res.Code, res.Body.String())
			}
		})
	}
}
