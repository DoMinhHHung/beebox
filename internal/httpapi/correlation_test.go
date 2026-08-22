package httpapi

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/requestcorrelation"
)

func correlationTestKey(t *testing.T) requestcorrelation.Key {
	t.Helper()
	value := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	key, err := requestcorrelation.LoadKey(func(name string) (string, bool) {
		if name == requestcorrelation.KeyEnvironmentVariable {
			return value, true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newCorrelationSignupHandler(t *testing.T, signup *fakeSignup) http.Handler {
	t.Helper()
	appID := applicationinstance.InternalID(42)
	base := New(
		http.NotFoundHandler(),
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID}},
		fakeOrigins{appID: appID, origin: "https://app.example"},
		signup,
		&fakeVerification{},
	)
	return WithTrustedRequestCorrelation(base, correlationTestKey(t))
}

func correlationSignupRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/sign-ups", strings.NewReader(`{"email":"user@example.com","password":"correct horse battery staple"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "key")
	req.Header.Set(IdempotencyKeyHeader, "correlation-test")
	req.Header.Set("Origin", "https://app.example")
	return req
}

func TestAuthenticatedGatewayCorrelationBecomesAuditCorrelation(t *testing.T) {
	const requestID = "00112233445566778899aabbccddeeff"
	signup := &fakeSignup{}
	handler := newCorrelationSignupHandler(t, signup)
	key := correlationTestKey(t)
	id, ok := requestcorrelation.ParseID(requestID)
	if !ok {
		t.Fatal("parse request ID")
	}
	req := correlationSignupRequest()
	req.Header.Set(RequestIDHeader, "client-selected-value")
	req.Header.Set(requestcorrelation.InternalIDHeader, requestID)
	req.Header.Set(requestcorrelation.InternalSignatureHeader, requestcorrelation.Sign(key, id))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	if values := res.Header().Values(RequestIDHeader); len(values) != 1 || values[0] != requestID {
		t.Fatalf("response request IDs = %#v want exactly %q", values, requestID)
	}
	if got := hex.EncodeToString(signup.correlation[:]); got != requestID {
		t.Fatalf("audit correlation = %q want trusted gateway correlation %q", got, requestID)
	}
}

func TestDirectIdentityValidLookingRequestIDIsNotAuditAuthority(t *testing.T) {
	const supplied = "00112233445566778899aabbccddeeff"
	signup := &fakeSignup{}
	handler := newCorrelationSignupHandler(t, signup)
	req := correlationSignupRequest()
	req.Header.Set(RequestIDHeader, supplied)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	values := res.Header().Values(RequestIDHeader)
	if len(values) != 1 || len(values[0]) != 32 || values[0] == supplied {
		t.Fatalf("direct caller selected request ID: %#v", values)
	}
	if got := hex.EncodeToString(signup.correlation[:]); got != values[0] {
		t.Fatalf("audit correlation = %q response request ID = %q", got, values[0])
	}
}

func TestInvalidInternalCorrelationSignatureFallsBackToFreshCorrelation(t *testing.T) {
	const supplied = "00112233445566778899aabbccddeeff"
	signup := &fakeSignup{}
	handler := newCorrelationSignupHandler(t, signup)
	req := correlationSignupRequest()
	req.Header.Set(RequestIDHeader, supplied)
	req.Header.Set(requestcorrelation.InternalIDHeader, supplied)
	req.Header.Set(requestcorrelation.InternalSignatureHeader, "invalid-signature")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	values := res.Header().Values(RequestIDHeader)
	if len(values) != 1 || len(values[0]) != 32 || values[0] == supplied {
		t.Fatalf("invalid provenance was accepted: %#v", values)
	}
	if got := hex.EncodeToString(signup.correlation[:]); got != values[0] {
		t.Fatalf("audit correlation = %q response request ID = %q", got, values[0])
	}
}
