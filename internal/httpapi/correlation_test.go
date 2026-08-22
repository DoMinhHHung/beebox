package httpapi

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

func TestCanonicalGatewayRequestIDBecomesAuditCorrelation(t *testing.T) {
	const requestID = "00112233445566778899aabbccddeeff"
	appID := applicationinstance.InternalID(42)
	signup := &fakeSignup{}
	handler := New(
		http.NotFoundHandler(),
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID}},
		fakeOrigins{appID: appID, origin: "https://app.example"},
		signup,
		&fakeVerification{},
	)
	req := httptest.NewRequest(http.MethodPost, "/v1/sign-ups", strings.NewReader(`{"email":"user@example.com","password":"correct horse battery staple"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "key")
	req.Header.Set(IdempotencyKeyHeader, "gateway-correlation")
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set(RequestIDHeader, requestID)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	if got := res.Header().Get(RequestIDHeader); got != requestID {
		t.Fatalf("response request ID = %q want %q", got, requestID)
	}
	if got := hex.EncodeToString(signup.correlation[:]); got != requestID {
		t.Fatalf("audit correlation = %q want gateway request ID %q", got, requestID)
	}
}

func TestNonCanonicalInboundRequestIDIsNotAuditCorrelation(t *testing.T) {
	const supplied = "client-readable-request"
	appID := applicationinstance.InternalID(42)
	signup := &fakeSignup{}
	handler := New(
		http.NotFoundHandler(),
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID}},
		fakeOrigins{appID: appID},
		signup,
		&fakeVerification{},
	)
	req := httptest.NewRequest(http.MethodPost, "/v1/sign-ups", strings.NewReader(`{"email":"user@example.com","password":"correct horse battery staple"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "key")
	req.Header.Set(IdempotencyKeyHeader, "direct-correlation")
	req.Header.Set(RequestIDHeader, supplied)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	if got := res.Header().Get(RequestIDHeader); got == supplied || len(got) != 32 {
		t.Fatalf("response request ID = %q; direct noncanonical input should be replaced", got)
	}
	if got := hex.EncodeToString(signup.correlation[:]); got == supplied || got != res.Header().Get(RequestIDHeader) {
		t.Fatalf("audit correlation = %q response=%q", got, res.Header().Get(RequestIDHeader))
	}
}
