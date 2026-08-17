package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

type fakeApps struct {
	key string
	app applicationinstance.Instance
}

func (f fakeApps) ResolvePublishable(_ context.Context, key string) (applicationinstance.Instance, error) {
	if key != f.key {
		return applicationinstance.Instance{}, applicationinstance.ErrCredentialNotFound
	}
	return f.app, nil
}

type fakeOrigins struct {
	appID  applicationinstance.InternalID
	origin string
}

func (f fakeOrigins) IsAllowedOrigin(_ context.Context, appID applicationinstance.InternalID, origin string) (bool, error) {
	return appID == f.appID && origin == f.origin, nil
}

func (f fakeOrigins) AnyAllowedOrigin(_ context.Context, origin string) (bool, error) {
	return origin == f.origin, nil
}

type fakeSignup struct {
	appID applicationinstance.InternalID
	email string
	password string
	key string
	err error
}

func (f *fakeSignup) SignUp(_ context.Context, appID applicationinstance.InternalID, email, password, key string) error {
	f.appID, f.email, f.password, f.key = appID, email, password, key
	return f.err
}

type fakeVerification struct {
	requestErr error
	confirmErr error
}

func (f fakeVerification) Request(context.Context, applicationinstance.InternalID, string) error { return f.requestErr }
func (f fakeVerification) Confirm(context.Context, applicationinstance.InternalID, string, string) error { return f.confirmErr }

func TestSignUpBoundaryScopesApplicationOriginAndIdempotency(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	signup := &fakeSignup{}
	handler := New(http.NotFoundHandler(), fakeApps{key: "bb_pk_test", app: applicationinstance.Instance{InternalID: appID}}, fakeOrigins{appID: appID, origin: "https://app.example"}, signup, fakeVerification{})
	req := httptest.NewRequest(http.MethodPost, "/v1/sign-ups", strings.NewReader(`{"email":"user@example.com","password":"correct horse battery staple"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "bb_pk_test")
	req.Header.Set(IdempotencyKeyHeader, "signup-1")
	req.Header.Set("Origin", "https://app.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if signup.appID != appID || signup.key != "signup-1" {
		t.Fatalf("signup scope/key = %d/%q", signup.appID, signup.key)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("auth response omitted no-store")
	}
	if response.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatal("exact allowed origin was not reflected")
	}
	if response.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatal("credentialed CORS used wildcard")
	}
}

func TestSignUpRejectsForeignOriginAndUnknownJSONField(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	handler := New(http.NotFoundHandler(), fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID}}, fakeOrigins{appID: appID, origin: "https://good.example"}, &fakeSignup{}, fakeVerification{})
	foreign := httptest.NewRequest(http.MethodPost, "/v1/sign-ups", strings.NewReader(`{"email":"a@example.com","password":"correct horse battery staple"}`))
	foreign.Header.Set("Content-Type", "application/json")
	foreign.Header.Set(PublishableKeyHeader, "key")
	foreign.Header.Set(IdempotencyKeyHeader, "k")
	foreign.Header.Set("Origin", "https://evil.example")
	foreignResponse := httptest.NewRecorder()
	handler.ServeHTTP(foreignResponse, foreign)
	if foreignResponse.Code != http.StatusForbidden {
		t.Fatalf("foreign origin status = %d", foreignResponse.Code)
	}

	unknown := httptest.NewRequest(http.MethodPost, "/v1/sign-ups", strings.NewReader(`{"email":"a@example.com","password":"correct horse battery staple","admin":true}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknown.Header.Set(PublishableKeyHeader, "key")
	unknown.Header.Set(IdempotencyKeyHeader, "k2")
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", unknownResponse.Code)
	}
}

func TestSignUpMapsIdempotencyConflictAndDeliveryFailureSafely(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	for _, tc := range []struct {
		err error
		status int
		code string
	}{
		{errors.New("wrapped: "+"public idempotency conflict"), http.StatusServiceUnavailable, "service_unavailable"},
	} {
		signup := &fakeSignup{err: tc.err}
		handler := New(http.NotFoundHandler(), fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID}}, fakeOrigins{appID: appID}, signup, fakeVerification{})
		req := httptest.NewRequest(http.MethodPost, "/v1/sign-ups", strings.NewReader(`{"email":"a@example.com","password":"correct horse battery staple"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(PublishableKeyHeader, "key")
		req.Header.Set(IdempotencyKeyHeader, "k")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != tc.status || !strings.Contains(res.Body.String(), tc.code) {
			t.Fatalf("status/body = %d %s", res.Code, res.Body.String())
		}
	}
}

func TestPreflightRequiresStoredExactOrigin(t *testing.T) {
	appID := applicationinstance.InternalID(1)
	handler := New(http.NotFoundHandler(), fakeApps{}, fakeOrigins{appID: appID, origin: "https://app.example"}, &fakeSignup{}, fakeVerification{})
	req := httptest.NewRequest(http.MethodOptions, "/v1/sign-ups", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d body=%s", res.Code, res.Body.String())
	}
	if res.Header().Get("Vary") != "Origin" {
		t.Fatalf("Vary = %q", res.Header().Get("Vary"))
	}
}
