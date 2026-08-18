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
)

func TestVerificationConfirmRateLimitUsesExisting429Contract(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	verification := &fakeVerification{confirmErr: authentication.ErrPublicRateLimited}
	handler := New(
		http.NotFoundHandler(),
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID}},
		fakeOrigins{appID: appID},
		&fakeSignup{},
		verification,
	)
	req := httptest.NewRequest(http.MethodPost, "/v1/email-verifications/confirm", strings.NewReader(`{"email":"user@example.com","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d body=%s, want 429", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"rate_limited"`) {
		t.Fatalf("body = %s, want rate_limited code", response.Body.String())
	}
	if response.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q, want 60", response.Header().Get("Retry-After"))
	}
}

type hardeningResetService struct {
	confirmErr error
}

func (s hardeningResetService) RequestWithCorrelation(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) error {
	return nil
}

func (s hardeningResetService) ConfirmWithCorrelation(context.Context, applicationinstance.InternalID, string, string, string, audit.CorrelationID) error {
	return s.confirmErr
}

func TestPasswordResetConfirmRateLimitUsesExisting429Contract(t *testing.T) {
	appID := applicationinstance.InternalID(42)
	base := New(
		http.NotFoundHandler(),
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID}},
		fakeOrigins{appID: appID},
		&fakeSignup{},
		&fakeVerification{},
	)
	handler := WithPasswordReset(
		base,
		fakeApps{key: "key", app: applicationinstance.Instance{InternalID: appID}},
		fakeOrigins{appID: appID},
		hardeningResetService{confirmErr: authentication.ErrPasswordResetRateLimited},
	)
	req := httptest.NewRequest(http.MethodPost, "/v1/password-resets/confirm", strings.NewReader(`{"email":"user@example.com","code":"12345678","new_password":"correct horse battery staple"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d body=%s, want 429", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"rate_limited"`) {
		t.Fatalf("body = %s, want rate_limited code", response.Body.String())
	}
	if response.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q, want 60", response.Header().Get("Retry-After"))
	}
}
