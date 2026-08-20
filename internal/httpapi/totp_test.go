package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type totpHTTPServiceStub struct {
	startCalls   int
	confirmCalls int
	currentCalls int
	removeCalls  int
	lastSession  authentication.TOTPSession
	lastID       string
	lastCode     string
	err          error
}

func (s *totpHTTPServiceStub) StartEnrollment(_ context.Context, current authentication.TOTPSession, _ audit.CorrelationID) (authentication.TOTPEnrollmentResult, error) {
	s.startCalls++
	s.lastSession = current
	if s.err != nil {
		return authentication.TOTPEnrollmentResult{}, s.err
	}
	return authentication.TOTPEnrollmentResult{
		EnrollmentID: "mfe_123e4567-e89b-42d3-a456-426614174501",
		Secret:       "SETUPSECRET",
		OTPAuthURI:   "otpauth://totp/BeeBox:test",
		ExpiresIn:    600,
	}, nil
}

func (s *totpHTTPServiceStub) ConfirmEnrollment(_ context.Context, current authentication.TOTPSession, id, code string, _ audit.CorrelationID) (authentication.TOTPCredentialView, error) {
	s.confirmCalls++
	s.lastSession, s.lastID, s.lastCode = current, id, code
	if s.err != nil {
		return authentication.TOTPCredentialView{}, s.err
	}
	return authentication.TOTPCredentialView{ID: "mfc_123e4567-e89b-42d3-a456-426614174502", CreatedAt: time.Unix(1, 0).UTC()}, nil
}

func (s *totpHTTPServiceStub) Current(_ context.Context, current authentication.TOTPSession) (authentication.TOTPCredentialView, error) {
	s.currentCalls++
	s.lastSession = current
	if s.err != nil {
		return authentication.TOTPCredentialView{}, s.err
	}
	return authentication.TOTPCredentialView{ID: "mfc_123e4567-e89b-42d3-a456-426614174502", CreatedAt: time.Unix(1, 0).UTC()}, nil
}

func (s *totpHTTPServiceStub) Remove(_ context.Context, current authentication.TOTPSession, _ audit.CorrelationID) error {
	s.removeCalls++
	s.lastSession = current
	return s.err
}

type totpCompletionStub struct {
	calls     int
	lastAppID applicationinstance.InternalID
	lastToken string
	lastCode  string
	err       error
}

func (s *totpCompletionStub) Complete(_ context.Context, appID applicationinstance.InternalID, token, code string, _ audit.CorrelationID) (session.TokenPair, error) {
	s.calls++
	s.lastAppID, s.lastToken, s.lastCode = appID, token, code
	if s.err != nil {
		return session.TokenPair{}, s.err
	}
	return session.TokenPair{
		AccessToken:  "access-new",
		RefreshToken: "refresh-new",
		ExpiresIn:    300,
		SessionID:    "ses_123e4567-e89b-42d3-a456-426614174503",
	}, nil
}

func totpHTTPFixture(service *totpHTTPServiceStub, completion *totpCompletionStub) http.Handler {
	now := time.Now().UTC()
	app := applicationinstance.Instance{InternalID: 1, PublicID: passkeyTestApp}
	record := session.Record{
		PublicID:              passkeyTestSID,
		UserPublicID:          string(passkeyTestUser),
		UserInternalID:        2,
		ApplicationPublicID:   string(passkeyTestApp),
		ApplicationInstanceID: 1,
		CreatedAt:             now.Add(-time.Minute),
		IdleExpiresAt:         now.Add(time.Hour),
		ExpiresAt:             now.Add(24 * time.Hour),
	}
	return WithTOTP(
		http.NotFoundHandler(),
		passkeyApplicationResolverStub{app: app},
		passkeyOriginPolicyStub{},
		passkeySessionManagementStub{record: record},
		service,
		completion,
	)
}

func totpRequest(method, path, body string, authenticated bool) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(PublishableKeyHeader, "pk_test")
	req.Header.Set("Origin", "https://app.example")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		req.Header.Set("Authorization", "Bearer access")
	}
	return req
}

func TestTOTPHTTPEnrollmentUsesResolvedApplicationAndCurrentSession(t *testing.T) {
	service := &totpHTTPServiceStub{}
	h := totpHTTPFixture(service, &totpCompletionStub{})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, totpRequest(http.MethodPost, "/v1/mfa/totp/enrollments", "", true))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control=%q", rr.Header().Get("Cache-Control"))
	}
	if service.startCalls != 1 || service.lastSession.ApplicationInstanceID != 1 || service.lastSession.ApplicationPublicID != passkeyTestApp || service.lastSession.UserID != 2 || service.lastSession.UserPublicID != passkeyTestUser || service.lastSession.SessionPublicID != passkeyTestSID {
		t.Fatalf("calls=%d session=%+v", service.startCalls, service.lastSession)
	}
	if !strings.Contains(rr.Body.String(), "SETUPSECRET") || !strings.Contains(rr.Body.String(), "otpauth://") {
		t.Fatalf("one-time setup response=%s", rr.Body.String())
	}

	for name, mutate := range map[string]func(*http.Request){
		"missing session": func(r *http.Request) { r.Header.Del("Authorization") },
		"wrong app":       func(r *http.Request) { r.Header.Set(PublishableKeyHeader, "pk_other") },
		"wrong origin":    func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
	} {
		t.Run(name, func(t *testing.T) {
			before := service.startCalls
			req := totpRequest(http.MethodPost, "/v1/mfa/totp/enrollments", "", true)
			mutate(req)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code == http.StatusCreated || service.startCalls != before {
				t.Fatalf("status=%d calls before=%d after=%d body=%s", rr.Code, before, service.startCalls, rr.Body.String())
			}
		})
	}
}

func TestTOTPHTTPPendingCompletionUsesPendingAuthorityNotBearerSession(t *testing.T) {
	completion := &totpCompletionStub{}
	h := totpHTTPFixture(&totpHTTPServiceStub{}, completion)
	body := `{"pending_mfa_token":"mfp_123e4567-e89b-42d3-a456-426614174504.token","code":"123456"}`

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, totpRequest(http.MethodPost, "/v1/mfa/totp/complete", body, false))
	if rr.Code != http.StatusOK || completion.calls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", rr.Code, completion.calls, rr.Body.String())
	}
	if completion.lastAppID != 1 || completion.lastCode != "123456" || !strings.HasPrefix(completion.lastToken, "mfp_") {
		t.Fatalf("completion=%+v", completion)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control=%q", rr.Header().Get("Cache-Control"))
	}

	for name, mutate := range map[string]func(*http.Request){
		"wrong app":      func(r *http.Request) { r.Header.Set(PublishableKeyHeader, "pk_other") },
		"wrong origin":   func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"missing origin": func(r *http.Request) { r.Header.Del("Origin") },
	} {
		t.Run(name, func(t *testing.T) {
			before := completion.calls
			req := totpRequest(http.MethodPost, "/v1/mfa/totp/complete", body, false)
			mutate(req)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code == http.StatusOK || completion.calls != before {
				t.Fatalf("status=%d calls before=%d after=%d body=%s", rr.Code, before, completion.calls, rr.Body.String())
			}
		})
	}
}

func TestTOTPHTTPStateAndRemovalUseSafeStableErrors(t *testing.T) {
	service := &totpHTTPServiceStub{err: authentication.ErrTOTPEnrollmentInvalid}
	h := totpHTTPFixture(service, &totpCompletionStub{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, totpRequest(http.MethodGet, "/v1/mfa/totp", "", true))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Fatalf("state status=%d body=%s", rr.Code, rr.Body.String())
	}

	service.err = authentication.ErrTOTPReverificationRequired
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, totpRequest(http.MethodDelete, "/v1/mfa/totp", "", true))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "reverification_required") {
		t.Fatalf("remove status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "SETUPSECRET") || strings.Contains(rr.Body.String(), "123456") {
		t.Fatalf("sensitive value leaked: %s", rr.Body.String())
	}
}
