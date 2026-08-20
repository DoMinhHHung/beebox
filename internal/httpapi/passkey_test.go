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
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/session"
)

const (
	passkeyTestApp  = applicationinstance.PublicID("app_123e4567-e89b-42d3-a456-426614174000")
	passkeyTestUser = identity.PublicID("usr_123e4567-e89b-42d3-a456-426614174001")
	passkeyTestSID  = "ses_123e4567-e89b-42d3-a456-426614174002"
	passkeyTestPKY  = "pky_123e4567-e89b-42d3-a456-426614174003"
	passkeyTestPKA  = "pka_123e4567-e89b-42d3-a456-426614174004"
)

type passkeyApplicationResolverStub struct {
	app applicationinstance.Instance
}

func (s passkeyApplicationResolverStub) ResolvePublishable(_ context.Context, key string) (applicationinstance.Instance, error) {
	if key != "pk_test" {
		return applicationinstance.Instance{}, applicationinstance.ErrNotFound
	}
	return s.app, nil
}

type passkeyOriginPolicyStub struct{}

func (passkeyOriginPolicyStub) IsAllowedOrigin(_ context.Context, appID applicationinstance.InternalID, origin string) (bool, error) {
	return appID == 1 && origin == "https://app.example", nil
}
func (passkeyOriginPolicyStub) AnyAllowedOrigin(_ context.Context, origin string) (bool, error) {
	return origin == "https://app.example", nil
}

type passkeySessionManagementStub struct {
	record session.Record
}

func (s passkeySessionManagementStub) Current(_ context.Context, appID applicationinstance.InternalID, appPublic, token string) (session.Record, error) {
	if appID != 1 || appPublic != string(passkeyTestApp) || token != "access" {
		return session.Record{}, session.ErrSessionNotFound
	}
	return s.record, nil
}
func (passkeySessionManagementStub) SignOut(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error {
	return nil
}
func (passkeySessionManagementStub) GetSession(context.Context, applicationinstance.InternalID, string) (session.Record, error) {
	return session.Record{}, session.ErrSessionNotFound
}
func (passkeySessionManagementStub) RevokeSession(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) error {
	return nil
}

type passkeyHTTPServiceStub struct {
	beginRegistrationCalls   int
	beginAuthenticationCalls int
	listCalls                int
	removeCalls              int
	finishRegistrationCalls  int
	lastSession              authentication.PasskeySession
	lastApp                  applicationinstance.Instance
	lastOrigin               string
	lastID                   string
	err                      error
}

func (s *passkeyHTTPServiceStub) BeginRegistration(_ context.Context, current authentication.PasskeySession, origin string) (authentication.PasskeyBeginResult, error) {
	s.beginRegistrationCalls++
	s.lastSession, s.lastOrigin = current, origin
	if s.err != nil {
		return authentication.PasskeyBeginResult{}, s.err
	}
	return authentication.PasskeyBeginResult{AttemptID: passkeyTestPKA, PublicKey: json.RawMessage(`{"challenge":"opaque"}`), ExpiresIn: 300}, nil
}
func (s *passkeyHTTPServiceStub) FinishRegistration(_ context.Context, current authentication.PasskeySession, origin, attemptID, _ string, _ json.RawMessage, _ audit.CorrelationID) (authentication.PasskeyView, error) {
	s.finishRegistrationCalls++
	s.lastSession, s.lastOrigin, s.lastID = current, origin, attemptID
	if s.err != nil {
		return authentication.PasskeyView{}, s.err
	}
	return authentication.PasskeyView{ID: passkeyTestPKY, CreatedAt: time.Unix(1, 0).UTC()}, nil
}
func (s *passkeyHTTPServiceStub) BeginAuthentication(_ context.Context, app applicationinstance.Instance, origin string) (authentication.PasskeyBeginResult, error) {
	s.beginAuthenticationCalls++
	s.lastApp, s.lastOrigin = app, origin
	if s.err != nil {
		return authentication.PasskeyBeginResult{}, s.err
	}
	return authentication.PasskeyBeginResult{AttemptID: passkeyTestPKA, PublicKey: json.RawMessage(`{"challenge":"opaque"}`), ExpiresIn: 300}, nil
}
func (s *passkeyHTTPServiceStub) List(_ context.Context, current authentication.PasskeySession) ([]authentication.PasskeyView, error) {
	s.listCalls++
	s.lastSession = current
	if s.err != nil {
		return nil, s.err
	}
	return []authentication.PasskeyView{{ID: passkeyTestPKY, Name: "Laptop", CreatedAt: time.Unix(1, 0).UTC()}}, nil
}
func (s *passkeyHTTPServiceStub) Remove(_ context.Context, current authentication.PasskeySession, id string, _ audit.CorrelationID) error {
	s.removeCalls++
	s.lastSession, s.lastID = current, id
	return s.err
}

type passkeyCompletionStub struct {
	calls      int
	lastApp    applicationinstance.Instance
	lastOrigin string
	lastID     string
	err        error
}

func (s *passkeyCompletionStub) CompleteAuthentication(_ context.Context, app applicationinstance.Instance, origin, attemptID string, _ json.RawMessage, _ audit.CorrelationID) (session.TokenPair, error) {
	s.calls++
	s.lastApp, s.lastOrigin, s.lastID = app, origin, attemptID
	if s.err != nil {
		return session.TokenPair{}, s.err
	}
	return session.TokenPair{AccessToken: "new-access", RefreshToken: "refresh", ExpiresIn: 300, SessionID: passkeyTestSID}, nil
}

func passkeyHTTPFixture(t *testing.T, service *passkeyHTTPServiceStub, completion *passkeyCompletionStub) http.Handler {
	t.Helper()
	now := time.Now().UTC()
	app := applicationinstance.Instance{InternalID: 1, PublicID: passkeyTestApp}
	record := session.Record{
		PublicID: passkeyTestSID, UserPublicID: string(passkeyTestUser), UserInternalID: 2,
		ApplicationPublicID: string(passkeyTestApp), ApplicationInstanceID: 1,
		CreatedAt: now.Add(-time.Minute), IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(24 * time.Hour),
	}
	return WithPasskeys(http.NotFoundHandler(), passkeyApplicationResolverStub{app: app}, passkeyOriginPolicyStub{}, passkeySessionManagementStub{record: record}, service, completion)
}

func passkeyRequest(method, path, body string, authenticated bool) *http.Request {
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

func TestPasskeyHTTPRegistrationBindsResolvedApplicationSessionAndOrigin(t *testing.T) {
	service := &passkeyHTTPServiceStub{}
	h := passkeyHTTPFixture(t, service, &passkeyCompletionStub{})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, passkeyRequest(http.MethodPost, "/v1/passkeys/registration/attempts", `{}`, true))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if service.beginRegistrationCalls != 1 || service.lastOrigin != "https://app.example" {
		t.Fatalf("calls=%d origin=%q", service.beginRegistrationCalls, service.lastOrigin)
	}
	if service.lastSession.ApplicationInstanceID != 1 || service.lastSession.ApplicationPublicID != passkeyTestApp || service.lastSession.UserID != 2 || service.lastSession.UserPublicID != passkeyTestUser || service.lastSession.SessionPublicID != passkeyTestSID {
		t.Fatalf("derived session=%+v", service.lastSession)
	}

	for name, mutate := range map[string]func(*http.Request){
		"missing bearer":      func(r *http.Request) { r.Header.Del("Authorization") },
		"wrong app":           func(r *http.Request) { r.Header.Set(PublishableKeyHeader, "pk_other") },
		"wrong origin":        func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"noncanonical origin": func(r *http.Request) { r.Header.Set("Origin", "https://APP.example") },
	} {
		t.Run(name, func(t *testing.T) {
			before := service.beginRegistrationCalls
			req := passkeyRequest(http.MethodPost, "/v1/passkeys/registration/attempts", `{}`, true)
			mutate(req)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code == http.StatusCreated || service.beginRegistrationCalls != before {
				t.Fatalf("status=%d calls before=%d after=%d body=%s", rr.Code, before, service.beginRegistrationCalls, rr.Body.String())
			}
		})
	}
}

func TestPasskeyHTTPAuthenticationBindsApplicationOriginAndRejectsMalformedProofLocator(t *testing.T) {
	service := &passkeyHTTPServiceStub{}
	completion := &passkeyCompletionStub{}
	h := passkeyHTTPFixture(t, service, completion)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, passkeyRequest(http.MethodPost, "/v1/passkeys/authentication/attempts", `{}`, false))
	if rr.Code != http.StatusCreated || service.beginAuthenticationCalls != 1 || service.lastApp.InternalID != 1 || service.lastApp.PublicID != passkeyTestApp || service.lastOrigin != "https://app.example" {
		t.Fatalf("status=%d service=%+v body=%s", rr.Code, service, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, passkeyRequest(http.MethodPost, "/v1/passkeys/authentication/complete", `{"attempt_id":"pka_bad","credential":{"id":"opaque"}}`, false))
	if rr.Code != http.StatusBadRequest || completion.calls != 0 {
		t.Fatalf("malformed status=%d calls=%d body=%s", rr.Code, completion.calls, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, passkeyRequest(http.MethodPost, "/v1/passkeys/authentication/complete", `{"attempt_id":"`+passkeyTestPKA+`","credential":{"id":"opaque"}}`, false))
	if rr.Code != http.StatusOK || completion.calls != 1 || completion.lastID != passkeyTestPKA || completion.lastOrigin != "https://app.example" || completion.lastApp.PublicID != passkeyTestApp {
		t.Fatalf("complete status=%d completion=%+v body=%s", rr.Code, completion, rr.Body.String())
	}
}

func TestPasskeyHTTPListAndRemovalUseCurrentPrincipalAndSafeErrors(t *testing.T) {
	service := &passkeyHTTPServiceStub{}
	h := passkeyHTTPFixture(t, service, &passkeyCompletionStub{})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, passkeyRequest(http.MethodGet, "/v1/passkeys", "", true))
	if rr.Code != http.StatusOK || service.listCalls != 1 || service.lastSession.UserPublicID != passkeyTestUser || strings.Contains(rr.Body.String(), string(passkeyTestUser)) {
		t.Fatalf("list status=%d calls=%d session=%+v body=%s", rr.Code, service.listCalls, service.lastSession, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, passkeyRequest(http.MethodDelete, "/v1/passkeys/pky_bad", "", true))
	if rr.Code != http.StatusBadRequest || service.removeCalls != 0 {
		t.Fatalf("malformed remove status=%d calls=%d", rr.Code, service.removeCalls)
	}

	service.err = authentication.ErrPasskeyReverificationRequired
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, passkeyRequest(http.MethodDelete, "/v1/passkeys/"+passkeyTestPKY, "", true))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"code":"reverification_required"`) {
		t.Fatalf("freshness status=%d body=%s", rr.Code, rr.Body.String())
	}

	service.err = authentication.ErrLastAuthenticationMethod
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, passkeyRequest(http.MethodDelete, "/v1/passkeys/"+passkeyTestPKY, "", true))
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"code":"last_authentication_method"`) {
		t.Fatalf("last-method status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPasskeyHTTPProofFailuresCollapseWithoutInternalDetail(t *testing.T) {
	completion := &passkeyCompletionStub{err: authentication.ErrPasskeyProof}
	h := passkeyHTTPFixture(t, &passkeyHTTPServiceStub{}, completion)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, passkeyRequest(http.MethodPost, "/v1/passkeys/authentication/complete", `{"attempt_id":"`+passkeyTestPKA+`","credential":{"clientDataJSON":"malformed"}}`, false))
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), `"code":"invalid_passkey_proof"`) || strings.Contains(rr.Body.String(), "clientDataJSON") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
