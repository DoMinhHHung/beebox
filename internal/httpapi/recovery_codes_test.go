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

type recoveryHTTPServiceStub struct {
	regenerateCalls int
	stateCalls      int
	lastSession     authentication.TOTPSession
	err             error
}

func (s *recoveryHTTPServiceStub) Regenerate(_ context.Context, current authentication.TOTPSession, _ audit.CorrelationID) (authentication.RecoveryCodeSetResult, error) {
	s.regenerateCalls++
	s.lastSession = current
	if s.err != nil {
		return authentication.RecoveryCodeSetResult{}, s.err
	}
	return authentication.RecoveryCodeSetResult{Codes: []string{"01234-56789-ABCDE-FGHJK-MNPQRS"}}, nil
}

func (s *recoveryHTTPServiceStub) State(_ context.Context, current authentication.TOTPSession) (authentication.RecoveryCodeState, error) {
	s.stateCalls++
	s.lastSession = current
	if s.err != nil {
		return authentication.RecoveryCodeState{}, s.err
	}
	return authentication.RecoveryCodeState{Available: true, Remaining: 9}, nil
}

type recoveryCompletionStub struct {
	calls     int
	lastAppID applicationinstance.InternalID
	lastToken string
	lastCode  string
	err       error
}

func (s *recoveryCompletionStub) Complete(_ context.Context, appID applicationinstance.InternalID, token, code string, _ audit.CorrelationID) (session.TokenPair, error) {
	s.calls++
	s.lastAppID, s.lastToken, s.lastCode = appID, token, code
	if s.err != nil {
		return session.TokenPair{}, s.err
	}
	return session.TokenPair{AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 300, SessionID: "ses_123e4567-e89b-42d3-a456-426614174503"}, nil
}

func recoveryHTTPFixture(recovery *recoveryHTTPServiceStub, completion *recoveryCompletionStub) http.Handler {
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
	return WithRecoveryCodes(http.NotFoundHandler(), passkeyApplicationResolverStub{app: app}, passkeyOriginPolicyStub{}, passkeySessionManagementStub{record: record}, recovery, completion)
}

func recoveryRequest(method, path, body string, authenticated bool) *http.Request {
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

func TestRecoveryCodeHTTPRegenerationReturnsCodesOnlyOnceFromService(t *testing.T) {
	recovery := &recoveryHTTPServiceStub{}
	h := recoveryHTTPFixture(recovery, &recoveryCompletionStub{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, recoveryRequest(http.MethodPost, "/v1/mfa/recovery-codes/regenerate", "", true))
	if rr.Code != http.StatusOK || recovery.regenerateCalls != 1 || !strings.Contains(rr.Body.String(), "01234-56789-ABCDE-FGHJK-MNPQRS") {
		t.Fatalf("status=%d calls=%d body=%s", rr.Code, recovery.regenerateCalls, rr.Body.String())
	}
	if recovery.lastSession.ApplicationInstanceID != 1 || recovery.lastSession.UserID != 2 || recovery.lastSession.SessionPublicID != passkeyTestSID {
		t.Fatalf("session=%+v", recovery.lastSession)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, recoveryRequest(http.MethodGet, "/v1/mfa/recovery-codes", "", true))
	if rr.Code != http.StatusOK || recovery.stateCalls != 1 || !strings.Contains(rr.Body.String(), `"remaining":9`) || strings.Contains(rr.Body.String(), "01234-") {
		t.Fatalf("state status=%d calls=%d body=%s", rr.Code, recovery.stateCalls, rr.Body.String())
	}
}

func TestRecoveryCodeHTTPCompletionUsesPendingAuthorityAndStableErrors(t *testing.T) {
	completion := &recoveryCompletionStub{}
	h := recoveryHTTPFixture(&recoveryHTTPServiceStub{}, completion)
	body := `{"pending_mfa_token":"mfp_123e4567-e89b-42d3-a456-426614174504.secret","code":"01234-56789-ABCDE-FGHJK-MNPQRS"}`
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, recoveryRequest(http.MethodPost, "/v1/mfa/recovery-codes/complete", body, false))
	if rr.Code != http.StatusOK || completion.calls != 1 || completion.lastAppID != 1 || completion.lastCode != "01234-56789-ABCDE-FGHJK-MNPQRS" || !strings.HasPrefix(completion.lastToken, "mfp_") {
		t.Fatalf("status=%d completion=%+v body=%s", rr.Code, completion, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"authenticated"`) || strings.Contains(rr.Body.String(), "pending_mfa_token") {
		t.Fatalf("authenticated result=%s", rr.Body.String())
	}

	completion.err = authentication.ErrRecoveryInvalid
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, recoveryRequest(http.MethodPost, "/v1/mfa/recovery-codes/complete", body, false))
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid_recovery_proof") || strings.Contains(rr.Body.String(), "01234-") {
		t.Fatalf("failure status=%d body=%s", rr.Code, rr.Body.String())
	}
}
