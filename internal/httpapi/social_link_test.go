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
	"github.com/DoMinhHHung/beebox/internal/session"
)

type fakeSocialLinkHTTPSessions struct {
	record      session.Record
	err         error
	currentCall int
	appID       applicationinstance.InternalID
	appPublicID string
	token       string
}

func (f *fakeSocialLinkHTTPSessions) Current(_ context.Context, appID applicationinstance.InternalID, appPublicID, token string) (session.Record, error) {
	f.currentCall++
	f.appID, f.appPublicID, f.token = appID, appPublicID, token
	return f.record, f.err
}
func (*fakeSocialLinkHTTPSessions) SignOut(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error { return nil }
func (*fakeSocialLinkHTTPSessions) GetSession(context.Context, applicationinstance.InternalID, string) (session.Record, error) { return session.Record{}, nil }
func (*fakeSocialLinkHTTPSessions) RevokeSession(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) error { return nil }

type fakeSocialLinkHTTPService struct {
	createCalls int
	current     authentication.SocialLinkSession
	provider    authentication.Provider
	redirect    string
	create      authentication.SocialLinkResult
	createErr   error
	complete    authentication.SocialLinkCallbackResult
	completeErr error
	completeCalls int
	state       string
}

func (f *fakeSocialLinkHTTPService) CreateLinkAttempt(_ context.Context, _ applicationinstance.Instance, current authentication.SocialLinkSession, provider authentication.Provider, redirect string) (authentication.SocialLinkResult, error) {
	f.createCalls++
	f.current, f.provider, f.redirect = current, provider, redirect
	return f.create, f.createErr
}
func (f *fakeSocialLinkHTTPService) CompleteLinkCallback(_ context.Context, _ authentication.Provider, state, _ string, _ bool, _ audit.CorrelationID) (authentication.SocialLinkCallbackResult, error) {
	f.completeCalls++
	f.state = state
	return f.complete, f.completeErr
}

func TestSocialLinkAttemptHTTPBindsAuthenticatedSessionAndRejectsClientPrincipalFields(t *testing.T) {
	appPublicID, _ := applicationinstance.NewPublicID()
	app := applicationinstance.Instance{InternalID: 42, PublicID: appPublicID}
	now := time.Now().UTC()
	sessions := &fakeSocialLinkHTTPSessions{record: session.Record{
		PublicID: "ses_11111111-1111-4111-8111-111111111111", UserInternalID: 77,
		ApplicationInstanceID: app.InternalID, ApplicationPublicID: string(app.PublicID),
		CreatedAt: now.Add(-time.Minute), IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(2*time.Hour),
	}}
	links := &fakeSocialLinkHTTPService{create: authentication.SocialLinkResult{AuthorizationURL: "https://provider.example/authorize", ExpiresIn: 540}}
	handler := WithSocialLinks(http.NotFoundHandler(), &socialHTTPApps{key: "bb_pk_fixture", app: app}, socialHTTPOrigins{appID: app.InternalID, origin: "https://app.example"}, sessions, links)

	req := httptest.NewRequest(http.MethodPost, "/v1/social-links/attempts", strings.NewReader(`{"provider":"github","redirect_url":"https://app.example/link-complete"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "bb_pk_fixture")
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Authorization", "Bearer access-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("status/body=%d %s", res.Code, res.Body.String())
	}
	if sessions.currentCall != 1 || sessions.token != "access-token" || links.createCalls != 1 {
		t.Fatalf("session/link dispatch=%d/%d token=%q", sessions.currentCall, links.createCalls, sessions.token)
	}
	if links.current.UserID != 77 || links.current.PublicID != sessions.record.PublicID || links.current.ApplicationInstanceID != app.InternalID {
		t.Fatalf("link principal=%#v", links.current)
	}
	if got := res.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control=%q", got)
	}
	if got := res.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("cors origin=%q", got)
	}
	var payload socialLinkAttemptResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil || payload.ExpiresIn != 540 {
		t.Fatalf("payload=%#v err=%v", payload, err)
	}

	links.createCalls = 0
	req = httptest.NewRequest(http.MethodPost, "/v1/social-links/attempts", strings.NewReader(`{"provider":"github","redirect_url":"https://app.example/link-complete","user_id":"usr_attacker"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PublishableKeyHeader, "bb_pk_fixture")
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Authorization", "Bearer access-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || links.createCalls != 0 {
		t.Fatalf("unknown principal field status=%d calls=%d body=%s", res.Code, links.createCalls, res.Body.String())
	}
}

func TestSocialLinkCallbackRoutingDoesNotUseCallbackSessionOrUntrustedRedirect(t *testing.T) {
	links := &fakeSocialLinkHTTPService{complete: authentication.SocialLinkCallbackResult{RedirectURL: "https://app.example/link-complete"}}
	baseCalls := 0
	base := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { baseCalls++; w.WriteHeader(http.StatusTeapot) })
	handler := WithSocialLinks(base, nil, nil, nil, links)

	req := httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state=lnk_fixture&code=ok&user_id=attacker&session_id=other&redirect_url=https://evil.example", nil)
	req.Header.Set("Authorization", "Bearer replacement-session")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusSeeOther || links.completeCalls != 1 || baseCalls != 0 {
		t.Fatalf("link callback status=%d link=%d base=%d body=%s", res.Code, links.completeCalls, baseCalls, res.Body.String())
	}
	if got := res.Header().Get("Location"); got != "https://app.example/link-complete?beebox_link=success" {
		t.Fatalf("redirect=%q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/social-auth/callback/github?state=plain-p23-state", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusTeapot || baseCalls != 1 {
		t.Fatalf("normal state was intercepted: status=%d base=%d", res.Code, baseCalls)
	}
}

func TestSocialLinkAttemptMapsFreshnessAndSessionFailures(t *testing.T) {
	appPublicID, _ := applicationinstance.NewPublicID()
	app := applicationinstance.Instance{InternalID: 3, PublicID: appPublicID}
	now := time.Now().UTC()
	baseSession := session.Record{PublicID: "ses_fixture", UserInternalID: 5, ApplicationInstanceID: 3, ApplicationPublicID: string(appPublicID), CreatedAt: now, IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour)}
	for _, tc := range []struct {
		name string
		err error
		want int
		code string
	}{
		{name: "stale", err: authentication.ErrSocialLinkReverificationRequired, want: http.StatusForbidden, code: "reverification_required"},
		{name: "invalid session", err: authentication.ErrSocialLinkInvalidSession, want: http.StatusUnauthorized, code: "invalid_session"},
	}{
		t.Run(tc.name, func(t *testing.T) {
			sessions := &fakeSocialLinkHTTPSessions{record: baseSession}
			links := &fakeSocialLinkHTTPService{createErr: tc.err}
			handler := WithSocialLinks(http.NotFoundHandler(), &socialHTTPApps{key: "pk", app: app}, socialHTTPOrigins{appID: 3, origin: "https://app.example"}, sessions, links)
			req := httptest.NewRequest(http.MethodPost, "/v1/social-links/attempts", strings.NewReader(`{"provider":"github","redirect_url":"https://app.example/link"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(PublishableKeyHeader, "pk")
			req.Header.Set("Origin", "https://app.example")
			req.Header.Set("Authorization", "Bearer token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want || !strings.Contains(res.Body.String(), `"code":"`+tc.code+`"`) {
				t.Fatalf("status/body=%d %s", res.Code, res.Body.String())
			}
		})
	}
}
