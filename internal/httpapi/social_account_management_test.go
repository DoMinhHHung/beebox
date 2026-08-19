package httpapi

import (
	"context"
	"encoding/json"
	"errors"
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

type fakeSocialAccountHTTPService struct {
	page        authentication.SocialAccountPage
	listErr     error
	listCalls   int
	listCurrent authentication.SocialAccountSession
	listLimit   int
	listCursor  string
	unlinkErr   error
	unlinkCalls int
	unlinkID    string
}

func (f *fakeSocialAccountHTTPService) List(_ context.Context, current authentication.SocialAccountSession, limit int, cursor string) (authentication.SocialAccountPage, error) {
	f.listCalls++
	f.listCurrent, f.listLimit, f.listCursor = current, limit, cursor
	return f.page, f.listErr
}

func (f *fakeSocialAccountHTTPService) Unlink(_ context.Context, _ authentication.SocialAccountSession, id string, _ audit.CorrelationID) error {
	f.unlinkCalls++
	f.unlinkID = id
	return f.unlinkErr
}

func TestSocialAccountManagementHTTPListUsesAuthenticatedPrincipalAndMinimizedModel(t *testing.T) {
	appPublicID, _ := applicationinstance.NewPublicID()
	app := applicationinstance.Instance{InternalID: 42, PublicID: appPublicID}
	now := time.Now().UTC()
	sessions := &fakeSocialLinkHTTPSessions{record: session.Record{
		PublicID: "ses_11111111-1111-4111-8111-111111111111", UserInternalID: 77,
		ApplicationInstanceID: app.InternalID, ApplicationPublicID: string(app.PublicID),
		CreatedAt: now.Add(-30 * time.Minute), IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour),
	}}
	management := &fakeSocialAccountHTTPService{page: authentication.SocialAccountPage{
		Items: []authentication.LinkedSocialAccount{{PublicID: "sli_123e4567-e89b-42d3-a456-426614174000", Provider: authentication.ProviderGitHub, CreatedAt: now}},
		NextCursor: "opaque-cursor",
	}}
	handler := WithSocialAccountManagement(http.NotFoundHandler(), &socialHTTPApps{key: "pk", app: app}, socialHTTPOrigins{appID: app.InternalID, origin: "https://app.example"}, sessions, management)
	req := httptest.NewRequest(http.MethodGet, "/v1/social-links?limit=20", nil)
	setSocialAccountAuthHeaders(req, "pk", "https://app.example", "access-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status/body=%d %s", res.Code, res.Body.String())
	}
	if management.listCalls != 1 || management.listCurrent.UserID != 77 || management.listLimit != 20 || sessions.token != "access-token" {
		t.Fatalf("list/session calls=%d current=%#v limit=%d token=%q", management.listCalls, management.listCurrent, management.listLimit, sessions.token)
	}
	if res.Header().Get("Cache-Control") != "no-store" || res.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("security headers=%v", res.Header())
	}
	var payload map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	body := res.Body.String()
	for _, forbidden := range []string{"provider_subject", "user_id", "internal_id", "access_token", "refresh_token", "profile", "email"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}
	if payload["next_cursor"] != "opaque-cursor" {
		t.Fatalf("payload=%v", payload)
	}
}

func TestSocialAccountManagementHTTPRejectsTrustBoundaryAmbiguity(t *testing.T) {
	appPublicID, _ := applicationinstance.NewPublicID()
	app := applicationinstance.Instance{InternalID: 2, PublicID: appPublicID}
	now := time.Now().UTC()
	sessions := &fakeSocialLinkHTTPSessions{record: session.Record{PublicID: "ses_fixture", UserInternalID: 3, ApplicationInstanceID: 2, ApplicationPublicID: string(app.PublicID), CreatedAt: now, IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour)}}
	for _, tc := range []struct {
		name string
		set  func(*http.Request)
		want int
	}{
		{name: "missing key", set: func(r *http.Request) { r.Header.Del(PublishableKeyHeader) }, want: http.StatusUnauthorized},
		{name: "duplicate key", set: func(r *http.Request) { r.Header.Add(PublishableKeyHeader, "pk") }, want: http.StatusUnauthorized},
		{name: "missing origin", set: func(r *http.Request) { r.Header.Del("Origin") }, want: http.StatusForbidden},
		{name: "duplicate origin", set: func(r *http.Request) { r.Header.Add("Origin", "https://app.example") }, want: http.StatusForbidden},
		{name: "missing bearer", set: func(r *http.Request) { r.Header.Del("Authorization") }, want: http.StatusUnauthorized},
		{name: "duplicate bearer", set: func(r *http.Request) { r.Header.Add("Authorization", "Bearer other") }, want: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			management := &fakeSocialAccountHTTPService{}
			handler := WithSocialAccountManagement(http.NotFoundHandler(), &socialHTTPApps{key: "pk", app: app}, socialHTTPOrigins{appID: 2, origin: "https://app.example"}, sessions, management)
			req := httptest.NewRequest(http.MethodGet, "/v1/social-links", nil)
			setSocialAccountAuthHeaders(req, "pk", "https://app.example", "token")
			tc.set(req)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want || management.listCalls != 0 {
				t.Fatalf("status=%d want=%d list=%d body=%s", res.Code, tc.want, management.listCalls, res.Body.String())
			}
		})
	}
}

func TestSocialAccountManagementHTTPDeleteMapsFreshnessLastMethodAndIdempotentSuccess(t *testing.T) {
	appPublicID, _ := applicationinstance.NewPublicID()
	app := applicationinstance.Instance{InternalID: 2, PublicID: appPublicID}
	now := time.Now().UTC()
	sessions := &fakeSocialLinkHTTPSessions{record: session.Record{PublicID: "ses_fixture", UserInternalID: 3, ApplicationInstanceID: 2, ApplicationPublicID: string(app.PublicID), CreatedAt: now, IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour)}}
	id := "sli_123e4567-e89b-42d3-a456-426614174000"
	for _, tc := range []struct {
		name string
		err  error
		want int
		code string
	}{
		{name: "success or already absent", want: http.StatusNoContent},
		{name: "stale", err: authentication.ErrSocialAccountReverification, want: http.StatusForbidden, code: "reverification_required"},
		{name: "invalid session", err: authentication.ErrSocialAccountInvalidSession, want: http.StatusUnauthorized, code: "invalid_session"},
		{name: "last method", err: authentication.ErrLastAuthenticationMethod, want: http.StatusConflict, code: "last_authentication_method"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			management := &fakeSocialAccountHTTPService{unlinkErr: tc.err}
			handler := WithSocialAccountManagement(http.NotFoundHandler(), &socialHTTPApps{key: "pk", app: app}, socialHTTPOrigins{appID: 2, origin: "https://app.example"}, sessions, management)
			req := httptest.NewRequest(http.MethodDelete, "/v1/social-links/"+id, nil)
			setSocialAccountAuthHeaders(req, "pk", "https://app.example", "token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want || management.unlinkCalls != 1 || management.unlinkID != id {
				t.Fatalf("status=%d want=%d calls=%d id=%q body=%s", res.Code, tc.want, management.unlinkCalls, management.unlinkID, res.Body.String())
			}
			if tc.code != "" && !strings.Contains(res.Body.String(), `"code":"`+tc.code+`"`) {
				t.Fatalf("body=%s", res.Body.String())
			}
		})
	}

	management := &fakeSocialAccountHTTPService{}
	handler := WithSocialAccountManagement(http.NotFoundHandler(), &socialHTTPApps{key: "pk", app: app}, socialHTTPOrigins{appID: 2, origin: "https://app.example"}, sessions, management)
	req := httptest.NewRequest(http.MethodDelete, "/v1/social-links/not-an-id", nil)
	setSocialAccountAuthHeaders(req, "pk", "https://app.example", "token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || management.unlinkCalls != 0 {
		t.Fatalf("malformed id status=%d calls=%d", res.Code, management.unlinkCalls)
	}
}

func TestSocialAccountManagementHTTPPaginationValidation(t *testing.T) {
	appPublicID, _ := applicationinstance.NewPublicID()
	app := applicationinstance.Instance{InternalID: 2, PublicID: appPublicID}
	now := time.Now().UTC()
	sessions := &fakeSocialLinkHTTPSessions{record: session.Record{PublicID: "ses_fixture", UserInternalID: 3, ApplicationInstanceID: 2, ApplicationPublicID: string(app.PublicID), CreatedAt: now, IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour)}}
	management := &fakeSocialAccountHTTPService{listErr: authentication.ErrSocialAccountInvalidRequest}
	handler := WithSocialAccountManagement(http.NotFoundHandler(), &socialHTTPApps{key: "pk", app: app}, socialHTTPOrigins{appID: 2, origin: "https://app.example"}, sessions, management)
	for _, target := range []string{"/v1/social-links?limit=0", "/v1/social-links?limit=101", "/v1/social-links?limit=1&limit=2", "/v1/social-links?cursor=bad"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		setSocialAccountAuthHeaders(req, "pk", "https://app.example", "token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("target=%s status/body=%d %s", target, res.Code, res.Body.String())
		}
	}
}

func setSocialAccountAuthHeaders(req *http.Request, key, origin, token string) {
	req.Header.Set(PublishableKeyHeader, key)
	req.Header.Set("Origin", origin)
	req.Header.Set("Authorization", "Bearer "+token)
}

var _ = errors.Is
