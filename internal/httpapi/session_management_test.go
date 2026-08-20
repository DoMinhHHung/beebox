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

type managementAppResolver struct {
	publishable string
	secret      string
	app         applicationinstance.Instance
}

func (r managementAppResolver) ResolvePublishable(_ context.Context, key string) (applicationinstance.Instance, error) {
	if key != r.publishable {
		return applicationinstance.Instance{}, errors.New("invalid")
	}
	return r.app, nil
}

func (r managementAppResolver) AuthenticateSecret(_ context.Context, key string) (applicationinstance.Instance, error) {
	if key != r.secret {
		return applicationinstance.Instance{}, errors.New("invalid")
	}
	return r.app, nil
}

type managementSessions struct {
	record             session.Record
	page               session.Page
	revokedSession     string
	revokeOthersCalled bool
	signOutAllCalled   bool
}

func (s *managementSessions) Current(_ context.Context, appID applicationinstance.InternalID, appPublicID, token string) (session.Record, error) {
	if appID != s.record.ApplicationInstanceID || appPublicID != s.record.ApplicationPublicID || token != "access-token" {
		return session.Record{}, session.ErrSessionNotFound
	}
	return s.record, nil
}

func (s *managementSessions) SignOut(_ context.Context, appID applicationinstance.InternalID, appPublicID, token string, _ audit.CorrelationID) error {
	_, err := s.Current(context.Background(), appID, appPublicID, token)
	return err
}

func (s *managementSessions) GetSession(_ context.Context, appID applicationinstance.InternalID, publicID string) (session.Record, error) {
	if appID != s.record.ApplicationInstanceID || publicID != s.record.PublicID {
		return session.Record{}, session.ErrSessionNotFound
	}
	return s.record, nil
}

func (s *managementSessions) RevokeSession(_ context.Context, appID applicationinstance.InternalID, publicID string, _ audit.CorrelationID) error {
	if appID != s.record.ApplicationInstanceID || publicID != s.record.PublicID {
		return session.ErrSessionNotFound
	}
	return nil
}

func (s *managementSessions) ListSessions(_ context.Context, appID applicationinstance.InternalID, appPublicID, token string, limit int, cursor string) (session.Page, error) {
	if _, err := s.Current(context.Background(), appID, appPublicID, token); err != nil {
		return session.Page{}, err
	}
	if limit != 2 || cursor != "cursor" {
		return session.Page{}, session.ErrSessionInvalidRequest
	}
	return s.page, nil
}

func (s *managementSessions) RevokeOwnSession(_ context.Context, appID applicationinstance.InternalID, appPublicID, token, selected string, _ audit.CorrelationID) (bool, error) {
	if _, err := s.Current(context.Background(), appID, appPublicID, token); err != nil {
		return false, err
	}
	s.revokedSession = selected
	return selected == s.record.PublicID, nil
}

func (s *managementSessions) RevokeOtherSessions(_ context.Context, appID applicationinstance.InternalID, appPublicID, token string, _ audit.CorrelationID) error {
	if _, err := s.Current(context.Background(), appID, appPublicID, token); err != nil {
		return err
	}
	s.revokeOthersCalled = true
	return nil
}

func (s *managementSessions) SignOutEverywhere(_ context.Context, appID applicationinstance.InternalID, appPublicID, token string, _ audit.CorrelationID) error {
	if _, err := s.Current(context.Background(), appID, appPublicID, token); err != nil {
		return err
	}
	s.signOutAllCalled = true
	return nil
}

func TestSessionManagementCurrentAndBackendScope(t *testing.T) {
	appPublicID := applicationinstance.PublicID("app_00000000-0000-4000-8000-000000000001")
	record := session.Record{
		PublicID:              "ses_00000000-0000-4000-8000-000000000002",
		UserPublicID:          "usr_00000000-0000-4000-8000-000000000003",
		ApplicationPublicID:   string(appPublicID),
		ApplicationInstanceID: 7,
		CreatedAt:             time.Unix(1, 0),
		ExpiresAt:             time.Unix(2, 0),
	}
	apps := managementAppResolver{publishable: "bb_pk_test", secret: "bb_sk_test.secret", app: applicationinstance.Instance{InternalID: 7, PublicID: appPublicID}}
	handler := WithSessionManagement(http.NotFoundHandler(), apps, apps, &managementSessions{record: record})

	req := httptest.NewRequest(http.MethodGet, "/v1/sessions/current", nil)
	req.Header.Set(PublishableKeyHeader, "bb_pk_test")
	req.Header.Set("Authorization", "Bearer access-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("current status = %d", res.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/backend/sessions/"+record.PublicID, nil)
	req.Header.Set("Authorization", "Bearer bb_sk_test.secret")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("backend status = %d", res.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/backend/sessions/"+record.PublicID, nil)
	req.Header.Set("Authorization", "Bearer bb_sk_wrong.secret")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret status = %d", res.Code)
	}
}

func TestSessionSelfServiceListIsMinimizedAndCurrentMarked(t *testing.T) {
	appPublicID := applicationinstance.PublicID("app_00000000-0000-4000-8000-000000000001")
	now := time.Unix(1700000000, 0).UTC()
	currentID := "ses_00000000-0000-4000-8000-000000000002"
	record := session.Record{PublicID: currentID, ApplicationPublicID: string(appPublicID), ApplicationInstanceID: 7}
	store := &managementSessions{record: record, page: session.Page{Items: []session.SelfServiceRecord{{
		PublicID: currentID, CreatedAt: now, LastSeenAt: now.Add(time.Minute), IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), Current: true,
	}}, NextCursor: "next"}}
	apps := managementAppResolver{publishable: "bb_pk_test", app: applicationinstance.Instance{InternalID: 7, PublicID: appPublicID}}
	handler := WithSessionManagement(http.NotFoundHandler(), apps, apps, store)
	req := httptest.NewRequest(http.MethodGet, "/v1/sessions?limit=2&cursor=cursor", nil)
	req.Header.Set(PublishableKeyHeader, "bb_pk_test")
	req.Header.Set("Authorization", "Bearer access-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("list status/body = %d %s", res.Code, res.Body.String())
	}
	if res.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control = %q", res.Header().Get("Cache-Control"))
	}
	var payload map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	body := res.Body.String()
	for _, forbidden := range []string{"user_id", "mfa_method", "ip", "user_agent", "location", "device"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("list response leaks %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(body, `"current":true`) || payload["next_cursor"] != "next" {
		t.Fatalf("list response = %s", body)
	}
}

func TestSessionSelfServiceMutationTransportAndCookieClearing(t *testing.T) {
	appPublicID := applicationinstance.PublicID("app_00000000-0000-4000-8000-000000000001")
	currentID := "ses_00000000-0000-4000-8000-000000000002"
	record := session.Record{PublicID: currentID, ApplicationPublicID: string(appPublicID), ApplicationInstanceID: 7}
	store := &managementSessions{record: record}
	apps := managementAppResolver{publishable: "bb_pk_test", app: applicationinstance.Instance{InternalID: 7, PublicID: appPublicID}}
	handler := WithSessionManagement(http.NotFoundHandler(), apps, apps, store)

	request := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set(PublishableKeyHeader, "bb_pk_test")
		req.Header.Set("Authorization", "Bearer access-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	if res := request("/v1/sessions/" + currentID + "/revoke"); res.Code != http.StatusNoContent || !strings.Contains(res.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("revoke-current status/cookie = %d %q", res.Code, res.Header().Get("Set-Cookie"))
	}
	if store.revokedSession != currentID {
		t.Fatalf("revoked session = %q", store.revokedSession)
	}
	if res := request("/v1/sessions/revoke-others"); res.Code != http.StatusOK || !store.revokeOthersCalled {
		t.Fatalf("revoke-others status/called = %d/%v", res.Code, store.revokeOthersCalled)
	}
	if res := request("/v1/sessions/sign-out-everywhere"); res.Code != http.StatusOK || !store.signOutAllCalled || !strings.Contains(res.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("sign-out-everywhere status/called/cookie = %d/%v/%q", res.Code, store.signOutAllCalled, res.Header().Get("Set-Cookie"))
	}
}

func TestSessionSelfServiceReverificationPurposeRouting(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodPost, "/v1/sessions/ses_00000000-0000-4000-8000-000000000002/revoke", authentication.ReverificationPurposeSessionRevoke},
		{http.MethodPost, "/v1/sessions/revoke-others", authentication.ReverificationPurposeSessionRevokeOthers},
		{http.MethodPost, "/v1/sessions/sign-out-everywhere", authentication.ReverificationPurposeSignOutEverywhere},
		{http.MethodPost, "/v1/sessions/sign-out", ""},
		{http.MethodGet, "/v1/sessions", ""},
	}
	for _, tc := range cases {
		if got := requiredReverificationPurposeFor(tc.method, tc.path); got != tc.want {
			t.Fatalf("%s %s purpose=%q want=%q", tc.method, tc.path, got, tc.want)
		}
	}
}
