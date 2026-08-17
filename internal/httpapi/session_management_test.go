package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
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
	record session.Record
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
