package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/DoMinhHHung/beebox/beebox-identity/internal/infrastructure/crypto"
	"github.com/DoMinhHHung/beebox/beebox-identity/internal/infrastructure/oauth"
	"github.com/google/uuid"
)

type memStates struct {
	items map[string]domain.OAuthState
}

func (m *memStates) Create(_ context.Context, state domain.OAuthState) error {
	if m.items == nil {
		m.items = map[string]domain.OAuthState{}
	}
	m.items[state.StateHash] = state
	return nil
}

func (m *memStates) TakeByHash(_ context.Context, stateHash string) (domain.OAuthState, error) {
	item, ok := m.items[stateHash]
	if !ok {
		return domain.OAuthState{}, domain.ErrNotFound
	}
	delete(m.items, stateHash)
	return item, nil
}

type staticCreds struct{ creds oauth.Credentials }

func (s staticCreds) Get(_ context.Context, _ uuid.UUID, _ string) (oauth.Credentials, error) {
	return s.creds, nil
}

type resolveFunc func(context.Context, string, string) (domain.Scope, error)

func (f resolveFunc) Resolve(ctx context.Context, pk, slug string) (domain.Scope, error) {
	return f(ctx, pk, slug)
}

func oauthServer(t *testing.T, modules []string, states domain.OAuthStateRepository) http.Handler {
	t.Helper()
	projectID := uuid.MustParse("01800000-0000-7000-8000-000000000001")
	now := func() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC) }
	return New(Deps{
		OAuthStart: application.OAuthStart{
			States: states,
			Creds: staticCreds{creds: oauth.Credentials{
				ClientID:    "cid",
				RedirectURI: "https://app.example/cb",
			}},
			Now: now,
		},
		OAuthCallback: application.OAuthCallback{
			States: states,
			Tokens: crypto.SessionTokens{},
			Now:    now,
			TTL:    time.Hour,
		},
		InternalToken: "dev-internal",
		Resolver: resolveFunc(func(_ context.Context, _, _ string) (domain.Scope, error) {
			return domain.Scope{ProjectID: projectID, Env: domain.EnvTest, Modules: modules}, nil
		}),
	})
}

func TestOAuthStartModuleDisabled(t *testing.T) {
	h := oauthServer(t, []string{domain.ModuleAuthPassword}, &memStates{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/oauth/google/start", nil)
	req.Header.Set("X-BeeBox-Internal-Token", "dev-internal")
	req.Header.Set("X-BeeBox-Project-Id", "01800000-0000-7000-8000-000000000001")
	req.Header.Set("X-BeeBox-Env", "test")
	req.Header.Set("X-BeeBox-Modules", "auth.password")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "module_disabled" {
		t.Fatalf("code=%q", body.Error.Code)
	}
}

func TestOAuthCallbackUnknownState(t *testing.T) {
	h := oauthServer(t, []string{"auth.oauth.google"}, &memStates{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/oauth/google/callback?code=abc&state=not-a-real-state", nil)
	req.Header.Set("X-BeeBox-Internal-Token", "dev-internal")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOAuthStartRedirects(t *testing.T) {
	h := oauthServer(t, []string{"auth.oauth.google"}, &memStates{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/oauth/google/start", nil)
	req.Header.Set("X-BeeBox-Internal-Token", "dev-internal")
	req.Header.Set("X-BeeBox-Project-Id", "01800000-0000-7000-8000-000000000001")
	req.Header.Set("X-BeeBox-Env", "test")
	req.Header.Set("X-BeeBox-Modules", "auth.oauth.google")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") == "" {
		t.Fatal("missing location")
	}
}
