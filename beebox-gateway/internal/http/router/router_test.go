package router

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/config"
	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/http/middleware"
	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/resolve"
	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
)

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type fakeResolver struct {
	project resolve.Project
	err     error
}

func (f fakeResolver) Resolve(*http.Request) (resolve.Project, error) {
	if f.err != nil {
		return resolve.Project{}, f.err
	}
	return f.project, nil
}

func sampleProject() resolve.Project {
	return resolve.Project{
		ProjectID: "01800000-0000-7000-8000-000000000001",
		Slug:      "shop",
		PlanSlug:  "free",
		Env:       "test",
		Origins:   []string{"http://localhost:3000"},
		Modules:   []string{"auth.password", "users.profile"},
	}
}

func testCfg(plansURL, projectsURL string) config.Config {
	return config.Config{
		RequestTimeout:    2 * time.Second,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		PlansBaseURL:      plansURL,
		ProjectsBaseURL:   projectsURL,
		InternalToken:     "dev-internal",
		RateLimitRPS:      1000,
		RateLimitBurst:    1000,
	}
}

func newGateway(t *testing.T, cfg config.Config, resolver middleware.Resolver) http.Handler {
	t.Helper()
	if resolver == nil {
		resolver = middleware.HTTPResolver{Client: &resolve.Client{
			BaseURL: cfg.ProjectsBaseURL,
			Token:   cfg.InternalToken,
			HTTP:    &http.Client{Timeout: cfg.RequestTimeout},
		}}
	}
	return NewWithResolver(cfg, resolver)
}

func TestHealthLiveReady(t *testing.T) {
	h := newGateway(t, testCfg("http://127.0.0.1:9", "http://127.0.0.1:9"), fakeResolver{project: sampleProject()})
	for _, path := range []string{"/health/live", "/health/ready"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, rec.Code)
		}
	}
}

func TestUnknownPath(t *testing.T) {
	h := newGateway(t, testCfg("http://127.0.0.1:9", "http://127.0.0.1:9"), fakeResolver{project: sampleProject()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/no/such/route", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
	body := decodeError(t, rec.Body)
	if body.Error.Code != "not_found" {
		t.Fatalf("code=%q", body.Error.Code)
	}
}

func TestInternalNotProxied(t *testing.T) {
	h := newGateway(t, testCfg("http://127.0.0.1:9", "http://127.0.0.1:9"), fakeResolver{project: sampleProject()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/resolve?pk=pk_test_x", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestClientConfigAfterResolve(t *testing.T) {
	h := newGateway(t, testCfg("http://127.0.0.1:9", "http://127.0.0.1:9"), fakeResolver{project: sampleProject()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/client/config", nil)
	req.Header.Set("X-BeeBox-Publishable-Key", "pk_test_ok")
	req.Header.Set("Origin", "http://localhost:3000")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatalf("acao=%q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatalf("must not reflect *")
	}
	var body struct {
		Project  map[string]string `json:"project"`
		PlanSlug string            `json:"plan_slug"`
		Modules  []string          `json:"modules"`
		Fields   []any             `json:"fields"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body.Project["id"] == "" || body.Project["slug"] != "shop" || body.PlanSlug != "free" {
		t.Fatalf("body=%+v", body)
	}
	if body.Fields == nil || len(body.Fields) != 0 {
		t.Fatalf("fields=%v", body.Fields)
	}
}

func TestClientConfigBearerAndHostSlug(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/resolve" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-BeeBox-Internal-Token") != "dev-internal" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(sampleProject())
	}))
	t.Cleanup(upstream.Close)
	h := newGateway(t, testCfg("http://127.0.0.1:9", upstream.URL), nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/client/config", nil)
	req.Header.Set("Authorization", "Bearer pk_test_live")
	req.Header.Set("Origin", "http://localhost:3000")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/client/config", nil)
	req.Host = "shop.api.beebox.dev"
	req.Header.Set("Origin", "http://localhost:3000")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("host status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCORSDeny(t *testing.T) {
	h := newGateway(t, testCfg("http://127.0.0.1:9", "http://127.0.0.1:9"), fakeResolver{project: sampleProject()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/client/config", nil)
	req.Header.Set("X-BeeBox-Publishable-Key", "pk_test_ok")
	req.Header.Set("Origin", "https://evil.example")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
	body := decodeError(t, rec.Body)
	if body.Error.Code != "forbidden" {
		t.Fatalf("code=%q", body.Error.Code)
	}
}

func TestProxyPlansAndProjects(t *testing.T) {
	plans := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/plans" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plans":[{"slug":"free"}]}`))
	}))
	t.Cleanup(plans.Close)
	projects := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/resolve" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Header.Get("X-BeeBox-Owner-Id") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"unauthorized"}}`))
			return
		}
		if r.Header.Get("X-Request-ID") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"projects":[]}`))
	}))
	t.Cleanup(projects.Close)

	h := newGateway(t, testCfg(plans.URL, projects.URL), fakeResolver{project: sampleProject()})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/plans", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"free"`) {
		t.Fatalf("plans status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("projects without owner status=%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.Header.Set("X-BeeBox-Owner-Id", "01800000-0000-7000-8000-0000000000bb")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("projects with owner status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRateLimit(t *testing.T) {
	cfg := testCfg("http://127.0.0.1:9", "http://127.0.0.1:9")
	cfg.RateLimitRPS = 1
	cfg.RateLimitBurst = 1
	h := newGateway(t, cfg, fakeResolver{project: sampleProject()})
	req := func() *http.Response {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/v1/plans", nil)
		r.RemoteAddr = "10.0.0.8:1234"
		h.ServeHTTP(rec, r)
		return rec.Result()
	}
	first := req()
	if first.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("first request limited")
	}
	second := req()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second status=%d", second.StatusCode)
	}
	var body errorBody
	if err := json.NewDecoder(second.Body).Decode(&body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body.Error.Code != "too_many_requests" {
		t.Fatalf("code=%q", body.Error.Code)
	}
}

func decodeError(t *testing.T, r io.Reader) errorBody {
	t.Helper()
	var body errorBody
	if err := json.NewDecoder(r).Decode(&body); err != nil {
		t.Fatalf("json: %v", err)
	}
	return body
}

func TestClientConfigOAuthSlugs(t *testing.T) {
	project := sampleProject()
	project.PlanSlug = "pro"
	project.Modules = []string{"auth.password", "auth.oauth.google", "auth.oauth.github", "users.profile"}
	h := newGateway(t, testCfg("http://127.0.0.1:9", "http://127.0.0.1:9"), fakeResolver{project: project})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/client/config", nil)
	req.Header.Set("X-BeeBox-Publishable-Key", "pk_test_ok")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Auth struct {
			Password bool     `json:"password"`
			OAuth    []string `json:"oauth"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Auth.Password {
		t.Fatal("password")
	}
	if len(body.Auth.OAuth) != 2 || body.Auth.OAuth[0] != "google" || body.Auth.OAuth[1] != "github" {
		t.Fatalf("oauth=%v", body.Auth.OAuth)
	}
}

func TestOAuthCallbackDoesNotRequireProject(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/oauth/google/callback" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"unauthorized"}}`))
	}))
	t.Cleanup(upstream.Close)
	cfg := testCfg("http://127.0.0.1:9", "http://127.0.0.1:9")
	cfg.IdentityBaseURL = upstream.URL
	h := newGateway(t, cfg, fakeResolver{err: apperror.New(apperror.CodeUnauthorized, "project not resolved")})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/oauth/google/callback?code=x&state=y", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "unauthorized" {
		t.Fatalf("code=%q body=%s", body.Error.Code, rec.Body.String())
	}
}
