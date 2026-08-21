package gateway

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig(t *testing.T, upstream string) Config {
	t.Helper()
	parsed, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		IdentityBaseURL:       parsed,
		ConnectTimeout:        100 * time.Millisecond,
		ResponseHeaderTimeout: 200 * time.Millisecond,
		RequestTimeout:        300 * time.Millisecond,
		ReadinessTimeout:      100 * time.Millisecond,
		ShutdownTimeout:       time.Second,
		IdleConnTimeout:       time.Second,
		MaxBodyBytes:          1024,
	}
}

func TestGatewayForwardsRouteQueryBodyAndResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sign-ins" || r.URL.RawQuery != "next=a%2Fb&x=1" {
			t.Errorf("unexpected target %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(body) != `{"email":"user@example.test"}` {
			t.Errorf("unexpected body %q", body)
		}
		w.Header().Set("X-Upstream", "preserved")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer upstream.Close()

	h := NewHandler(testConfig(t, upstream.URL), nil)
	req := httptest.NewRequest(http.MethodPost, "http://public.test/v1/sign-ins?next=a%2Fb&x=1", strings.NewReader(`{"email":"user@example.test"}`))
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated || resp.Body.String() != "created" || resp.Header().Get("X-Upstream") != "preserved" {
		t.Fatalf("unexpected response status=%d body=%q headers=%v", resp.Code, resp.Body.String(), resp.Header())
	}
	if resp.Header().Get(requestIDHeader) == "" {
		t.Fatal("missing request id")
	}
}

func TestGatewayOverwritesSpoofedForwardingHeadersAndPropagatesRequestID(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	h := NewHandler(testConfig(t, upstream.URL), nil)
	req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/profile", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("Forwarded", "for=attacker")
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	req.Header.Set("X-Forwarded-Host", "evil.test")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set(requestIDHeader, "req-safe-123")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)

	headers := <-seen
	if headers.Get("Forwarded") != "" {
		t.Fatalf("Forwarded was not stripped: %q", headers.Get("Forwarded"))
	}
	if got := headers.Get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Fatalf("unexpected forwarded for %q", got)
	}
	if got := headers.Get("X-Forwarded-Host"); got != "public.test" {
		t.Fatalf("unexpected forwarded host %q", got)
	}
	if got := headers.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("unexpected forwarded proto %q", got)
	}
	if got := headers.Get(requestIDHeader); got != "req-safe-123" {
		t.Fatalf("unexpected request id %q", got)
	}
	if resp.Header().Get(requestIDHeader) != "req-safe-123" {
		t.Fatalf("request id not returned")
	}
}

func TestGatewayReplacesInvalidRequestID(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(requestIDHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	h := NewHandler(testConfig(t, upstream.URL), nil)
	req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/profile", nil)
	req.Header.Set(requestIDHeader, "bad id with spaces")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	got := <-seen
	if got == "" || got == "bad id with spaces" || !validRequestID(got) {
		t.Fatalf("invalid replacement %q", got)
	}
}

func TestGatewayHealthAndReadiness(t *testing.T) {
	var mu sync.Mutex
	ready := true
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		isReady := ready
		mu.Unlock()
		if !isReady {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := NewHandler(testConfig(t, upstream.URL), nil)
	for path, want := range map[string]int{"/health/live": http.StatusOK, "/health/ready": http.StatusOK} {
		req := httptest.NewRequest(http.MethodGet, "http://public.test"+path, nil)
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		if resp.Code != want {
			t.Fatalf("%s: got %d want %d", path, resp.Code, want)
		}
	}
	mu.Lock()
	ready = false
	mu.Unlock()
	req := httptest.NewRequest(http.MethodGet, "http://public.test/health/ready", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d want 503", resp.Code)
	}
}

func TestGatewayMapsUnavailableAndTimeout(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		h := NewHandler(testConfig(t, "http://127.0.0.1:1"), nil)
		req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/profile", nil)
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		if resp.Code != http.StatusBadGateway {
			t.Fatalf("got %d want 502: %s", resp.Code, resp.Body.String())
		}
	})

	t.Run("timeout", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer upstream.Close()
		cfg := testConfig(t, upstream.URL)
		cfg.RequestTimeout = 25 * time.Millisecond
		cfg.ResponseHeaderTimeout = time.Second
		h := NewHandler(cfg, nil)
		req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/profile", nil)
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		if resp.Code != http.StatusGatewayTimeout {
			t.Fatalf("got %d want 504: %s", resp.Code, resp.Body.String())
		}
	})
}

func TestGatewayRejectsOversizedKnownBody(t *testing.T) {
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	cfg := testConfig(t, upstream.URL)
	cfg.MaxBodyBytes = 4
	h := NewHandler(cfg, nil)
	req := httptest.NewRequest(http.MethodPost, "http://public.test/v1/sign-ins", bytes.NewReader([]byte("12345")))
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d want 413", resp.Code)
	}
	if called {
		t.Fatal("upstream should not be called")
	}
}

func TestGatewayPropagatesCancellation(t *testing.T) {
	canceled := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		canceled <- struct{}{}
	}))
	defer upstream.Close()
	cfg := testConfig(t, upstream.URL)
	cfg.RequestTimeout = time.Second
	h := NewHandler(cfg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/profile", nil).WithContext(ctx)
	resp := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(resp, req)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("upstream cancellation not observed")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("gateway did not return after cancellation")
	}
}

func TestGatewayAccessLogOmitsQueryAndSecrets(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	h := NewHandler(testConfig(t, upstream.URL), logger)
	req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/social/callback?code=secret-provider-code&state=secret-state", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if strings.Contains(logs.String(), "secret-provider-code") || strings.Contains(logs.String(), "secret-state") {
		t.Fatalf("query secret leaked to log: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"path":"/v1/social/callback"`) {
		t.Fatalf("path missing from log: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"request_id":"`) {
		t.Fatalf("request id missing from log: %s", logs.String())
	}
}
