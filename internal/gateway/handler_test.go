package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/requestcorrelation"
)

func testConfig(t *testing.T, upstream string) Config {
	t.Helper()
	parsed, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	key, err := requestcorrelation.LoadKey(func(name string) (string, bool) {
		if name == requestcorrelation.KeyEnvironmentVariable {
			return testCorrelationKey, true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		IdentityBaseURL:       parsed,
		CorrelationKey:        key,
		ConnectTimeout:        100 * time.Millisecond,
		ResponseHeaderTimeout: 200 * time.Millisecond,
		RequestTimeout:        300 * time.Millisecond,
		ReadinessTimeout:      100 * time.Millisecond,
		ShutdownTimeout:       time.Second,
		IdleConnTimeout:       time.Second,
		ReadHeaderTimeout:     100 * time.Millisecond,
		ReadTimeout:           time.Second,
		WriteTimeout:          2 * time.Second,
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
	if values := resp.Header().Values(requestIDHeader); len(values) != 1 || len(values[0]) != 32 {
		t.Fatalf("request ids = %#v", values)
	}
}

func TestGatewayOverwritesSpoofedForwardingAndCorrelationHeaders(t *testing.T) {
	seen := make(chan http.Header, 1)
	cfg := testConfig(t, "http://127.0.0.1")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.Header().Add(requestIDHeader, "identity-should-be-normalized")
		w.Header().Add(requestIDHeader, "duplicate-identity-value")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	cfg.IdentityBaseURL = parsed
	h := NewHandler(cfg, nil)
	spoofed := "00112233445566778899aabbccddeeff"
	req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/profile", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("Forwarded", "for=attacker")
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	req.Header.Set("X-Forwarded-Host", "evil.test")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set(requestIDHeader, spoofed)
	req.Header.Set(requestcorrelation.InternalIDHeader, spoofed)
	req.Header.Set(requestcorrelation.InternalSignatureHeader, "attacker-signature")
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
	publicID := headers.Get(requestIDHeader)
	if publicID == "" || publicID == spoofed {
		t.Fatalf("client selected public request id: %q", publicID)
	}
	internalID := headers.Get(requestcorrelation.InternalIDHeader)
	if internalID != publicID {
		t.Fatalf("internal/public correlation mismatch %q/%q", internalID, publicID)
	}
	if _, ok := requestcorrelation.Verify(cfg.CorrelationKey, internalID, headers.Get(requestcorrelation.InternalSignatureHeader)); !ok {
		t.Fatal("gateway did not provide authenticated correlation provenance")
	}
	if values := resp.Header().Values(requestIDHeader); len(values) != 1 || values[0] != publicID {
		t.Fatalf("public response request ids = %#v, want exactly %q", values, publicID)
	}
	if resp.Header().Get(requestcorrelation.InternalIDHeader) != "" || resp.Header().Get(requestcorrelation.InternalSignatureHeader) != "" {
		t.Fatal("internal correlation metadata leaked to public response")
	}
}

func TestGatewayReplacesEveryClientRequestID(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(requestIDHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	h := NewHandler(testConfig(t, upstream.URL), nil)
	for _, supplied := range []string{"req-safe-123", "00112233445566778899aabbccddeeff", "bad id with spaces"} {
		req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/profile", nil)
		req.Header.Set(requestIDHeader, supplied)
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		got := <-seen
		if got == "" || got == supplied || len(got) != 32 {
			t.Fatalf("client id %q was not replaced: %q", supplied, got)
		}
		if values := resp.Header().Values(requestIDHeader); len(values) != 1 || values[0] != got {
			t.Fatalf("response IDs = %#v, upstream saw %q", values, got)
		}
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
		if len(resp.Header().Values(requestIDHeader)) != 1 {
			t.Fatalf("%s request IDs = %#v", path, resp.Header().Values(requestIDHeader))
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

func TestGatewayMapsUnavailableAndTimeoutToCanonicalErrors(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		h := NewHandler(testConfig(t, "http://127.0.0.1:1"), nil)
		req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/profile", nil)
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		assertGatewayError(t, resp, http.StatusBadGateway, "upstream_unavailable")
	})
	t.Run("timeout", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer upstream.Close()
		cfg := testConfig(t, upstream.URL)
		cfg.RequestTimeout = 25 * time.Millisecond
		cfg.ResponseHeaderTimeout = time.Second
		h := NewHandler(cfg, nil)
		req := httptest.NewRequest(http.MethodGet, "http://public.test/v1/profile", nil)
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		assertGatewayError(t, resp, http.StatusGatewayTimeout, "upstream_timeout")
	})
}

func assertGatewayError(t *testing.T, resp *httptest.ResponseRecorder, status int, code string) gatewayErrorEnvelope {
	t.Helper()
	if resp.Code != status {
		t.Fatalf("status=%d want=%d body=%s", resp.Code, status, resp.Body.String())
	}
	var envelope gatewayErrorEnvelope
	if err := json.Unmarshal(resp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v body=%s", err, resp.Body.String())
	}
	if envelope.Error.Code != code || envelope.Error.Message == "" || envelope.Error.RequestID == "" {
		t.Fatalf("error envelope=%+v", envelope)
	}
	values := resp.Header().Values(requestIDHeader)
	if len(values) != 1 || values[0] != envelope.Error.RequestID {
		t.Fatalf("header IDs=%#v body request_id=%q", values, envelope.Error.RequestID)
	}
	return envelope
}

type trackedBody struct {
	reader io.Reader
	closed bool
}

func (b *trackedBody) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *trackedBody) Close() error {
	b.closed = true
	return nil
}

func TestGatewayRejectsOversizedKnownBodyBeforeUpstream(t *testing.T) {
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	cfg := testConfig(t, upstream.URL)
	cfg.MaxBodyBytes = 4
	h := NewHandler(cfg, nil)
	body := &trackedBody{reader: strings.NewReader("12345")}
	req := httptest.NewRequest(http.MethodPost, "http://public.test/v1/sign-ins", body)
	req.ContentLength = 5
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	assertGatewayError(t, resp, http.StatusRequestEntityTooLarge, "request_too_large")
	if called {
		t.Fatal("upstream should not be called")
	}
	if !body.closed {
		t.Fatal("rejected known-length body was not closed")
	}
}

func TestGatewayBuffersUnknownLengthBodiesBeforeDispatch(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		limit      int64
		chunked    bool
		wantStatus int
		wantCalled bool
	}{
		{"below", "abc", 4, false, http.StatusNoContent, true},
		{"exact", "abcd", 4, false, http.StatusNoContent, true},
		{"limit-plus-one", "abcde", 4, false, http.StatusRequestEntityTooLarge, false},
		{"chunked-over", "abcdef", 4, true, http.StatusRequestEntityTooLarge, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			var gotBody string
			var gotLength int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				payload, _ := io.ReadAll(r.Body)
				gotBody = string(payload)
				gotLength = r.ContentLength
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			cfg := testConfig(t, upstream.URL)
			cfg.MaxBodyBytes = tc.limit
			h := NewHandler(cfg, nil)
			body := &trackedBody{reader: strings.NewReader(tc.body)}
			req := httptest.NewRequest(http.MethodPost, "http://public.test/v1/sign-ins", body)
			req.ContentLength = -1
			if tc.chunked {
				req.TransferEncoding = []string{"chunked"}
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			if resp.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", resp.Code, tc.wantStatus, resp.Body.String())
			}
			if called != tc.wantCalled {
				t.Fatalf("upstream called=%v want=%v", called, tc.wantCalled)
			}
			if !body.closed {
				t.Fatal("original body was not closed")
			}
			if tc.wantCalled && (gotBody != tc.body || gotLength != int64(len(tc.body))) {
				t.Fatalf("body/length changed: %q/%d want %q/%d", gotBody, gotLength, tc.body, len(tc.body))
			}
			if !tc.wantCalled {
				assertGatewayError(t, resp, http.StatusRequestEntityTooLarge, "request_too_large")
			}
		})
	}
}

type cancelAfterFirstRead struct {
	ctx    context.Context
	cancel context.CancelFunc
	read   bool
}

func (r *cancelAfterFirstRead) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		p[0] = 'x'
		r.cancel()
		return 1, nil
	}
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}
func (r *cancelAfterFirstRead) Close() error { return nil }

func TestGatewayCancellationDuringBoundedPreReadReturnsWithoutDispatch(t *testing.T) {
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	cfg := testConfig(t, upstream.URL)
	ctx, cancel := context.WithCancel(context.Background())
	body := &cancelAfterFirstRead{ctx: ctx, cancel: cancel}
	req := httptest.NewRequest(http.MethodPost, "http://public.test/v1/sign-ins", nil).WithContext(ctx)
	req.Body = body
	req.ContentLength = -1
	resp := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		NewHandler(cfg, nil).ServeHTTP(resp, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("gateway did not return after body-read cancellation")
	}
	if called {
		t.Fatal("canceled body was dispatched upstream")
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
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
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
	if strings.Contains(logs.String(), requestcorrelation.InternalSignatureHeader) || strings.Contains(logs.String(), testCorrelationKey) {
		t.Fatal("internal correlation secret/signature leaked to logs")
	}
}
