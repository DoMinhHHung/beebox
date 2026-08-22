package gateway

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/platform/httpserver"
)

func startActualGateway(t *testing.T, cfg Config) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httpserver.NewWithConfig(listener.Addr().String(), NewHandler(cfg, nil), httpserver.ServerConfig{
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleConnTimeout,
	})
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	cleanup := func() {
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("gateway server did not stop")
		}
	}
	return "http://" + listener.Addr().String(), cleanup
}

func decodeActualGatewayError(t *testing.T, resp *http.Response, wantStatus int, wantCode string) gatewayErrorEnvelope {
	t.Helper()
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, wantStatus, payload)
	}
	var envelope gatewayErrorEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("decode canonical error: %v body=%s", err, payload)
	}
	if envelope.Error.Code != wantCode || envelope.Error.Message == "" || envelope.Error.RequestID == "" {
		t.Fatalf("canonical error=%+v", envelope)
	}
	values := resp.Header.Values(requestIDHeader)
	if len(values) != 1 || values[0] != envelope.Error.RequestID {
		t.Fatalf("response request IDs=%#v error request_id=%q", values, envelope.Error.RequestID)
	}
	return envelope
}

func TestGatewayActualServerDeadlineOrderingReturnsCanonicalTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer upstream.Close()
	cfg := testConfig(t, upstream.URL)
	cfg.RequestTimeout = 50 * time.Millisecond
	cfg.ResponseHeaderTimeout = time.Second
	cfg.ReadHeaderTimeout = 50 * time.Millisecond
	cfg.ReadTimeout = 100 * time.Millisecond
	cfg.WriteTimeout = 500 * time.Millisecond
	baseURL, cleanup := startActualGateway(t, cfg)
	defer cleanup()
	resp, err := http.Get(baseURL + "/v1/profile")
	if err != nil {
		t.Fatalf("gateway connection died before canonical timeout response: %v", err)
	}
	decodeActualGatewayError(t, resp, http.StatusGatewayTimeout, "upstream_timeout")
}

func TestGatewayMaximumConfiguredDeadlinesProduceProtocolCorrectServer(t *testing.T) {
	cfg, err := LoadConfig(gatewayTestLookup(map[string]string{
		"BEEBOX_GATEWAY_REQUEST_TIMEOUT":     "30s",
		"BEEBOX_GATEWAY_READ_HEADER_TIMEOUT": "5s",
		"BEEBOX_GATEWAY_READ_TIMEOUT":        "30s",
		"BEEBOX_GATEWAY_WRITE_TIMEOUT":       "65s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	cfg.IdentityBaseURL = testConfig(t, upstream.URL).IdentityBaseURL
	if cfg.WriteTimeout < cfg.ReadTimeout+cfg.RequestTimeout+serverWriteSafetyMargin {
		t.Fatalf("maximum deadline ordering is unsafe: %+v", cfg)
	}
	baseURL, cleanup := startActualGateway(t, cfg)
	defer cleanup()
	resp, err := http.Get(baseURL + "/v1/profile")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || len(resp.Header.Values(requestIDHeader)) != 1 {
		t.Fatalf("maximum deadline server response status=%d ids=%#v", resp.StatusCode, resp.Header.Values(requestIDHeader))
	}
}

func TestGatewayMutationTimeoutCanFollowCommittedUpstreamMutationWithoutRetry(t *testing.T) {
	var calls atomic.Int32
	var mutated atomic.Bool
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		calls.Add(1)
		mutated.Store(true)
		<-releaseUpstream
		w.WriteHeader(http.StatusNoContent)
	}))
	defer func() {
		close(releaseUpstream)
		upstream.Close()
	}()
	cfg := testConfig(t, upstream.URL)
	cfg.RequestTimeout = 50 * time.Millisecond
	cfg.ResponseHeaderTimeout = time.Second
	cfg.ReadHeaderTimeout = 50 * time.Millisecond
	cfg.ReadTimeout = 100 * time.Millisecond
	cfg.WriteTimeout = 500 * time.Millisecond
	baseURL, cleanup := startActualGateway(t, cfg)
	defer cleanup()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/sign-ins", strings.NewReader(`{"email":"user@example.test","password":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway did not return canonical timeout: %v", err)
	}
	decodeActualGatewayError(t, resp, http.StatusGatewayTimeout, "upstream_timeout")
	if !mutated.Load() {
		t.Fatal("synthetic authoritative mutation did not occur before timeout")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("gateway automatically retried ambiguous mutation: calls=%d", got)
	}
}
