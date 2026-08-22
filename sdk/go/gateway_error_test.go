package beebox

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/gateway"
	"github.com/DoMinhHHung/beebox/internal/requestcorrelation"
)

type captureRequestIDTransport struct {
	base      http.RoundTripper
	requestID string
}

func (t *captureRequestIDTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(req)
	if res != nil {
		t.requestID = res.Header.Get(requestcorrelation.PublicHeader)
	}
	return res, err
}

func sdkGatewayConfig(t *testing.T, upstream string, maxBodyBytes int64) gateway.Config {
	t.Helper()
	identityURL, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	keyValue := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	key, err := requestcorrelation.LoadKey(func(name string) (string, bool) {
		if name == requestcorrelation.KeyEnvironmentVariable {
			return keyValue, true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	return gateway.Config{
		IdentityBaseURL:       identityURL,
		CorrelationKey:        key,
		ConnectTimeout:        50 * time.Millisecond,
		ResponseHeaderTimeout: 100 * time.Millisecond,
		RequestTimeout:        200 * time.Millisecond,
		ReadinessTimeout:      50 * time.Millisecond,
		ShutdownTimeout:       time.Second,
		IdleConnTimeout:       time.Second,
		ReadHeaderTimeout:     50 * time.Millisecond,
		ReadTimeout:           time.Second,
		WriteTimeout:          2 * time.Second,
		MaxBodyBytes:          maxBodyBytes,
	}
}

func sdkClientThroughGateway(t *testing.T, handler http.Handler) (*Client, *captureRequestIDTransport, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	transport := &captureRequestIDTransport{base: http.DefaultTransport}
	client, err := NewClient(server.URL, "bb_pk_sdk_gateway", WithHTTPClient(&http.Client{Transport: transport, Timeout: time.Second}))
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, transport, server.Close
}

func assertGatewaySDKError(t *testing.T, err error, transport *captureRequestIDTransport, wantStatus int, wantCode string) {
	t.Helper()
	var sdkErr *Error
	if !errors.As(err, &sdkErr) {
		t.Fatalf("error type = %T, want *beebox.Error", err)
	}
	if sdkErr.StatusCode != wantStatus {
		t.Fatalf("StatusCode=%d want=%d", sdkErr.StatusCode, wantStatus)
	}
	if sdkErr.Code != wantCode {
		t.Fatalf("Code=%q want=%q", sdkErr.Code, wantCode)
	}
	if sdkErr.Message == "" {
		t.Fatal("Message is empty")
	}
	if sdkErr.RequestID == "" || len(sdkErr.RequestID) != 32 {
		t.Fatalf("RequestID=%q", sdkErr.RequestID)
	}
	if transport.requestID != sdkErr.RequestID {
		t.Fatalf("header request ID=%q SDK RequestID=%q", transport.requestID, sdkErr.RequestID)
	}
}

func TestSDKDecodesCanonicalGatewayErrors(t *testing.T) {
	t.Run("upstream-unavailable", func(t *testing.T) {
		cfg := sdkGatewayConfig(t, "http://127.0.0.1:1", 1<<20)
		client, transport, cleanup := sdkClientThroughGateway(t, gateway.NewHandler(cfg, nil))
		defer cleanup()
		_, err := client.CurrentSession(context.Background(), "access-token")
		if err == nil {
			t.Fatal("expected Gateway upstream failure")
		}
		assertGatewaySDKError(t, err, transport, http.StatusBadGateway, "upstream_unavailable")
	})

	t.Run("request-too-large", func(t *testing.T) {
		called := false
		identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}))
		defer identity.Close()
		cfg := sdkGatewayConfig(t, identity.URL, 32)
		client, transport, cleanup := sdkClientThroughGateway(t, gateway.NewHandler(cfg, nil))
		defer cleanup()
		_, err := client.SignIn(context.Background(), "oversized-email-address@example.test", "oversized-password-value")
		if err == nil {
			t.Fatal("expected Gateway body-limit failure")
		}
		assertGatewaySDKError(t, err, transport, http.StatusRequestEntityTooLarge, "request_too_large")
		if called {
			t.Fatal("oversized SDK request reached Identity")
		}
	})
}
