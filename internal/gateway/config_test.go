package gateway

import (
	"strings"
	"testing"
	"time"
)

const testCorrelationKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"

func gatewayTestLookup(overrides map[string]string) LookupEnv {
	values := map[string]string{
		"BEEBOX_IDENTITY_UPSTREAM_URL":    "http://127.0.0.1:8081/",
		"BEEBOX_INTERNAL_CORRELATION_KEY": testCorrelationKey,
	}
	for key, value := range overrides {
		values[key] = value
	}
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestLoadConfigRequiresIdentityUpstream(t *testing.T) {
	_, err := LoadConfig(func(string) (string, bool) { return "", false })
	if err == nil || !strings.Contains(err.Error(), "BEEBOX_IDENTITY_UPSTREAM_URL") {
		t.Fatalf("expected required upstream error, got %v", err)
	}
}

func TestLoadConfigRequiresDedicatedCorrelationKey(t *testing.T) {
	_, err := LoadConfig(func(name string) (string, bool) {
		if name == "BEEBOX_IDENTITY_UPSTREAM_URL" {
			return "http://127.0.0.1:8081", true
		}
		return "", false
	})
	if err == nil || !strings.Contains(err.Error(), "BEEBOX_INTERNAL_CORRELATION_KEY") {
		t.Fatalf("expected correlation key error, got %v", err)
	}
}

func TestLoadConfigDefaultsHaveSafeDeadlineOrdering(t *testing.T) {
	cfg, err := LoadConfig(gatewayTestLookup(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RequestTimeout != 15*time.Second || cfg.ReadHeaderTimeout != 5*time.Second || cfg.ReadTimeout != 10*time.Second || cfg.WriteTimeout != 30*time.Second {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.WriteTimeout < cfg.ReadTimeout+cfg.RequestTimeout+serverWriteSafetyMargin {
		t.Fatalf("unsafe default ordering: %+v", cfg)
	}
}

func TestLoadConfigValidatesAndLoadsBounds(t *testing.T) {
	cfg, err := LoadConfig(gatewayTestLookup(map[string]string{
		"BEEBOX_GATEWAY_HTTP_ADDR":               "127.0.0.1:9090",
		"BEEBOX_GATEWAY_CONNECT_TIMEOUT":         "2s",
		"BEEBOX_GATEWAY_RESPONSE_HEADER_TIMEOUT": "3s",
		"BEEBOX_GATEWAY_REQUEST_TIMEOUT":         "4s",
		"BEEBOX_GATEWAY_READINESS_TIMEOUT":       "1s",
		"BEEBOX_GATEWAY_SHUTDOWN_TIMEOUT":        "5s",
		"BEEBOX_GATEWAY_IDLE_CONN_TIMEOUT":       "30s",
		"BEEBOX_GATEWAY_READ_HEADER_TIMEOUT":     "2s",
		"BEEBOX_GATEWAY_READ_TIMEOUT":            "6s",
		"BEEBOX_GATEWAY_WRITE_TIMEOUT":           "15s",
		"BEEBOX_GATEWAY_MAX_BODY_BYTES":          "2048",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "127.0.0.1:9090" || cfg.IdentityBaseURL.String() != "http://127.0.0.1:8081" {
		t.Fatalf("unexpected addresses: %+v", cfg)
	}
	if cfg.ConnectTimeout != 2*time.Second || cfg.ResponseHeaderTimeout != 3*time.Second || cfg.RequestTimeout != 4*time.Second {
		t.Fatalf("unexpected timeouts: %+v", cfg)
	}
	if cfg.ReadHeaderTimeout != 2*time.Second || cfg.ReadTimeout != 6*time.Second || cfg.WriteTimeout != 15*time.Second {
		t.Fatalf("unexpected server timeouts: %+v", cfg)
	}
	if cfg.MaxBodyBytes != 2048 {
		t.Fatalf("unexpected body limit %d", cfg.MaxBodyBytes)
	}
}

func TestLoadConfigAcceptsMaximumSafeGatewayTimeouts(t *testing.T) {
	cfg, err := LoadConfig(gatewayTestLookup(map[string]string{
		"BEEBOX_GATEWAY_REQUEST_TIMEOUT":     "30s",
		"BEEBOX_GATEWAY_READ_HEADER_TIMEOUT": "5s",
		"BEEBOX_GATEWAY_READ_TIMEOUT":        "30s",
		"BEEBOX_GATEWAY_WRITE_TIMEOUT":       "65s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RequestTimeout != maximumRequestTimeout || cfg.ReadTimeout != maximumReadTimeout || cfg.WriteTimeout != maximumWriteTimeout {
		t.Fatalf("maximums not loaded: %+v", cfg)
	}
}

func TestLoadConfigRejectsUnsafeDeadlineOrderingAndExtremeDurations(t *testing.T) {
	tests := []map[string]string{
		{"BEEBOX_GATEWAY_REQUEST_TIMEOUT": "30s", "BEEBOX_GATEWAY_READ_TIMEOUT": "30s", "BEEBOX_GATEWAY_WRITE_TIMEOUT": "64.999s"},
		{"BEEBOX_GATEWAY_READ_HEADER_TIMEOUT": "10s", "BEEBOX_GATEWAY_READ_TIMEOUT": "9s", "BEEBOX_GATEWAY_WRITE_TIMEOUT": "40s"},
		{"BEEBOX_GATEWAY_REQUEST_TIMEOUT": "1h", "BEEBOX_GATEWAY_READ_TIMEOUT": "30s", "BEEBOX_GATEWAY_WRITE_TIMEOUT": "65s"},
		{"BEEBOX_GATEWAY_REQUEST_TIMEOUT": "1ns"},
	}
	for _, overrides := range tests {
		if _, err := LoadConfig(gatewayTestLookup(overrides)); err == nil {
			t.Fatalf("expected config to fail: %#v", overrides)
		}
	}
}

func TestLoadConfigRejectsUnsafeUpstreamShape(t *testing.T) {
	for _, raw := range []string{
		"ftp://identity.internal",
		"http://user:pass@identity.internal",
		"http://identity.internal/base",
		"http://identity.internal?x=1",
		"http://identity.internal/#fragment",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := LoadConfig(func(name string) (string, bool) {
				if name == "BEEBOX_IDENTITY_UPSTREAM_URL" {
					return raw, true
				}
				if name == "BEEBOX_INTERNAL_CORRELATION_KEY" {
					return testCorrelationKey, true
				}
				return "", false
			})
			if err == nil {
				t.Fatalf("expected %q to fail", raw)
			}
		})
	}
}
