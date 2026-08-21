package gateway

import (
	"strings"
	"testing"
	"time"
)

func TestLoadConfigRequiresIdentityUpstream(t *testing.T) {
	_, err := LoadConfig(func(string) (string, bool) { return "", false })
	if err == nil || !strings.Contains(err.Error(), "BEEBOX_IDENTITY_UPSTREAM_URL") {
		t.Fatalf("expected required upstream error, got %v", err)
	}
}

func TestLoadConfigValidatesAndLoadsBounds(t *testing.T) {
	values := map[string]string{
		"BEEBOX_GATEWAY_HTTP_ADDR":               "127.0.0.1:9090",
		"BEEBOX_IDENTITY_UPSTREAM_URL":           "http://127.0.0.1:8081/",
		"BEEBOX_GATEWAY_CONNECT_TIMEOUT":         "2s",
		"BEEBOX_GATEWAY_RESPONSE_HEADER_TIMEOUT": "3s",
		"BEEBOX_GATEWAY_REQUEST_TIMEOUT":         "4s",
		"BEEBOX_GATEWAY_READINESS_TIMEOUT":       "1s",
		"BEEBOX_GATEWAY_SHUTDOWN_TIMEOUT":        "5s",
		"BEEBOX_GATEWAY_IDLE_CONN_TIMEOUT":       "30s",
		"BEEBOX_GATEWAY_MAX_BODY_BYTES":          "2048",
	}
	cfg, err := LoadConfig(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "127.0.0.1:9090" || cfg.IdentityBaseURL.String() != "http://127.0.0.1:8081" {
		t.Fatalf("unexpected addresses: %+v", cfg)
	}
	if cfg.ConnectTimeout != 2*time.Second || cfg.ResponseHeaderTimeout != 3*time.Second || cfg.RequestTimeout != 4*time.Second {
		t.Fatalf("unexpected timeouts: %+v", cfg)
	}
	if cfg.MaxBodyBytes != 2048 {
		t.Fatalf("unexpected body limit %d", cfg.MaxBodyBytes)
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
				return "", false
			})
			if err == nil {
				t.Fatalf("expected %q to fail", raw)
			}
		})
	}
}
