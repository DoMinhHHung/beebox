package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(mapLookup(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}

	if cfg.ShutdownTimeout != 10*time.Second {
		t.Fatalf(
			"ShutdownTimeout = %s, want %s",
			cfg.ShutdownTimeout,
			10*time.Second,
		)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(mapLookup(map[string]string{
		"BEEBOX_HTTP_ADDR":        "127.0.0.1:9090",
		"BEEBOX_SHUTDOWN_TIMEOUT": "3s",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTPAddr != "127.0.0.1:9090" {
		t.Fatalf(
			"HTTPAddr = %q, want %q",
			cfg.HTTPAddr,
			"127.0.0.1:9090",
		)
	}

	if cfg.ShutdownTimeout != 3*time.Second {
		t.Fatalf(
			"ShutdownTimeout = %s, want %s",
			cfg.ShutdownTimeout,
			3*time.Second,
		)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]string
		want   string
	}{
		{
			name:   "empty address",
			values: map[string]string{"BEEBOX_HTTP_ADDR": ""},
			want:   "BEEBOX_HTTP_ADDR must not be empty",
		},
		{
			name:   "address without port",
			values: map[string]string{"BEEBOX_HTTP_ADDR": "localhost"},
			want:   "invalid BEEBOX_HTTP_ADDR",
		},
		{
			name:   "non numeric port",
			values: map[string]string{"BEEBOX_HTTP_ADDR": "localhost:http"},
			want:   "port must be numeric",
		},
		{
			name:   "invalid shutdown duration",
			values: map[string]string{"BEEBOX_SHUTDOWN_TIMEOUT": "later"},
			want:   "invalid BEEBOX_SHUTDOWN_TIMEOUT",
		},
		{
			name:   "non positive shutdown duration",
			values: map[string]string{"BEEBOX_SHUTDOWN_TIMEOUT": "0s"},
			want:   "must be greater than zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(mapLookup(tt.values))
			if err == nil {
				t.Fatal("Load() error = nil, want error")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf(
					"Load() error = %q, want substring %q",
					err,
					tt.want,
				)
			}
		})
	}
}

func mapLookup(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
