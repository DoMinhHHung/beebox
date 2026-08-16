package config

import (
	"strings"
	"testing"
	"time"
)

const testDatabaseURL = "postgres://beebox:test-password@localhost:5432/beebox"

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(mapLookup(map[string]string{
		"BEEBOX_DATABASE_URL": testDatabaseURL,
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Fatalf("ShutdownTimeout = %s, want 10s", cfg.ShutdownTimeout)
	}
	if cfg.DatabaseURL != testDatabaseURL {
		t.Fatal("DatabaseURL does not match the configured value")
	}
	if cfg.DatabaseStartupTimeout != 5*time.Second {
		t.Fatalf(
			"DatabaseStartupTimeout = %s, want 5s",
			cfg.DatabaseStartupTimeout,
		)
	}
	if cfg.DatabaseReadinessTimeout != time.Second {
		t.Fatalf(
			"DatabaseReadinessTimeout = %s, want 1s",
			cfg.DatabaseReadinessTimeout,
		)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(mapLookup(map[string]string{
		"BEEBOX_HTTP_ADDR":                  "127.0.0.1:9090",
		"BEEBOX_SHUTDOWN_TIMEOUT":           "3s",
		"BEEBOX_DATABASE_URL":               "postgresql://localhost/beebox",
		"BEEBOX_DATABASE_STARTUP_TIMEOUT":   "4s",
		"BEEBOX_DATABASE_READINESS_TIMEOUT": "250ms",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTPAddr != "127.0.0.1:9090" {
		t.Fatalf("HTTPAddr = %q, want 127.0.0.1:9090", cfg.HTTPAddr)
	}
	if cfg.ShutdownTimeout != 3*time.Second {
		t.Fatalf("ShutdownTimeout = %s, want 3s", cfg.ShutdownTimeout)
	}
	if cfg.DatabaseStartupTimeout != 4*time.Second {
		t.Fatalf("DatabaseStartupTimeout = %s, want 4s", cfg.DatabaseStartupTimeout)
	}
	if cfg.DatabaseReadinessTimeout != 250*time.Millisecond {
		t.Fatalf(
			"DatabaseReadinessTimeout = %s, want 250ms",
			cfg.DatabaseReadinessTimeout,
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
			name:   "missing database URL",
			values: nil,
			want:   "BEEBOX_DATABASE_URL is required",
		},
		{
			name:   "empty database URL",
			values: map[string]string{"BEEBOX_DATABASE_URL": ""},
			want:   "BEEBOX_DATABASE_URL is required",
		},
		{
			name: "malformed database URL",
			values: map[string]string{
				"BEEBOX_DATABASE_URL": "postgres://user:super-secret@%zz/db",
			},
			want: "must be a valid PostgreSQL URI",
		},
		{
			name: "non PostgreSQL scheme",
			values: map[string]string{
				"BEEBOX_DATABASE_URL": "mysql://user:super-secret@localhost/db",
			},
			want: "must use the postgres or postgresql scheme",
		},
		{
			name: "database URL without host",
			values: map[string]string{
				"BEEBOX_DATABASE_URL": "postgres:///beebox",
			},
			want: "must include a host",
		},
		{
			name: "database URL with fragment",
			values: map[string]string{
				"BEEBOX_DATABASE_URL": "postgres://localhost/beebox#super-secret",
			},
			want: "must not include a fragment",
		},
		{
			name: "empty address",
			values: map[string]string{
				"BEEBOX_DATABASE_URL": testDatabaseURL,
				"BEEBOX_HTTP_ADDR":    "",
			},
			want: "BEEBOX_HTTP_ADDR must not be empty",
		},
		{
			name: "address without port",
			values: map[string]string{
				"BEEBOX_DATABASE_URL": testDatabaseURL,
				"BEEBOX_HTTP_ADDR":    "localhost",
			},
			want: "invalid BEEBOX_HTTP_ADDR",
		},
		{
			name: "non numeric port",
			values: map[string]string{
				"BEEBOX_DATABASE_URL": testDatabaseURL,
				"BEEBOX_HTTP_ADDR":    "localhost:http",
			},
			want: "port must be numeric",
		},
		{
			name: "invalid shutdown duration",
			values: map[string]string{
				"BEEBOX_DATABASE_URL":     testDatabaseURL,
				"BEEBOX_SHUTDOWN_TIMEOUT": "later",
			},
			want: "invalid BEEBOX_SHUTDOWN_TIMEOUT duration",
		},
		{
			name: "non positive shutdown duration",
			values: map[string]string{
				"BEEBOX_DATABASE_URL":     testDatabaseURL,
				"BEEBOX_SHUTDOWN_TIMEOUT": "0s",
			},
			want: "BEEBOX_SHUTDOWN_TIMEOUT must be greater than zero",
		},
		{
			name: "empty startup duration",
			values: map[string]string{
				"BEEBOX_DATABASE_URL":             testDatabaseURL,
				"BEEBOX_DATABASE_STARTUP_TIMEOUT": "",
			},
			want: "BEEBOX_DATABASE_STARTUP_TIMEOUT must not be empty",
		},
		{
			name: "invalid startup duration",
			values: map[string]string{
				"BEEBOX_DATABASE_URL":             testDatabaseURL,
				"BEEBOX_DATABASE_STARTUP_TIMEOUT": "later",
			},
			want: "invalid BEEBOX_DATABASE_STARTUP_TIMEOUT duration",
		},
		{
			name: "negative startup duration",
			values: map[string]string{
				"BEEBOX_DATABASE_URL":             testDatabaseURL,
				"BEEBOX_DATABASE_STARTUP_TIMEOUT": "-1s",
			},
			want: "BEEBOX_DATABASE_STARTUP_TIMEOUT must be greater than zero",
		},
		{
			name: "empty readiness duration",
			values: map[string]string{
				"BEEBOX_DATABASE_URL":               testDatabaseURL,
				"BEEBOX_DATABASE_READINESS_TIMEOUT": "",
			},
			want: "BEEBOX_DATABASE_READINESS_TIMEOUT must not be empty",
		},
		{
			name: "invalid readiness duration",
			values: map[string]string{
				"BEEBOX_DATABASE_URL":               testDatabaseURL,
				"BEEBOX_DATABASE_READINESS_TIMEOUT": "later",
			},
			want: "invalid BEEBOX_DATABASE_READINESS_TIMEOUT duration",
		},
		{
			name: "non positive readiness duration",
			values: map[string]string{
				"BEEBOX_DATABASE_URL":               testDatabaseURL,
				"BEEBOX_DATABASE_READINESS_TIMEOUT": "0s",
			},
			want: "BEEBOX_DATABASE_READINESS_TIMEOUT must be greater than zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(mapLookup(tt.values))
			if err == nil {
				t.Fatal("Load() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %q, want substring %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "super-secret") {
				t.Fatalf("Load() error leaks credential marker: %q", err)
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
