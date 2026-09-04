package config

import "testing"

func TestLoadRequiresDatabaseAndToken(t *testing.T) {
	t.Setenv(envDatabaseURL, "")
	t.Setenv(envInternalToken, "")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error")
	}
	t.Setenv(envDatabaseURL, "postgres://beebox:beebox@127.0.0.1:5432/beebox?sslmode=disable")
	if _, err := Load(); err == nil {
		t.Fatalf("expected token error")
	}
	t.Setenv(envInternalToken, "dev-internal")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != defaultHTTPAddr || cfg.ProjectsBaseURL != defaultProjectsBase {
		t.Fatalf("cfg=%+v", cfg)
	}
	if cfg.SessionTTL != defaultSessionTTL {
		t.Fatalf("ttl=%s", cfg.SessionTTL)
	}
}
