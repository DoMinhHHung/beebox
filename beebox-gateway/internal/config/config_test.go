package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv(envHTTPAddr, "")
	t.Setenv(envShutdownTimeout, "")
	t.Setenv(envRequestTimeout, "")
	t.Setenv(envReadTimeout, "")
	t.Setenv(envReadHeaderTimeout, "")
	t.Setenv(envPlansBaseURL, "")
	t.Setenv(envProjectsBaseURL, "")
	t.Setenv(envInternalToken, "")
	t.Setenv(envRateLimitRPS, "")
	t.Setenv(envRateLimitBurst, "")
	unset := []string{
		envHTTPAddr, envShutdownTimeout, envRequestTimeout, envReadTimeout, envReadHeaderTimeout,
		envPlansBaseURL, envProjectsBaseURL, envInternalToken, envRateLimitRPS, envRateLimitBurst,
	}
	for _, k := range unset {
		_ = os.Unsetenv(k)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != defaultHTTPAddr {
		t.Fatalf("addr=%q", cfg.HTTPAddr)
	}
	if cfg.ReadTimeout != 10*time.Second {
		t.Fatalf("read=%s", cfg.ReadTimeout)
	}
	if cfg.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("readHeader=%s", cfg.ReadHeaderTimeout)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Fatalf("shutdown=%s", cfg.ShutdownTimeout)
	}
	if cfg.PlansBaseURL != defaultPlansBaseURL || cfg.ProjectsBaseURL != defaultProjectsBaseURL {
		t.Fatalf("urls plans=%q projects=%q", cfg.PlansBaseURL, cfg.ProjectsBaseURL)
	}
}

func TestLoadTimeoutParseError(t *testing.T) {
	t.Setenv(envReadTimeout, "not-a-duration")
	_, err := Load()
	if err == nil {
		t.Fatalf("expected parse error")
	}
}

func TestLoadReadHeaderTimeoutParseError(t *testing.T) {
	t.Setenv(envReadHeaderTimeout, "abc")
	_, err := Load()
	if err == nil {
		t.Fatalf("expected parse error")
	}
}

func TestLoadRequestTimeoutParseError(t *testing.T) {
	t.Setenv(envRequestTimeout, "nope")
	_, err := Load()
	if err == nil {
		t.Fatalf("expected parse error")
	}
}

func TestLoadCustomTimeouts(t *testing.T) {
	t.Setenv(envReadTimeout, "3s")
	t.Setenv(envReadHeaderTimeout, "1s")
	t.Setenv(envShutdownTimeout, "15s")
	t.Setenv(envRequestTimeout, "2s")
	t.Setenv(envRateLimitRPS, "5")
	t.Setenv(envRateLimitBurst, "2")
	t.Setenv(envPlansBaseURL, "http://plans.local")
	t.Setenv(envProjectsBaseURL, "http://projects.local")
	t.Setenv(envInternalToken, "tok")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ReadTimeout != 3*time.Second || cfg.ReadHeaderTimeout != time.Second {
		t.Fatalf("read=%s header=%s", cfg.ReadTimeout, cfg.ReadHeaderTimeout)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Fatalf("shutdown=%s", cfg.ShutdownTimeout)
	}
	if cfg.InternalToken != "tok" || cfg.RateLimitBurst != 2 || cfg.RateLimitRPS != 5 {
		t.Fatalf("cfg=%+v", cfg)
	}
}
