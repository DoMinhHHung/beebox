package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	envHTTPAddr          = "BEEBOX_HTTP_ADDR"
	envDatabaseURL       = "BEEBOX_DATABASE_URL"
	envPlansBaseURL      = "BEEBOX_PLANS_BASE_URL"
	envShutdownTimeout   = "BEEBOX_SHUTDOWN_TIMEOUT"
	envReadTimeout       = "BEEBOX_READ_TIMEOUT"
	envReadHeaderTimeout = "BEEBOX_READ_HEADER_TIMEOUT"
	envInternalToken     = "BEEBOX_INTERNAL_TOKEN"
	envAllowOwnerHeader  = "BEEBOX_ALLOW_OWNER_HEADER"
	envOAuthKEK          = "BEEBOX_OAUTH_KEK"
	defaultHTTPAddr      = ":8082"
	defaultPlansBase     = "http://127.0.0.1:8081"
	defaultShutdown      = 10 * time.Second
	defaultRead          = 10 * time.Second
	defaultReadHeader    = 5 * time.Second
)

type Config struct {
	HTTPAddr          string
	DatabaseURL       string
	PlansBaseURL      string
	ShutdownTimeout   time.Duration
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	InternalToken     string
	AllowOwnerHeader  bool
	OAuthKEK          string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:          defaultHTTPAddr,
		DatabaseURL:       os.Getenv(envDatabaseURL),
		PlansBaseURL:      defaultPlansBase,
		ShutdownTimeout:   defaultShutdown,
		ReadTimeout:       defaultRead,
		ReadHeaderTimeout: defaultReadHeader,
		InternalToken:     os.Getenv(envInternalToken),
		AllowOwnerHeader:  envTruthy(os.Getenv(envAllowOwnerHeader)),
		OAuthKEK:          strings.TrimSpace(os.Getenv(envOAuthKEK)),
	}
	if v := os.Getenv(envHTTPAddr); v != "" {
		cfg.HTTPAddr = v
	}
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("%s is required", envDatabaseURL)
	}
	if strings.TrimSpace(cfg.InternalToken) == "" {
		return Config{}, fmt.Errorf("%s is required", envInternalToken)
	}
	if v := os.Getenv(envPlansBaseURL); v != "" {
		cfg.PlansBaseURL = v
	}
	var err error
	if cfg.ShutdownTimeout, err = durationEnv(envShutdownTimeout, cfg.ShutdownTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ReadTimeout, err = durationEnv(envReadTimeout, cfg.ReadTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ReadHeaderTimeout, err = durationEnv(envReadHeaderTimeout, cfg.ReadHeaderTimeout); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func envTruthy(v string) bool {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: must be greater than 0", name)
	}
	return d, nil
}
