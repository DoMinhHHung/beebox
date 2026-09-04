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
	envProjectsBaseURL   = "BEEBOX_PROJECTS_BASE_URL"
	envInternalToken     = "BEEBOX_INTERNAL_TOKEN"
	envShutdownTimeout   = "BEEBOX_SHUTDOWN_TIMEOUT"
	envReadTimeout       = "BEEBOX_READ_TIMEOUT"
	envReadHeaderTimeout = "BEEBOX_READ_HEADER_TIMEOUT"
	envSessionTTL        = "BEEBOX_SESSION_TTL"
	defaultHTTPAddr      = ":8083"
	defaultProjectsBase  = "http://127.0.0.1:8082"
	defaultShutdown      = 10 * time.Second
	defaultRead          = 10 * time.Second
	defaultReadHeader    = 5 * time.Second
	defaultSessionTTL    = 7 * 24 * time.Hour
)

type Config struct {
	HTTPAddr          string
	DatabaseURL       string
	ProjectsBaseURL   string
	InternalToken     string
	ShutdownTimeout   time.Duration
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	SessionTTL        time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:          defaultHTTPAddr,
		DatabaseURL:       os.Getenv(envDatabaseURL),
		ProjectsBaseURL:   defaultProjectsBase,
		InternalToken:     os.Getenv(envInternalToken),
		ShutdownTimeout:   defaultShutdown,
		ReadTimeout:       defaultRead,
		ReadHeaderTimeout: defaultReadHeader,
		SessionTTL:        defaultSessionTTL,
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
	if v := os.Getenv(envProjectsBaseURL); v != "" {
		cfg.ProjectsBaseURL = v
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
	if cfg.SessionTTL, err = durationEnv(envSessionTTL, cfg.SessionTTL); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
