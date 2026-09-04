package config

import (
	"fmt"
	"os"
	"time"
)

const (
	envHTTPAddr        = "BEEBOX_HTTP_ADDR"
	envDatabaseURL     = "BEEBOX_DATABASE_URL"
	envPlansBaseURL    = "BEEBOX_PLANS_BASE_URL"
	envShutdownTimeout = "BEEBOX_SHUTDOWN_TIMEOUT"
	defaultHTTPAddr    = ":8082"
	defaultPlansBase   = "http://127.0.0.1:8081"
	defaultShutdown    = 10 * time.Second
)

type Config struct {
	HTTPAddr        string
	DatabaseURL     string
	PlansBaseURL    string
	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:        defaultHTTPAddr,
		DatabaseURL:     os.Getenv(envDatabaseURL),
		PlansBaseURL:    defaultPlansBase,
		ShutdownTimeout: defaultShutdown,
	}
	if v := os.Getenv(envHTTPAddr); v != "" {
		cfg.HTTPAddr = v
	}
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("%s is required", envDatabaseURL)
	}
	if v := os.Getenv(envPlansBaseURL); v != "" {
		cfg.PlansBaseURL = v
	}
	if v := os.Getenv(envShutdownTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", envShutdownTimeout, err)
		}
		if d <= 0 {
			return Config{}, fmt.Errorf("%s: must be greater than 0", envShutdownTimeout)
		}
		cfg.ShutdownTimeout = d
	}
	return cfg, nil
}
