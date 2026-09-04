package config

import (
	"fmt"
	"os"
	"time"
)

const (
	envHTTPAddr        = "BEEBOX_HTTP_ADDR"
	envShutdownTimeout = "BEEBOX_SHUTDOWN_TIMEOUT"
	envRequestTimeout  = "BEEBOX_REQUEST_TIMEOUT"
	defaultHTTPAddr    = ":8080"
	defaultShutdown    = 10 * time.Second
	defaultRequest     = 10 * time.Second
)

type Config struct {
	HTTPAddr        string
	ShutdownTimeout time.Duration
	RequestTimeout  time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:        defaultHTTPAddr,
		ShutdownTimeout: defaultShutdown,
		RequestTimeout:  defaultRequest,
	}

	if v := os.Getenv(envHTTPAddr); v != "" {
		cfg.HTTPAddr = v
	}

	if v := os.Getenv(envShutdownTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", envShutdownTimeout, err)
		}
		cfg.ShutdownTimeout = d
	}

	if v := os.Getenv(envRequestTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", envRequestTimeout, err)
		}
		cfg.RequestTimeout = d
	}

	return cfg, nil
}
