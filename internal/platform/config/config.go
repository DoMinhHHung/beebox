package config

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

const (
	defaultHTTPAddr        = ":8080"
	defaultShutdownTimeout = 10 * time.Second
)

type Config struct {
	HTTPAddr        string
	ShutdownTimeout time.Duration
}

type LookupEnv func(string) (string, bool)

func Load(lookup LookupEnv) (Config, error) {
	cfg := Config{
		HTTPAddr:        defaultHTTPAddr,
		ShutdownTimeout: defaultShutdownTimeout,
	}

	if value, ok := lookup("BEEBOX_HTTP_ADDR"); ok {
		if value == "" {
			return Config{}, fmt.Errorf("BEEBOX_HTTP_ADDR must not be empty")
		}
		cfg.HTTPAddr = value
	}

	if err := validateHTTPAddr(cfg.HTTPAddr); err != nil {
		return Config{}, fmt.Errorf("invalid BEEBOX_HTTP_ADDR: %w", err)
	}

	if value, ok := lookup("BEEBOX_SHUTDOWN_TIMEOUT"); ok {
		if value == "" {
			return Config{}, fmt.Errorf("BEEBOX_SHUTDOWN_TIMEOUT must not be empty")
		}

		timeout, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("invalid BEEBOX_SHUTDOWN_TIMEOUT: %w", err)
		}
		if timeout <= 0 {
			return Config{}, fmt.Errorf("BEEBOX_SHUTDOWN_TIMEOUT must be greater than zero")
		}

		cfg.ShutdownTimeout = timeout
	}

	return cfg, nil
}

func validateHTTPAddr(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be numeric")
	}
	if portNumber < 0 || portNumber > 65535 {
		return fmt.Errorf("port must be between 0 and 65535")
	}

	return nil
}
