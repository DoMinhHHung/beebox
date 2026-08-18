package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

const (
	defaultHTTPAddr                 = ":8080"
	defaultShutdownTimeout          = 10 * time.Second
	defaultDatabaseStartupTimeout   = 5 * time.Second
	defaultDatabaseReadinessTimeout = time.Second
	defaultDatabaseMigrationTimeout = 30 * time.Second
	defaultKDFConcurrency           = 2
)

type Config struct {
	HTTPAddr                 string
	ShutdownTimeout          time.Duration
	DatabaseURL              string
	DatabaseStartupTimeout   time.Duration
	DatabaseReadinessTimeout time.Duration
	KDFConcurrency           int
}

type MigrationConfig struct {
	DatabaseURL              string
	DatabaseStartupTimeout   time.Duration
	DatabaseMigrationTimeout time.Duration
}

type LookupEnv func(string) (string, bool)

func Load(lookup LookupEnv) (Config, error) {
	cfg := Config{
		HTTPAddr:                 defaultHTTPAddr,
		ShutdownTimeout:          defaultShutdownTimeout,
		DatabaseStartupTimeout:   defaultDatabaseStartupTimeout,
		DatabaseReadinessTimeout: defaultDatabaseReadinessTimeout,
		KDFConcurrency:           defaultKDFConcurrency,
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
	databaseURL, err := loadDatabaseURL(lookup)
	if err != nil {
		return Config{}, err
	}
	cfg.DatabaseURL = databaseURL
	cfg.ShutdownTimeout, err = loadPositiveDuration(lookup, "BEEBOX_SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout)
	if err != nil {
		return Config{}, err
	}
	cfg.DatabaseStartupTimeout, err = loadPositiveDuration(lookup, "BEEBOX_DATABASE_STARTUP_TIMEOUT", cfg.DatabaseStartupTimeout)
	if err != nil {
		return Config{}, err
	}
	cfg.DatabaseReadinessTimeout, err = loadPositiveDuration(lookup, "BEEBOX_DATABASE_READINESS_TIMEOUT", cfg.DatabaseReadinessTimeout)
	if err != nil {
		return Config{}, err
	}
	cfg.KDFConcurrency, err = loadBoundedPositiveInt(lookup, "BEEBOX_KDF_CONCURRENCY", cfg.KDFConcurrency, 64)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadMigration(lookup LookupEnv) (MigrationConfig, error) {
	databaseURL, err := loadDatabaseURL(lookup)
	if err != nil {
		return MigrationConfig{}, err
	}
	startupTimeout, err := loadPositiveDuration(lookup, "BEEBOX_DATABASE_STARTUP_TIMEOUT", defaultDatabaseStartupTimeout)
	if err != nil {
		return MigrationConfig{}, err
	}
	migrationTimeout, err := loadPositiveDuration(lookup, "BEEBOX_DATABASE_MIGRATION_TIMEOUT", defaultDatabaseMigrationTimeout)
	if err != nil {
		return MigrationConfig{}, err
	}
	return MigrationConfig{
		DatabaseURL:              databaseURL,
		DatabaseStartupTimeout:   startupTimeout,
		DatabaseMigrationTimeout: migrationTimeout,
	}, nil
}

func loadDatabaseURL(lookup LookupEnv) (string, error) {
	value, ok := lookup("BEEBOX_DATABASE_URL")
	if !ok || value == "" {
		return "", fmt.Errorf("BEEBOX_DATABASE_URL is required and must not be empty")
	}
	if err := validateDatabaseURL(value); err != nil {
		return "", err
	}
	return value, nil
}

func loadPositiveDuration(lookup LookupEnv, name string, defaultValue time.Duration) (time.Duration, error) {
	value, ok := lookup(name)
	if !ok {
		return defaultValue, nil
	}
	if value == "" {
		return 0, fmt.Errorf("%s must not be empty", name)
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s duration", name)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return duration, nil
}

func loadBoundedPositiveInt(lookup LookupEnv, name string, defaultValue, maxValue int) (int, error) {
	value, ok := lookup(name)
	if !ok {
		return defaultValue, nil
	}
	if value == "" {
		return 0, fmt.Errorf("%s must not be empty", name)
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 || n > maxValue {
		return 0, fmt.Errorf("%s must be between 1 and %d", name, maxValue)
	}
	return n, nil
}

func validateDatabaseURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("BEEBOX_DATABASE_URL must be a valid PostgreSQL URI")
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return fmt.Errorf("BEEBOX_DATABASE_URL must use the postgres or postgresql scheme")
	}
	if parsed.Host == "" {
		return fmt.Errorf("BEEBOX_DATABASE_URL must include a host")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("BEEBOX_DATABASE_URL must not include a fragment")
	}
	return nil
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
