package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	envHTTPAddr            = "BEEBOX_HTTP_ADDR"
	envShutdownTimeout     = "BEEBOX_SHUTDOWN_TIMEOUT"
	envRequestTimeout      = "BEEBOX_REQUEST_TIMEOUT"
	envReadTimeout         = "BEEBOX_READ_TIMEOUT"
	envReadHeaderTimeout   = "BEEBOX_READ_HEADER_TIMEOUT"
	envPlansBaseURL        = "BEEBOX_PLANS_BASE_URL"
	envProjectsBaseURL     = "BEEBOX_PROJECTS_BASE_URL"
	envIdentityBaseURL     = "BEEBOX_IDENTITY_BASE_URL"
	envInternalToken       = "BEEBOX_INTERNAL_TOKEN"
	envRateLimitRPS        = "BEEBOX_RATE_LIMIT_RPS"
	envRateLimitBurst      = "BEEBOX_RATE_LIMIT_BURST"
	defaultHTTPAddr        = ":8080"
	defaultShutdown        = 10 * time.Second
	defaultRequest         = 10 * time.Second
	defaultRead            = 10 * time.Second
	defaultReadHeader      = 5 * time.Second
	defaultPlansBaseURL    = "http://127.0.0.1:8081"
	defaultProjectsBaseURL = "http://127.0.0.1:8082"
	defaultIdentityBaseURL = "http://127.0.0.1:8083"
	defaultRateLimitRPS    = 20.0
	defaultRateLimitBurst  = 40
)

type Config struct {
	HTTPAddr          string
	ShutdownTimeout   time.Duration
	RequestTimeout    time.Duration
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	PlansBaseURL      string
	ProjectsBaseURL   string
	IdentityBaseURL   string
	InternalToken     string
	RateLimitRPS      float64
	RateLimitBurst    int
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:          defaultHTTPAddr,
		ShutdownTimeout:   defaultShutdown,
		RequestTimeout:    defaultRequest,
		ReadTimeout:       defaultRead,
		ReadHeaderTimeout: defaultReadHeader,
		PlansBaseURL:      defaultPlansBaseURL,
		ProjectsBaseURL:   defaultProjectsBaseURL,
		IdentityBaseURL:   defaultIdentityBaseURL,
		RateLimitRPS:      defaultRateLimitRPS,
		RateLimitBurst:    defaultRateLimitBurst,
	}

	if v := os.Getenv(envHTTPAddr); v != "" {
		cfg.HTTPAddr = v
	}
	if v := os.Getenv(envPlansBaseURL); v != "" {
		cfg.PlansBaseURL = v
	}
	if v := os.Getenv(envProjectsBaseURL); v != "" {
		cfg.ProjectsBaseURL = v
	}
	if v := os.Getenv(envIdentityBaseURL); v != "" {
		cfg.IdentityBaseURL = v
	}
	if v := os.Getenv(envInternalToken); v != "" {
		cfg.InternalToken = v
	}

	var err error
	if cfg.ShutdownTimeout, err = durationEnv(envShutdownTimeout, cfg.ShutdownTimeout, true); err != nil {
		return Config{}, err
	}
	if cfg.RequestTimeout, err = durationEnv(envRequestTimeout, cfg.RequestTimeout, false); err != nil {
		return Config{}, err
	}
	if cfg.ReadTimeout, err = durationEnv(envReadTimeout, cfg.ReadTimeout, true); err != nil {
		return Config{}, err
	}
	if cfg.ReadHeaderTimeout, err = durationEnv(envReadHeaderTimeout, cfg.ReadHeaderTimeout, true); err != nil {
		return Config{}, err
	}
	if cfg.RateLimitRPS, err = floatEnv(envRateLimitRPS, cfg.RateLimitRPS); err != nil {
		return Config{}, err
	}
	if cfg.RateLimitBurst, err = intEnv(envRateLimitBurst, cfg.RateLimitBurst); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func durationEnv(key string, fallback time.Duration, requirePositive bool) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if requirePositive && d <= 0 {
		return 0, fmt.Errorf("%s: must be greater than 0", key)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s: must be >= 0", key)
	}
	return d, nil
}

func floatEnv(key string, fallback float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s: must be greater than 0", key)
	}
	return n, nil
}

func intEnv(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s: must be greater than 0", key)
	}
	return n, nil
}
