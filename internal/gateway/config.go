package gateway

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/DoMinhHHung/beebox/internal/requestcorrelation"
)

const (
	defaultListenAddress               = ":8080"
	defaultConnectTimeout              = 3 * time.Second
	defaultResponseHeaderTimeout       = 10 * time.Second
	defaultRequestTimeout              = 15 * time.Second
	defaultReadinessTimeout            = 2 * time.Second
	defaultShutdownTimeout             = 10 * time.Second
	defaultIdleConnTimeout             = 60 * time.Second
	defaultReadHeaderTimeout           = 5 * time.Second
	defaultReadTimeout                 = 10 * time.Second
	defaultWriteTimeout                = 30 * time.Second
	minimumConfiguredTimeout           = 100 * time.Millisecond
	maximumRequestTimeout              = 30 * time.Second
	maximumReadTimeout                 = 30 * time.Second
	maximumWriteTimeout                = 65 * time.Second
	maximumGeneralTimeout              = 5 * time.Minute
	serverWriteSafetyMargin            = 5 * time.Second
	defaultMaxBodyBytes          int64 = 1 << 20
	maxConfiguredBodyBytes       int64 = 16 << 20
)

type LookupEnv func(string) (string, bool)

type Config struct {
	ListenAddress         string
	IdentityBaseURL       *url.URL
	CorrelationKey        requestcorrelation.Key
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	RequestTimeout        time.Duration
	ReadinessTimeout      time.Duration
	ShutdownTimeout       time.Duration
	IdleConnTimeout       time.Duration
	ReadHeaderTimeout     time.Duration
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	MaxBodyBytes          int64
}

func LoadConfig(lookup LookupEnv) (Config, error) {
	if lookup == nil {
		return Config{}, fmt.Errorf("gateway environment lookup is required")
	}

	cfg := Config{
		ListenAddress:         defaultListenAddress,
		ConnectTimeout:        defaultConnectTimeout,
		ResponseHeaderTimeout: defaultResponseHeaderTimeout,
		RequestTimeout:        defaultRequestTimeout,
		ReadinessTimeout:      defaultReadinessTimeout,
		ShutdownTimeout:       defaultShutdownTimeout,
		IdleConnTimeout:       defaultIdleConnTimeout,
		ReadHeaderTimeout:     defaultReadHeaderTimeout,
		ReadTimeout:           defaultReadTimeout,
		WriteTimeout:          defaultWriteTimeout,
		MaxBodyBytes:          defaultMaxBodyBytes,
	}

	if value, ok := lookup("BEEBOX_GATEWAY_HTTP_ADDR"); ok {
		if value == "" {
			return Config{}, fmt.Errorf("BEEBOX_GATEWAY_HTTP_ADDR must not be empty")
		}
		cfg.ListenAddress = value
	}
	if err := validateListenAddress(cfg.ListenAddress); err != nil {
		return Config{}, fmt.Errorf("invalid BEEBOX_GATEWAY_HTTP_ADDR: %w", err)
	}

	rawUpstream, ok := lookup("BEEBOX_IDENTITY_UPSTREAM_URL")
	if !ok || rawUpstream == "" {
		return Config{}, fmt.Errorf("BEEBOX_IDENTITY_UPSTREAM_URL is required and must not be empty")
	}
	upstream, err := parseIdentityBaseURL(rawUpstream)
	if err != nil {
		return Config{}, fmt.Errorf("invalid BEEBOX_IDENTITY_UPSTREAM_URL: %w", err)
	}
	cfg.IdentityBaseURL = upstream

	key, err := requestcorrelation.LoadKey(requestcorrelation.LookupEnv(lookup))
	if err != nil {
		return Config{}, fmt.Errorf("invalid %s", requestcorrelation.KeyEnvironmentVariable)
	}
	cfg.CorrelationKey = key

	if cfg.ConnectTimeout, err = loadBoundedDuration(lookup, "BEEBOX_GATEWAY_CONNECT_TIMEOUT", cfg.ConnectTimeout, minimumConfiguredTimeout, maximumGeneralTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ResponseHeaderTimeout, err = loadBoundedDuration(lookup, "BEEBOX_GATEWAY_RESPONSE_HEADER_TIMEOUT", cfg.ResponseHeaderTimeout, minimumConfiguredTimeout, maximumGeneralTimeout); err != nil {
		return Config{}, err
	}
	if cfg.RequestTimeout, err = loadBoundedDuration(lookup, "BEEBOX_GATEWAY_REQUEST_TIMEOUT", cfg.RequestTimeout, minimumConfiguredTimeout, maximumRequestTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ReadinessTimeout, err = loadBoundedDuration(lookup, "BEEBOX_GATEWAY_READINESS_TIMEOUT", cfg.ReadinessTimeout, minimumConfiguredTimeout, maximumGeneralTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ShutdownTimeout, err = loadBoundedDuration(lookup, "BEEBOX_GATEWAY_SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout, minimumConfiguredTimeout, maximumGeneralTimeout); err != nil {
		return Config{}, err
	}
	if cfg.IdleConnTimeout, err = loadBoundedDuration(lookup, "BEEBOX_GATEWAY_IDLE_CONN_TIMEOUT", cfg.IdleConnTimeout, minimumConfiguredTimeout, maximumGeneralTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ReadHeaderTimeout, err = loadBoundedDuration(lookup, "BEEBOX_GATEWAY_READ_HEADER_TIMEOUT", cfg.ReadHeaderTimeout, minimumConfiguredTimeout, maximumReadTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ReadTimeout, err = loadBoundedDuration(lookup, "BEEBOX_GATEWAY_READ_TIMEOUT", cfg.ReadTimeout, minimumConfiguredTimeout, maximumReadTimeout); err != nil {
		return Config{}, err
	}
	if cfg.WriteTimeout, err = loadBoundedDuration(lookup, "BEEBOX_GATEWAY_WRITE_TIMEOUT", cfg.WriteTimeout, minimumConfiguredTimeout, maximumWriteTimeout); err != nil {
		return Config{}, err
	}
	if cfg.MaxBodyBytes, err = loadBodyLimit(lookup, "BEEBOX_GATEWAY_MAX_BODY_BYTES", cfg.MaxBodyBytes); err != nil {
		return Config{}, err
	}
	if err := validateServerDeadlineOrdering(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateServerDeadlineOrdering(cfg Config) error {
	if cfg.ReadTimeout < cfg.ReadHeaderTimeout {
		return fmt.Errorf("BEEBOX_GATEWAY_READ_TIMEOUT must be greater than or equal to BEEBOX_GATEWAY_READ_HEADER_TIMEOUT")
	}
	minimumWrite := cfg.ReadTimeout + cfg.RequestTimeout + serverWriteSafetyMargin
	if cfg.WriteTimeout < minimumWrite {
		return fmt.Errorf("BEEBOX_GATEWAY_WRITE_TIMEOUT must be at least read timeout + request timeout + %s", serverWriteSafetyMargin)
	}
	return nil
}

func parseIdentityBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("must be a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("userinfo is not allowed")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("query and fragment are not allowed")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("path must be empty or /")
	}
	if parsed.RawPath != "" {
		return nil, fmt.Errorf("escaped path is not allowed")
	}
	parsed.Path = ""
	return parsed, nil
}

func loadBoundedDuration(lookup LookupEnv, name string, fallback, minimum, maximum time.Duration) (time.Duration, error) {
	value, ok := lookup(name)
	if !ok {
		return fallback, nil
	}
	if value == "" {
		return 0, fmt.Errorf("%s must not be empty", name)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be between %s and %s", name, minimum, maximum)
	}
	return parsed, nil
}

func loadBodyLimit(lookup LookupEnv, name string, fallback int64) (int64, error) {
	value, ok := lookup(name)
	if !ok {
		return fallback, nil
	}
	if value == "" {
		return 0, fmt.Errorf("%s must not be empty", name)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 || parsed > maxConfiguredBodyBytes {
		return 0, fmt.Errorf("%s must be between 1 and %d bytes", name, maxConfiguredBodyBytes)
	}
	return parsed, nil
}

func validateListenAddress(addr string) error {
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
