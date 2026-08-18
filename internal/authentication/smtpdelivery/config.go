package smtpdelivery

import (
	"context"
	"strconv"
	"time"
)

type LookupEnv func(string) (string, bool)

type Sender interface {
	DeliverVerificationCode(context.Context, string, string, time.Time) error
	DeliverPasswordResetCode(context.Context, string, string, time.Time) error
	DeliverSignInCode(context.Context, string, string, time.Time) error
}

type unavailable struct{}

func (unavailable) DeliverVerificationCode(context.Context, string, string, time.Time) error {
	return ErrDelivery
}

func (unavailable) DeliverPasswordResetCode(context.Context, string, string, time.Time) error {
	return ErrDelivery
}

func (unavailable) DeliverSignInCode(context.Context, string, string, time.Time) error {
	return ErrDelivery
}

// FromLookup returns an unavailable sender when SMTP is intentionally not
// configured. This keeps process startup independent of provider availability;
// reachable authentication lifecycles still receive stable delivery-unavailable
// behavior after committing their security-state correctness boundary.
func FromLookup(lookup LookupEnv) (Sender, error) {
	address, hasAddress := lookup("BEEBOX_SMTP_ADDR")
	if !hasAddress || address == "" {
		return unavailable{}, nil
	}
	from, ok := lookup("BEEBOX_SMTP_FROM")
	if !ok || from == "" {
		return nil, ErrConfig
	}
	modeValue, ok := lookup("BEEBOX_SMTP_TLS_MODE")
	if !ok || modeValue == "" {
		return nil, ErrConfig
	}
	username, _ := lookup("BEEBOX_SMTP_USERNAME")
	password, _ := lookup("BEEBOX_SMTP_PASSWORD")
	timeout := defaultTimeout
	if raw, ok := lookup("BEEBOX_SMTP_TIMEOUT"); ok {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return nil, ErrConfig
		}
		timeout = parsed
	}
	if raw, ok := lookup("BEEBOX_SMTP_REQUIRE_AUTH"); ok {
		requireAuth, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, ErrConfig
		}
		if requireAuth && (username == "" || password == "") {
			return nil, ErrConfig
		}
	}
	delivery, err := New(Config{
		Address:  address,
		From:     from,
		Username: username,
		Password: password,
		TLSMode:  TLSMode(modeValue),
		Timeout:  timeout,
	})
	if err != nil {
		return nil, ErrConfig
	}
	return delivery, nil
}
