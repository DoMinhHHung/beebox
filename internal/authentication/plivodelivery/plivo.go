package plivodelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/authentication"
)

const (
	productionBaseURL = "https://api.plivo.com/v1/Account"
	defaultTimeout    = 5 * time.Second
	maxResponseBytes  = 64 << 10
)

var (
	ErrConfig   = errors.New("SMS delivery configuration invalid")
	ErrDelivery = errors.New("SMS delivery failure")
)

type LookupEnv func(string) (string, bool)

type Delivery struct {
	authID    string
	authToken string
	from      string
	client    *http.Client
	baseURL   string
}

var _ authentication.PhoneOTPDelivery = (*Delivery)(nil)

func FromLookup(lookup LookupEnv) (*Delivery, error) {
	authID, okID := lookup("BEEBOX_PLIVO_AUTH_ID")
	authToken, okToken := lookup("BEEBOX_PLIVO_AUTH_TOKEN")
	from, okFrom := lookup("BEEBOX_PLIVO_FROM")
	if !okID || !okToken || !okFrom || authID == "" || authToken == "" || from == "" || len(authID) > 128 || len(authToken) > 256 || len(from) > 64 {
		return nil, ErrConfig
	}
	timeout, err := loadTimeout(lookup, "BEEBOX_PLIVO_TIMEOUT")
	if err != nil {
		return nil, ErrConfig
	}
	return newDelivery(authID, authToken, from, &http.Client{Timeout: timeout}, productionBaseURL, false)
}

func newDelivery(authID, authToken, from string, client *http.Client, baseURL string, allowHTTP bool) (*Delivery, error) {
	if authID == "" || authToken == "" || from == "" || len(authID) > 128 || len(authToken) > 256 || len(from) > 64 || client == nil {
		return nil, ErrConfig
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http")) {
		return nil, ErrConfig
	}
	return &Delivery{authID: authID, authToken: authToken, from: from, client: client, baseURL: strings.TrimRight(baseURL, "/")}, nil
}

func loadTimeout(lookup LookupEnv, key string) (time.Duration, error) {
	timeout := defaultTimeout
	if raw, ok := lookup(key); ok {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 || parsed > 30*time.Second {
			return 0, ErrConfig
		}
		timeout = parsed
	}
	return timeout, nil
}

func (d *Delivery) DeliverPhoneSignupCode(ctx context.Context, destination, code string, _ time.Time) error {
	return d.send(ctx, destination, "Your BeeBox phone verification code is "+code+". It expires in 10 minutes.")
}

func (d *Delivery) DeliverPhoneSignInCode(ctx context.Context, destination, code string, _ time.Time) error {
	return d.send(ctx, destination, "Your BeeBox sign-in code is "+code+". It expires in 10 minutes.")
}

func (d *Delivery) send(ctx context.Context, destination, body string) error {
	if d == nil || d.client == nil || destination == "" || body == "" {
		return ErrDelivery
	}
	payload, err := json.Marshal(struct {
		Src  string `json:"src"`
		Dst  string `json:"dst"`
		Text string `json:"text"`
	}{Src: d.from, Dst: destination, Text: body})
	if err != nil {
		return ErrDelivery
	}
	endpoint := d.baseURL + "/" + url.PathEscape(d.authID) + "/Message/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return ErrDelivery
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(d.authID, d.authToken)
	resp, err := d.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrDelivery
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return ErrDelivery
	}
	return nil
}
