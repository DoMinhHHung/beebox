package telnyxdelivery

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
	productionEndpoint = "https://api.telnyx.com/v2/messages"
	defaultTimeout     = 5 * time.Second
	maxResponseBytes   = 64 << 10
)

var (
	ErrConfig   = errors.New("SMS delivery configuration invalid")
	ErrDelivery = errors.New("SMS delivery failure")
)

type LookupEnv func(string) (string, bool)

type Delivery struct {
	apiKey   string
	from     string
	client   *http.Client
	endpoint string
}

var _ authentication.PhoneOTPDelivery = (*Delivery)(nil)

func FromLookup(lookup LookupEnv) (*Delivery, error) {
	apiKey, okKey := lookup("BEEBOX_TELNYX_API_KEY")
	from, okFrom := lookup("BEEBOX_TELNYX_FROM")
	if !okKey || !okFrom || apiKey == "" || from == "" || len(apiKey) > 256 || len(from) > 64 {
		return nil, ErrConfig
	}
	timeout, err := loadTimeout(lookup, "BEEBOX_TELNYX_TIMEOUT")
	if err != nil {
		return nil, ErrConfig
	}
	return newDelivery(apiKey, from, &http.Client{Timeout: timeout}, productionEndpoint, false)
}

func newDelivery(apiKey, from string, client *http.Client, endpoint string, allowHTTP bool) (*Delivery, error) {
	if apiKey == "" || from == "" || len(apiKey) > 256 || len(from) > 64 || client == nil {
		return nil, ErrConfig
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http")) {
		return nil, ErrConfig
	}
	return &Delivery{apiKey: apiKey, from: from, client: client, endpoint: strings.TrimRight(endpoint, "/")}, nil
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
		From string `json:"from"`
		To   string `json:"to"`
		Text string `json:"text"`
	}{From: d.from, To: destination, Text: body})
	if err != nil {
		return ErrDelivery
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(payload))
	if err != nil {
		return ErrDelivery
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.apiKey)
	resp, err := d.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrDelivery
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return ErrDelivery
	}
	return nil
}
