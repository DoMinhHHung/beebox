package vonagedelivery

import (
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
	productionBaseURL = "https://rest.nexmo.com"
	defaultTimeout    = 5 * time.Second
	maxResponseBytes  = 64 << 10
)

var (
	ErrConfig   = errors.New("SMS delivery configuration invalid")
	ErrDelivery = errors.New("SMS delivery failure")
)

type LookupEnv func(string) (string, bool)

type Delivery struct {
	apiKey    string
	apiSecret string
	from      string
	client    *http.Client
	baseURL   string
}

var _ authentication.PhoneOTPDelivery = (*Delivery)(nil)

func FromLookup(lookup LookupEnv) (*Delivery, error) {
	apiKey, okKey := lookup("BEEBOX_VONAGE_API_KEY")
	apiSecret, okSecret := lookup("BEEBOX_VONAGE_API_SECRET")
	from, okFrom := lookup("BEEBOX_VONAGE_FROM")
	if !okKey || !okSecret || !okFrom || apiKey == "" || apiSecret == "" || from == "" || len(apiKey) > 128 || len(apiSecret) > 256 || len(from) > 64 {
		return nil, ErrConfig
	}
	timeout, err := loadTimeout(lookup, "BEEBOX_VONAGE_TIMEOUT")
	if err != nil {
		return nil, ErrConfig
	}
	return newDelivery(apiKey, apiSecret, from, &http.Client{Timeout: timeout}, productionBaseURL, false)
}

func newDelivery(apiKey, apiSecret, from string, client *http.Client, baseURL string, allowHTTP bool) (*Delivery, error) {
	if apiKey == "" || apiSecret == "" || from == "" || len(apiKey) > 128 || len(apiSecret) > 256 || len(from) > 64 || client == nil {
		return nil, ErrConfig
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http")) {
		return nil, ErrConfig
	}
	return &Delivery{apiKey: apiKey, apiSecret: apiSecret, from: from, client: client, baseURL: strings.TrimRight(baseURL, "/")}, nil
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
	form := url.Values{}
	form.Set("from", providerNumber(d.from))
	form.Set("to", providerNumber(destination))
	form.Set("text", body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+"/sms/json", strings.NewReader(form.Encode()))
	if err != nil {
		return ErrDelivery
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(d.apiKey, d.apiSecret)
	resp, err := d.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrDelivery
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(payload) > maxResponseBytes || resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return ErrDelivery
	}
	var result struct {
		Messages []struct {
			Status string `json:"status"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(payload, &result); err != nil || len(result.Messages) != 1 || result.Messages[0].Status != "0" {
		return ErrDelivery
	}
	return nil
}

func providerNumber(value string) string {
	return strings.TrimPrefix(value, "+")
}
