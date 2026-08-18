package twiliodelivery

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/authentication"
)

const (
	productionBaseURL = "https://api.twilio.com/2010-04-01"
	defaultTimeout    = 5 * time.Second
	maxResponseBytes  = 64 << 10
)

var (
	ErrConfig   = errors.New("SMS delivery configuration invalid")
	ErrDelivery = errors.New("SMS delivery failure")
	accountSID  = regexp.MustCompile(`^AC[0-9a-fA-F]{32}$`)
)

type LookupEnv func(string) (string, bool)

type Delivery struct {
	accountSID string
	authToken  string
	from       string
	client     *http.Client
	baseURL    string
}

var _ authentication.PhoneOTPDelivery = (*Delivery)(nil)

func FromLookup(lookup LookupEnv) (*Delivery, error) {
	account, okAccount := lookup("BEEBOX_TWILIO_ACCOUNT_SID")
	token, okToken := lookup("BEEBOX_TWILIO_AUTH_TOKEN")
	from, okFrom := lookup("BEEBOX_TWILIO_FROM")
	if !okAccount || !okToken || !okFrom || account == "" || token == "" || from == "" || !accountSID.MatchString(account) || len(from) > 64 {
		return nil, ErrConfig
	}
	timeout := defaultTimeout
	if raw, ok := lookup("BEEBOX_TWILIO_TIMEOUT"); ok {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 || parsed > 30*time.Second {
			return nil, ErrConfig
		}
		timeout = parsed
	}
	delivery, err := newDelivery(account, token, from, &http.Client{Timeout: timeout}, productionBaseURL, false)
	if err != nil {
		return nil, ErrConfig
	}
	return delivery, nil
}

func newDelivery(account, token, from string, client *http.Client, baseURL string, allowHTTP bool) (*Delivery, error) {
	if !accountSID.MatchString(account) || token == "" || from == "" || client == nil || baseURL == "" {
		return nil, ErrConfig
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http")) {
		return nil, ErrConfig
	}
	return &Delivery{accountSID: account, authToken: token, from: from, client: client, baseURL: strings.TrimRight(baseURL, "/")}, nil
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
	values := url.Values{}
	values.Set("To", destination)
	values.Set("From", d.from)
	values.Set("Body", body)
	endpoint := d.baseURL + "/Accounts/" + url.PathEscape(d.accountSID) + "/Messages.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return ErrDelivery
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(d.accountSID, d.authToken)
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
