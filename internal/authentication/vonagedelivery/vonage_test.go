package vonagedelivery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func vonageSecret() string { return strings.Repeat("fixture_", 4) }

func TestFromLookupValidatesConfigTimeoutAndProductionHTTPS(t *testing.T) {
	secret := vonageSecret()
	values := map[string]string{
		"BEEBOX_VONAGE_API_KEY":    "fixture-key",
		"BEEBOX_VONAGE_API_SECRET": secret,
		"BEEBOX_VONAGE_FROM":       "+15551234567",
		"BEEBOX_VONAGE_TIMEOUT":    "3s",
	}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	delivery, err := FromLookup(lookup)
	if err != nil || delivery == nil || delivery.client.Timeout != 3*time.Second {
		t.Fatalf("FromLookup() delivery=%v err=%v", delivery, err)
	}
	delete(values, "BEEBOX_VONAGE_FROM")
	if _, err := FromLookup(lookup); !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), secret) {
		t.Fatalf("partial config error = %q", err)
	}
	if _, err := newDelivery("fixture-key", secret, "+15551234567", &http.Client{Timeout: time.Second}, "http://provider.example", false); !errors.Is(err, ErrConfig) {
		t.Fatalf("plaintext production endpoint error = %v", err)
	}
}

func TestDeliveryMapsProviderRequestAndPurposesWithoutRetry(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		send func(*Delivery) error
	}{
		{
			name: "signup",
			want: "phone verification code",
			send: func(d *Delivery) error {
				return d.DeliverPhoneSignupCode(context.Background(), "+84901234567", "123456", time.Now())
			},
		},
		{
			name: "signin",
			want: "sign-in code",
			send: func(d *Delivery) error {
				return d.DeliverPhoneSignInCode(context.Background(), "+84901234567", "654321", time.Now())
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			secret := vonageSecret()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/sms/json" {
					t.Fatalf("request = %s %s", r.Method, r.URL.Path)
				}
				user, pass, ok := r.BasicAuth()
				if !ok || user != "fixture-key" || pass != secret {
					t.Fatal("missing provider authentication")
				}
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.Form.Get("to") != "84901234567" || r.Form.Get("from") != "15551234567" || !strings.Contains(r.Form.Get("text"), tc.want) {
					t.Fatalf("provider request = %#v", r.Form)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"message-count":"1","messages":[{"status":"0","message-id":"ignored"}]}`))
			}))
			defer server.Close()
			delivery, err := newDelivery("fixture-key", secret, "+15551234567", server.Client(), server.URL, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.send(delivery); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatalf("provider calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestDeliveryClassifiesFailuresSafelyAndBoundsResponse(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{name: "provider-status", status: http.StatusOK, body: `{"messages":[{"status":"4","error-text":"provider detail"}]}`},
		{name: "400", status: http.StatusBadRequest, body: "provider body"},
		{name: "429", status: http.StatusTooManyRequests, body: "provider body"},
		{name: "500-large", status: http.StatusInternalServerError, body: strings.Repeat("provider-body", 20_000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			secret := vonageSecret()
			delivery, err := newDelivery("fixture-key", secret, "BeeBox", &http.Client{Timeout: time.Second}, server.URL, true)
			if err != nil {
				t.Fatal(err)
			}
			err = delivery.DeliverPhoneSignInCode(context.Background(), "+84901234567", "123456", time.Now())
			if !errors.Is(err, ErrDelivery) || err.Error() != "SMS delivery failure" || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "provider") {
				t.Fatalf("delivery error = %q", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("provider calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestDeliveryHonorsCancellationWithoutSecondRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Second
	delivery, err := newDelivery("fixture-key", vonageSecret(), "BeeBox", client, server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := delivery.DeliverPhoneSignupCode(ctx, "+84901234567", "123456", time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v", err)
	}
	if calls.Load() > 1 {
		t.Fatalf("provider calls = %d, want at most 1", calls.Load())
	}
}
