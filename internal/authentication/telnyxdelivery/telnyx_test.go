package telnyxdelivery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func telnyxSecret() string { return strings.Repeat("fixture_", 4) }

func TestFromLookupValidatesConfigTimeoutAndProductionHTTPS(t *testing.T) {
	secret := telnyxSecret()
	values := map[string]string{
		"BEEBOX_TELNYX_API_KEY": secret,
		"BEEBOX_TELNYX_FROM":    "+15551234567",
		"BEEBOX_TELNYX_TIMEOUT": "3s",
	}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	delivery, err := FromLookup(lookup)
	if err != nil || delivery == nil || delivery.client.Timeout != 3*time.Second {
		t.Fatalf("FromLookup() delivery=%v err=%v", delivery, err)
	}
	delete(values, "BEEBOX_TELNYX_FROM")
	if _, err := FromLookup(lookup); !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), secret) {
		t.Fatalf("partial config error = %q", err)
	}
	if _, err := newDelivery(secret, "+15551234567", &http.Client{Timeout: time.Second}, "http://provider.example/v2/messages", false); !errors.Is(err, ErrConfig) {
		t.Fatalf("plaintext production endpoint error = %v", err)
	}
}

func TestDeliveryMapsProviderRequestAndPurposesWithoutRetry(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(*Delivery) error
		want string
	}{
		{name: "signup", want: "phone verification code", send: func(d *Delivery) error { return d.DeliverPhoneSignupCode(context.Background(), "+84901234567", "123456", time.Now()) }},
		{name: "signin", want: "sign-in code", send: func(d *Delivery) error { return d.DeliverPhoneSignInCode(context.Background(), "+84901234567", "654321", time.Now()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			secret := telnyxSecret()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/v2/messages" {
					t.Fatalf("request = %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer "+secret {
					t.Fatal("missing provider authentication")
				}
				var payload struct {
					From string `json:"from"`
					To   string `json:"to"`
					Text string `json:"text"`
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if payload.From != "+15551234567" || payload.To != "+84901234567" || !strings.Contains(payload.Text, tc.want) {
					t.Fatalf("provider payload = %#v", payload)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":{"id":"ignored","to":[{"status":"queued"}]}}`))
			}))
			defer server.Close()
			delivery, err := newDelivery(secret, "+15551234567", server.Client(), server.URL+"/v2/messages", true)
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

func TestDeliveryClassifiesProviderFailuresSafelyAndBoundsResponse(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				_, _ = w.Write([]byte(strings.Repeat("provider-body", 20_000)))
			}))
			defer server.Close()
			secret := telnyxSecret()
			delivery, err := newDelivery(secret, "+15551234567", &http.Client{Timeout: time.Second}, server.URL+"/v2/messages", true)
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Second
	delivery, err := newDelivery(telnyxSecret(), "+15551234567", client, server.URL+"/v2/messages", true)
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
