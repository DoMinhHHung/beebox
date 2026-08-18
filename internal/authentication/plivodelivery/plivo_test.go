package plivodelivery

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

func plivoSecret() string { return strings.Repeat("fixture_", 4) }

func TestFromLookupValidatesConfigTimeoutAndProductionHTTPS(t *testing.T) {
	secret := plivoSecret()
	values := map[string]string{
		"BEEBOX_PLIVO_AUTH_ID":    "fixture-auth-id",
		"BEEBOX_PLIVO_AUTH_TOKEN": secret,
		"BEEBOX_PLIVO_FROM":       "+15551234567",
		"BEEBOX_PLIVO_TIMEOUT":    "3s",
	}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	delivery, err := FromLookup(lookup)
	if err != nil || delivery == nil || delivery.client.Timeout != 3*time.Second {
		t.Fatalf("FromLookup() delivery=%v err=%v", delivery, err)
	}
	delete(values, "BEEBOX_PLIVO_FROM")
	if _, err := FromLookup(lookup); !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), secret) {
		t.Fatalf("partial config error = %q", err)
	}
	if _, err := newDelivery("fixture-auth-id", secret, "+15551234567", &http.Client{Timeout: time.Second}, "http://provider.example", false); !errors.Is(err, ErrConfig) {
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
			secret := plivoSecret()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/fixture-auth-id/Message/" {
					t.Fatalf("request = %s %s", r.Method, r.URL.Path)
				}
				user, pass, ok := r.BasicAuth()
				if !ok || user != "fixture-auth-id" || pass != secret {
					t.Fatal("missing provider authentication")
				}
				var payload struct {
					Src  string `json:"src"`
					Dst  string `json:"dst"`
					Text string `json:"text"`
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if payload.Src != "+15551234567" || payload.Dst != "+84901234567" || !strings.Contains(payload.Text, tc.want) {
					t.Fatalf("provider payload = %#v", payload)
				}
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"message":"message(s) queued","message_uuid":["ignored"]}`))
			}))
			defer server.Close()
			delivery, err := newDelivery("fixture-auth-id", secret, "+15551234567", server.Client(), server.URL, true)
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
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				_, _ = w.Write([]byte(strings.Repeat("provider-body", 20_000)))
			}))
			defer server.Close()
			secret := plivoSecret()
			delivery, err := newDelivery("fixture-auth-id", secret, "+15551234567", &http.Client{Timeout: time.Second}, server.URL, true)
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
	delivery, err := newDelivery("fixture-auth-id", plivoSecret(), "+15551234567", client, server.URL, true)
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
