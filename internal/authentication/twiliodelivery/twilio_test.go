package twiliodelivery

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureAccountSID() string   { return "AC" + strings.Repeat("0", 32) }
func fixtureAPIKeySID() string    { return "SK" + strings.Repeat("1", 32) }
func fixtureAPIKeySecret() string { return "fixture-api-key-secret" }

func completeTwilioConfig() map[string]string {
	return map[string]string{
		"BEEBOX_TWILIO_ACCOUNT_SID":    fixtureAccountSID(),
		"BEEBOX_TWILIO_API_KEY_SID":    fixtureAPIKeySID(),
		"BEEBOX_TWILIO_API_KEY_SECRET": fixtureAPIKeySecret(),
		"BEEBOX_TWILIO_FROM":           "+15551234567",
	}
}

func TestFromLookupValidatesAPIKeyConfiguration(t *testing.T) {
	values := completeTwilioConfig()
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	delivery, err := FromLookup(lookup)
	if err != nil || delivery == nil {
		t.Fatalf("FromLookup() delivery=%v err=%v", delivery, err)
	}
	if delivery.client.Timeout != defaultTimeout {
		t.Fatalf("default timeout = %v, want %v", delivery.client.Timeout, defaultTimeout)
	}

	for _, key := range []string{
		"BEEBOX_TWILIO_ACCOUNT_SID",
		"BEEBOX_TWILIO_API_KEY_SID",
		"BEEBOX_TWILIO_API_KEY_SECRET",
		"BEEBOX_TWILIO_FROM",
	} {
		t.Run("missing-"+key, func(t *testing.T) {
			partial := completeTwilioConfig()
			delete(partial, key)
			partialLookup := func(name string) (string, bool) { value, ok := partial[name]; return value, ok }
			if _, err := FromLookup(partialLookup); !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), fixtureAPIKeySecret()) {
				t.Fatalf("partial config error = %q", err)
			}
		})
	}
}

func TestFromLookupRejectsMalformedSIDsAndInvalidTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		value string
	}{
		{name: "account-sid-prefix", key: "BEEBOX_TWILIO_ACCOUNT_SID", value: "SK" + strings.Repeat("0", 32)},
		{name: "account-sid-length", key: "BEEBOX_TWILIO_ACCOUNT_SID", value: "AC1234"},
		{name: "api-key-prefix", key: "BEEBOX_TWILIO_API_KEY_SID", value: "AC" + strings.Repeat("1", 32)},
		{name: "api-key-non-hex", key: "BEEBOX_TWILIO_API_KEY_SID", value: "SK" + strings.Repeat("z", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := completeTwilioConfig()
			values[tc.key] = tc.value
			lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
			if _, err := FromLookup(lookup); !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), fixtureAPIKeySecret()) {
				t.Fatalf("invalid SID error = %q", err)
			}
		})
	}

	for _, raw := range []string{"0s", "31s", "not-a-duration"} {
		t.Run("timeout-"+raw, func(t *testing.T) {
			values := completeTwilioConfig()
			values["BEEBOX_TWILIO_TIMEOUT"] = raw
			lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
			if _, err := FromLookup(lookup); !errors.Is(err, ErrConfig) {
				t.Fatalf("invalid timeout error = %v", err)
			}
		})
	}

	values := completeTwilioConfig()
	values["BEEBOX_TWILIO_TIMEOUT"] = "30s"
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	delivery, err := FromLookup(lookup)
	if err != nil || delivery.client.Timeout != 30*time.Second {
		t.Fatalf("max timeout delivery=%v err=%v", delivery, err)
	}
}

func TestNewDeliveryRejectsPlaintextProductionEndpoint(t *testing.T) {
	if _, err := newDelivery(
		fixtureAccountSID(), fixtureAPIKeySID(), fixtureAPIKeySecret(), "+15551234567",
		&http.Client{Timeout: time.Second}, "http://provider.example", false,
	); !errors.Is(err, ErrConfig) {
		t.Fatalf("plaintext production endpoint error = %v", err)
	}
}

func TestDeliveryUsesAccountInURLAndAPIKeyForBasicAuth(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(*Delivery) error
		want string
	}{
		{
			name: "signup",
			want: "phone verification code",
			send: func(d *Delivery) error {
				return d.DeliverPhoneSignupCode(context.Background(), "+84901234567", "123456", time.Now().Add(10*time.Minute))
			},
		},
		{
			name: "signin",
			want: "sign-in code",
			send: func(d *Delivery) error {
				return d.DeliverPhoneSignInCode(context.Background(), "+84901234567", "654321", time.Now().Add(10*time.Minute))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			account := fixtureAccountSID()
			keySID := fixtureAPIKeySID()
			keySecret := fixtureAPIKeySecret()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/Accounts/"+account+"/Messages.json" {
					t.Fatalf("request = %s %s", r.Method, r.URL.Path)
				}
				user, pass, ok := r.BasicAuth()
				if !ok || user != keySID || pass != keySecret {
					t.Fatalf("provider auth user=%q ok=%v", user, ok)
				}
				if user == account {
					t.Fatal("account SID used as Basic Auth username")
				}
				payload, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				form, err := url.ParseQuery(string(payload))
				if err != nil {
					t.Fatal(err)
				}
				if form.Get("To") != "+84901234567" || form.Get("From") != "+15551234567" {
					t.Fatalf("provider addressing = %#v", form)
				}
				if !strings.Contains(form.Get("Body"), tc.want) || !strings.Contains(form.Get("Body"), "expires in 10 minutes") {
					t.Fatalf("message body = %q", form.Get("Body"))
				}
				w.WriteHeader(http.StatusCreated)
			}))
			defer server.Close()

			delivery, err := newDelivery(account, keySID, keySecret, "+15551234567", server.Client(), server.URL, true)
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

func TestDeliverySafeFailureDoesNotLeakProviderBodyOrAPIKeySecret(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("provider diagnostic body " + fixtureAPIKeySecret()))
	}))
	defer server.Close()

	delivery, err := newDelivery(
		fixtureAccountSID(), fixtureAPIKeySID(), fixtureAPIKeySecret(), "+15551234567",
		server.Client(), server.URL, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = delivery.DeliverPhoneSignInCode(context.Background(), "+84901234567", "654321", time.Now())
	if !errors.Is(err, ErrDelivery) || err.Error() != "SMS delivery failure" ||
		strings.Contains(err.Error(), fixtureAPIKeySecret()) || strings.Contains(err.Error(), "provider diagnostic") {
		t.Fatalf("delivery err=%q", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1", calls.Load())
	}
}

func TestDeliveryHonorsContextCancellationAndDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Second
	delivery, err := newDelivery(
		fixtureAccountSID(), fixtureAPIKeySID(), fixtureAPIKeySecret(), "+15551234567",
		client, server.URL, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = delivery.DeliverPhoneSignInCode(ctx, "+84901234567", "123456", time.Now())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v", err)
	}
	if calls.Load() > 1 {
		t.Fatalf("provider calls = %d, want at most 1", calls.Load())
	}
}
