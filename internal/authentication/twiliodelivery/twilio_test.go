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

func fixtureAccountSID() string { return "AC" + strings.Repeat("0", 32) }
func fixtureAuthValue() string   { return strings.Repeat("fixture_", 4) }

func TestFromLookupDefaultsDisabledAndRejectsPartialTwilio(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	if sender, enabled, err := FromLookup(lookup); err != nil || enabled || sender != nil {
		t.Fatalf("disabled = sender=%v enabled=%v err=%v", sender, enabled, err)
	}
	authValue := fixtureAuthValue()
	values := map[string]string{
		"BEEBOX_SMS_MODE":           "twilio",
		"BEEBOX_TWILIO_ACCOUNT_SID": fixtureAccountSID(),
		"BEEBOX_TWILIO_AUTH_TOKEN":  authValue,
	}
	lookup = func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	if _, _, err := FromLookup(lookup); !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), authValue) {
		t.Fatalf("partial config error = %q", err)
	}
}

func TestDeliverySendsExactlyOnePurposeSpecificRequest(t *testing.T) {
	var calls atomic.Int32
	account := fixtureAccountSID()
	authValue := fixtureAuthValue()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/Accounts/"+account+"/Messages.json" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != account || pass != authValue {
			t.Fatal("missing provider authentication")
		}
		payload, err := io.ReadAll(r.Body)
		if err != nil { t.Fatal(err) }
		form, err := url.ParseQuery(string(payload))
		if err != nil { t.Fatal(err) }
		if form.Get("To") != "+84901234567" || form.Get("From") != "+15551234567" {
			t.Fatalf("provider addressing = %#v", form)
		}
		if !strings.Contains(form.Get("Body"), "phone verification code") || strings.Contains(form.Get("Body"), "sign-in") {
			t.Fatalf("signup body = %q", form.Get("Body"))
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	delivery, err := newDelivery(account, authValue, "+15551234567", server.Client(), server.URL)
	if err != nil { t.Fatal(err) }
	if err := delivery.DeliverPhoneSignupCode(context.Background(), "+84901234567", "123456", time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 { t.Fatalf("provider calls = %d, want 1", calls.Load()) }
}

func TestDeliverySignInPurposeAndSafeFailures(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil { t.Fatal(err) }
		if !strings.Contains(r.Form.Get("Body"), "sign-in code") { t.Fatalf("signin body = %q", r.Form.Get("Body")) }
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("provider diagnostic body"))
	}))
	defer server.Close()
	authValue := fixtureAuthValue()
	delivery, err := newDelivery(fixtureAccountSID(), authValue, "+15551234567", server.Client(), server.URL)
	if err != nil { t.Fatal(err) }
	err = delivery.DeliverPhoneSignInCode(context.Background(), "+84901234567", "654321", time.Now())
	if !errors.Is(err, ErrDelivery) || strings.Contains(err.Error(), authValue) || calls.Load() != 1 {
		t.Fatalf("delivery err=%q calls=%d", err, calls.Load())
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
	delivery, err := newDelivery(fixtureAccountSID(), fixtureAuthValue(), "+15551234567", client, server.URL)
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = delivery.DeliverPhoneSignInCode(ctx, "+84901234567", "123456", time.Now())
	if !errors.Is(err, context.Canceled) { t.Fatalf("cancel error = %v", err) }
	if calls.Load() > 1 { t.Fatalf("provider calls = %d, want at most 1", calls.Load()) }
}
