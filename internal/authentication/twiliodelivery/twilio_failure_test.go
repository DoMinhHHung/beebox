package twiliodelivery

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

func TestDeliveryClassifies4xx429And5xxSafelyWithoutRetry(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				_, _ = w.Write([]byte(strings.Repeat("provider-body-"+fixtureAPIKeySecret(), 20_000)))
			}))
			defer server.Close()
			delivery, err := newDelivery(
				fixtureAccountSID(), fixtureAPIKeySID(), fixtureAPIKeySecret(), "+15551234567",
				&http.Client{Timeout: time.Second}, server.URL, true,
			)
			if err != nil {
				t.Fatal(err)
			}
			err = delivery.DeliverPhoneSignInCode(context.Background(), "+84901234567", "123456", time.Now())
			if !errors.Is(err, ErrDelivery) || err.Error() != "SMS delivery failure" ||
				strings.Contains(err.Error(), fixtureAPIKeySecret()) || strings.Contains(err.Error(), "provider-body") {
				t.Fatalf("status %d error = %q", status, err)
			}
			if calls.Load() != 1 {
				t.Fatalf("status %d provider calls = %d, want exactly 1", status, calls.Load())
			}
		})
	}
}
