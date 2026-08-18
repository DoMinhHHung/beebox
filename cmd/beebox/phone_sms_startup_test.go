package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/platform/config"
)

func TestRunRejectsInvalidSMSConfigurationBeforeListening(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secret string
		values map[string]string
	}{
		{name: "twilio-partial", secret: "fixture-twilio-secret", values: map[string]string{
			"BEEBOX_SMS_MODE": "twilio", "BEEBOX_TWILIO_ACCOUNT_SID": "AC" + strings.Repeat("0", 32), "BEEBOX_TWILIO_AUTH_TOKEN": "fixture-twilio-secret",
		}},
		{name: "vonage-partial", secret: "fixture-vonage-secret", values: map[string]string{
			"BEEBOX_SMS_MODE": "vonage", "BEEBOX_VONAGE_API_KEY": "fixture-key", "BEEBOX_VONAGE_API_SECRET": "fixture-vonage-secret",
		}},
		{name: "plivo-partial", secret: "fixture-plivo-secret", values: map[string]string{
			"BEEBOX_SMS_MODE": "plivo", "BEEBOX_PLIVO_AUTH_ID": "fixture-auth-id", "BEEBOX_PLIVO_AUTH_TOKEN": "fixture-plivo-secret",
		}},
		{name: "telnyx-partial", secret: "fixture-telnyx-secret", values: map[string]string{
			"BEEBOX_SMS_MODE": "telnyx", "BEEBOX_TELNYX_API_KEY": "fixture-telnyx-secret",
		}},
		{name: "unknown-mode", values: map[string]string{"BEEBOX_SMS_MODE": "unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := &fakeDatabasePool{ping: func(context.Context) error { return nil }}
			listenCalled := false
			lookup := testLookup(tc.values)

			err := runWithDependencies(
				context.Background(),
				testLogger(),
				lookup,
				runtimeDependencies{
					openDatabase: func(context.Context, string) (databasePool, error) {
						return pool, nil
					},
					buildHTTP: func(_ databasePool, lookup config.LookupEnv, health http.Handler) (http.Handler, error) {
						if _, _, err := buildSMSDelivery(lookup); err != nil {
							return nil, err
						}
						return health, nil
					},
					listen: func(string, string) (net.Listener, error) {
						listenCalled = true
						return nil, errors.New("unexpected listen")
					},
				},
				nil,
			)
			if !errors.Is(err, errSMSDeliveryConfig) {
				t.Fatalf("runWithDependencies() error = %v", err)
			}
			if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("startup error leaks SMS credential fixture: %q", err)
			}
			if listenCalled {
				t.Fatal("listener started after invalid SMS configuration")
			}
			if pool.closed != 1 {
				t.Fatalf("pool Close() calls = %d, want 1", pool.closed)
			}
		})
	}
}
