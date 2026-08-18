package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/authentication/twiliodelivery"
	"github.com/DoMinhHHung/beebox/internal/platform/config"
)

func TestRunRejectsPartialSMSConfigurationBeforeListening(t *testing.T) {
	pool := &fakeDatabasePool{ping: func(context.Context) error { return nil }}
	listenCalled := false
	authValue := strings.Repeat("fixture_", 4)
	lookup := testLookup(map[string]string{
		"BEEBOX_SMS_MODE":           "twilio",
		"BEEBOX_TWILIO_ACCOUNT_SID": "AC" + strings.Repeat("0", 32),
		"BEEBOX_TWILIO_AUTH_TOKEN":  authValue,
	})

	err := runWithDependencies(
		context.Background(),
		testLogger(),
		lookup,
		runtimeDependencies{
			openDatabase: func(context.Context, string) (databasePool, error) {
				return pool, nil
			},
			buildHTTP: func(_ databasePool, lookup config.LookupEnv, health http.Handler) (http.Handler, error) {
				if _, _, err := twiliodelivery.FromLookup(twiliodelivery.LookupEnv(lookup)); err != nil {
					return nil, errors.New("load SMS delivery configuration")
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
	if err == nil || err.Error() != "load SMS delivery configuration" {
		t.Fatalf("runWithDependencies() error = %v", err)
	}
	if strings.Contains(err.Error(), authValue) {
		t.Fatalf("startup error leaks SMS credential fixture: %q", err)
	}
	if listenCalled {
		t.Fatal("listener started after partial SMS configuration")
	}
	if pool.closed != 1 {
		t.Fatalf("pool Close() calls = %d, want 1", pool.closed)
	}
}
