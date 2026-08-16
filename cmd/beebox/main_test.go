package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/platform/config"
)

const lifecycleTestDatabaseURL = "postgres://beebox:test-password@localhost/beebox"

type fakeDatabasePool struct {
	ping   func(context.Context) error
	closed int
}

func (p *fakeDatabasePool) Ping(ctx context.Context) error {
	return p.ping(ctx)
}

func (p *fakeDatabasePool) Close() {
	p.closed++
}

type fakeListener struct {
	closed bool
}

func (*fakeListener) Accept() (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (l *fakeListener) Close() error {
	l.closed = true
	return nil
}

func (*fakeListener) Addr() net.Addr {
	return fakeAddr("127.0.0.1:8080")
}

type fakeAddr string

func (fakeAddr) Network() string  { return "tcp" }
func (a fakeAddr) String() string { return string(a) }

func TestRunVerifiesDatabaseBeforeListeningAndCleansUp(t *testing.T) {
	var events []string
	pool := &fakeDatabasePool{
		ping: func(ctx context.Context) error {
			events = append(events, "ping")
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("database startup context has no deadline")
			}
			if remaining := time.Until(deadline); remaining <= 0 || remaining > time.Second {
				t.Fatalf("database startup deadline remaining = %s", remaining)
			}
			return nil
		},
	}
	listener := &fakeListener{}

	err := runWithDependencies(
		context.Background(),
		testLogger(),
		testLookup(map[string]string{
			"BEEBOX_DATABASE_STARTUP_TIMEOUT": "100ms",
		}),
		runtimeDependencies{
			openDatabase: func(
				ctx context.Context,
				databaseURL string,
			) (databasePool, error) {
				events = append(events, "open")
				if databaseURL != lifecycleTestDatabaseURL {
					t.Fatal("openDatabase received unexpected URL")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("openDatabase context has no deadline")
				}
				return pool, nil
			},
			listen: func(network, address string) (net.Listener, error) {
				events = append(events, "listen")
				if network != "tcp" || address != ":8080" {
					t.Fatalf("listen arguments = %q, %q", network, address)
				}
				return listener, nil
			},
			serveHTTP: func(
				context.Context,
				*http.Server,
				net.Listener,
				time.Duration,
			) error {
				events = append(events, "serve")
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("runWithDependencies() error = %v", err)
	}

	events = append(events, "assert")
	if want := []string{"open", "ping", "listen", "serve", "assert"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if pool.closed != 1 {
		t.Fatalf("pool Close() calls = %d, want 1", pool.closed)
	}
	if !listener.closed {
		t.Fatal("listener was not closed")
	}
}

func TestRunDoesNotListenWhenDatabasePingFailsAndCleansUp(t *testing.T) {
	const secretMarker = "super-secret"
	pool := &fakeDatabasePool{
		ping: func(context.Context) error {
			return errors.New("provider detail contains " + secretMarker)
		},
	}
	listenCalled := false

	err := runWithDependencies(
		context.Background(),
		testLogger(),
		testLookup(nil),
		runtimeDependencies{
			openDatabase: func(context.Context, string) (databasePool, error) {
				return pool, nil
			},
			listen: func(string, string) (net.Listener, error) {
				listenCalled = true
				return nil, errors.New("unexpected listen")
			},
		},
	)

	if err == nil || err.Error() != "verify PostgreSQL connectivity" {
		t.Fatalf("runWithDependencies() error = %q, want stable connectivity error", err)
	}
	if strings.Contains(err.Error(), secretMarker) {
		t.Fatalf("startup error leaks dependency detail: %q", err)
	}
	if listenCalled {
		t.Fatal("listen was called before PostgreSQL became reachable")
	}
	if pool.closed != 1 {
		t.Fatalf("pool Close() calls = %d, want 1", pool.closed)
	}
}

func TestRunClosesDatabasePoolWhenListenFails(t *testing.T) {
	pool := &fakeDatabasePool{
		ping: func(context.Context) error { return nil },
	}

	err := runWithDependencies(
		context.Background(),
		testLogger(),
		testLookup(nil),
		runtimeDependencies{
			openDatabase: func(context.Context, string) (databasePool, error) {
				return pool, nil
			},
			listen: func(string, string) (net.Listener, error) {
				return nil, errors.New("address unavailable")
			},
		},
	)

	if err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("runWithDependencies() error = %v, want listen error", err)
	}
	if pool.closed != 1 {
		t.Fatalf("pool Close() calls = %d, want 1", pool.closed)
	}
}

func TestRunValidatesConfigurationBeforeOpeningResources(t *testing.T) {
	opened := false
	listened := false

	err := runWithDependencies(
		context.Background(),
		testLogger(),
		func(string) (string, bool) { return "", false },
		runtimeDependencies{
			openDatabase: func(context.Context, string) (databasePool, error) {
				opened = true
				return nil, errors.New("unexpected open")
			},
			listen: func(string, string) (net.Listener, error) {
				listened = true
				return nil, errors.New("unexpected listen")
			},
		},
	)

	if err == nil || !strings.Contains(err.Error(), "BEEBOX_DATABASE_URL is required") {
		t.Fatalf("runWithDependencies() error = %v, want database configuration error", err)
	}
	if opened || listened {
		t.Fatalf("resource calls after invalid config: open=%t listen=%t", opened, listened)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testLookup(overrides map[string]string) config.LookupEnv {
	values := map[string]string{
		"BEEBOX_DATABASE_URL": lifecycleTestDatabaseURL,
	}
	for key, value := range overrides {
		values[key] = value
	}

	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
