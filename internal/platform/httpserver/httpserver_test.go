package httpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantBody string
	}{
		{
			name:     "liveness",
			path:     "/health/live",
			wantBody: "{\"status\":\"ok\"}\n",
		},
		{
			name:     "readiness",
			path:     "/health/ready",
			wantBody: "{\"status\":\"ready\"}\n",
		},
	}

	handler := NewHandler(
		func(context.Context) error { return nil },
		time.Second,
	)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodGet,
				tt.path,
				nil,
			)

			res := httptest.NewRecorder()

			handler.ServeHTTP(res, req)

			if res.Code != http.StatusOK {
				t.Fatalf(
					"status = %d, want %d",
					res.Code,
					http.StatusOK,
				)
			}

			if got := res.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
				t.Fatalf(
					"Content-Type = %q, want application/json; charset=utf-8",
					got,
				)
			}

			if res.Body.String() != tt.wantBody {
				t.Fatalf(
					"body = %q, want %q",
					res.Body.String(),
					tt.wantBody,
				)
			}
		})
	}
}

func TestRequireMethodRejectsUnsupportedMethodWithoutCallingHandler(
	t *testing.T,
) {
	called := false

	handler := requireMethod(
		http.MethodGet,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			called = true
		}),
	)

	req := httptest.NewRequest(
		http.MethodPost,
		"/health/live",
		nil,
	)

	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if called {
		t.Fatal(
			"wrapped health handler was called for unsupported method",
		)
	}

	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf(
			"status = %d, want %d",
			res.Code,
			http.StatusMethodNotAllowed,
		)
	}

	if got := res.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf(
			"Allow = %q, want %q",
			got,
			http.MethodGet,
		)
	}

	if got := res.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf(
			"Content-Type = %q, want application/json; charset=utf-8",
			got,
		)
	}

	if res.Body.String() != "{\"error\":\"method_not_allowed\"}\n" {
		t.Fatalf(
			"body = %q",
			res.Body.String(),
		)
	}
}

func TestReadinessReportsDependencyFailureWithoutLeakingDetails(t *testing.T) {
	const secretMarker = "super-secret"

	handler := NewHandler(
		func(context.Context) error {
			return errors.New("dial postgres://user:" + secretMarker + "@db")
		},
		time.Second,
	)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusServiceUnavailable)
	}
	if res.Body.String() != "{\"status\":\"not_ready\"}\n" {
		t.Fatalf("body = %q, want stable not-ready response", res.Body.String())
	}
	if got := res.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want application/json; charset=utf-8", got)
	}
	if strings.Contains(res.Body.String(), secretMarker) {
		t.Fatalf("response body leaks dependency detail: %q", res.Body.String())
	}
}

func TestReadinessBoundsDependencyCheck(t *testing.T) {
	handler := NewHandler(
		func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		10*time.Millisecond,
	)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusServiceUnavailable)
	}
	if res.Body.String() != "{\"status\":\"not_ready\"}\n" {
		t.Fatalf("body = %q, want stable not-ready response", res.Body.String())
	}
}

func TestReadinessHonorsRequestCancellation(t *testing.T) {
	called := 0
	handler := NewHandler(
		func(ctx context.Context) error {
			called++
			return ctx.Err()
		},
		time.Second,
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil).WithContext(ctx)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if called != 1 {
		t.Fatalf("readiness check calls = %d, want 1", called)
	}
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusServiceUnavailable)
	}
}

func TestLivenessDoesNotCallReadinessDependency(t *testing.T) {
	called := 0
	handler := NewHandler(
		func(context.Context) error {
			called++
			return errors.New("database unavailable")
		},
		time.Second,
	)

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if called != 0 {
		t.Fatalf("readiness check calls = %d, want 0", called)
	}
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusOK)
	}
	if res.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("body = %q, want liveness response", res.Body.String())
	}
}

func TestNewSetsExplicitTimeouts(t *testing.T) {
	server := New(
		":8080",
		NewHandler(
			func(context.Context) error { return nil },
			time.Second,
		),
	)

	if server.ReadHeaderTimeout != readHeaderTimeout {
		t.Fatalf(
			"ReadHeaderTimeout = %s, want %s",
			server.ReadHeaderTimeout,
			readHeaderTimeout,
		)
	}

	if server.ReadTimeout != readTimeout {
		t.Fatalf(
			"ReadTimeout = %s, want %s",
			server.ReadTimeout,
			readTimeout,
		)
	}

	if server.WriteTimeout != writeTimeout {
		t.Fatalf(
			"WriteTimeout = %s, want %s",
			server.WriteTimeout,
			writeTimeout,
		)
	}

	if server.IdleTimeout != idleTimeout {
		t.Fatalf(
			"IdleTimeout = %s, want %s",
			server.IdleTimeout,
			idleTimeout,
		)
	}
}

func TestRunStopsCleanlyWhenContextIsCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	server := New(
		listener.Addr().String(),
		NewHandler(
			func(context.Context) error { return nil },
			time.Second,
		),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- Run(
			ctx,
			server,
			listener,
			500*time.Millisecond,
		)
	}()

	client := &http.Client{
		Timeout: 500 * time.Millisecond,
	}

	url := "http://" +
		listener.Addr().String() +
		"/health/live"

	deadline := time.Now().Add(time.Second)

	for {
		resp, requestErr := client.Get(url)

		if requestErr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			break
		}

		if time.Now().After(deadline) {
			t.Fatalf(
				"server did not become reachable: %v",
				requestErr,
			)
		}

		time.Sleep(10 * time.Millisecond)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal(
			"Run() did not return after cancellation",
		)
	}
}
