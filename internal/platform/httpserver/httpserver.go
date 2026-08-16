package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 15 * time.Second
	idleTimeout       = 60 * time.Second
)

type statusResponse struct {
	Status string `json:"status"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type ReadinessCheck func(context.Context) error

func NewHandler(
	checkReadiness ReadinessCheck,
	readinessTimeout time.Duration,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle(
		"/health/live",
		requireMethod(http.MethodGet, healthHandler("ok")),
	)

	mux.Handle(
		"/health/ready",
		requireMethod(
			http.MethodGet,
			readinessHandler(checkReadiness, readinessTimeout),
		),
	)

	return mux
}

func New(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

func Run(
	ctx context.Context,
	server *http.Server,
	listener net.Listener,
	shutdownTimeout time.Duration,
) error {
	serveErr := make(chan error, 1)

	go func() {
		serveErr <- server.Serve(listener)
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return fmt.Errorf("serve HTTP: %w", err)

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			shutdownTimeout,
		)
		defer cancel()

		shutdownErr := server.Shutdown(shutdownCtx)
		err := <-serveErr

		if shutdownErr != nil {
			return fmt.Errorf(
				"shutdown HTTP server: %w",
				shutdownErr,
			)
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf(
				"serve HTTP during shutdown: %w",
				err,
			)
		}

		return nil
	}
}

func requireMethod(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)

			writeJSON(
				w,
				http.StatusMethodNotAllowed,
				errorResponse{Error: "method_not_allowed"},
			)

			return
		}

		next.ServeHTTP(w, r)
	})
}

func healthHandler(status string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(
			w,
			http.StatusOK,
			statusResponse{Status: status},
		)
	})
}

func readinessHandler(
	check ReadinessCheck,
	timeout time.Duration,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		if err := check(ctx); err != nil {
			writeJSON(
				w,
				http.StatusServiceUnavailable,
				statusResponse{Status: "not_ready"},
			)

			return
		}

		writeJSON(
			w,
			http.StatusOK,
			statusResponse{Status: "ready"},
		)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}
