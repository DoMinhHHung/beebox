package httpx

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/config"
	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/router"
)

func NewServer(cfg config.Config) *http.Server {
	return &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: router.New(cfg),
	}
}

func Run(cfg config.Config) error {
	srv := NewServer(cfg)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-sigCh:
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
