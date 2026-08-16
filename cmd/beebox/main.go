package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DoMinhHHung/beebox/internal/platform/config"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/httpserver"
)

type databasePool interface {
	Ping(context.Context) error
	Close()
}

type runtimeDependencies struct {
	openDatabase func(context.Context, string) (databasePool, error)
	listen       func(string, string) (net.Listener, error)
	serveHTTP    func(
		context.Context,
		*http.Server,
		net.Listener,
		time.Duration,
	) error
}

func main() {
	logger := slog.New(
		slog.NewJSONHandler(os.Stdout, nil),
	)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := run(ctx, logger, os.LookupEnv); err != nil {
		logger.Error(
			"beebox stopped with error",
			"error",
			err.Error(),
		)

		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	logger *slog.Logger,
	lookup config.LookupEnv,
) error {
	return runWithDependencies(
		ctx,
		logger,
		lookup,
		runtimeDependencies{
			openDatabase: func(
				ctx context.Context,
				databaseURL string,
			) (databasePool, error) {
				return database.Open(ctx, databaseURL)
			},
			listen:    net.Listen,
			serveHTTP: httpserver.Run,
		},
	)
}

func runWithDependencies(
	ctx context.Context,
	logger *slog.Logger,
	lookup config.LookupEnv,
	dependencies runtimeDependencies,
) error {
	cfg, err := config.Load(lookup)
	if err != nil {
		return fmt.Errorf(
			"load configuration: %w",
			err,
		)
	}

	startupCtx, cancelStartup := context.WithTimeout(
		ctx,
		cfg.DatabaseStartupTimeout,
	)

	pool, err := dependencies.openDatabase(
		startupCtx,
		cfg.DatabaseURL,
	)
	if err != nil {
		cancelStartup()
		return errors.New("initialize PostgreSQL pool")
	}
	defer pool.Close()

	if err := pool.Ping(startupCtx); err != nil {
		cancelStartup()
		return errors.New("verify PostgreSQL connectivity")
	}
	cancelStartup()

	listener, err := dependencies.listen(
		"tcp",
		cfg.HTTPAddr,
	)
	if err != nil {
		return fmt.Errorf(
			"listen on %q: %w",
			cfg.HTTPAddr,
			err,
		)
	}

	defer func() {
		_ = listener.Close()
	}()

	server := httpserver.New(
		cfg.HTTPAddr,
		httpserver.NewHandler(
			pool.Ping,
			cfg.DatabaseReadinessTimeout,
		),
	)

	logger.Info(
		"HTTP server starting",
		"address",
		listener.Addr().String(),
	)

	if err := dependencies.serveHTTP(
		ctx,
		server,
		listener,
		cfg.ShutdownTimeout,
	); err != nil {
		return err
	}

	logger.Info("HTTP server stopped")

	return nil
}
