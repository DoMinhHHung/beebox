package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/DoMinhHHung/beebox/internal/platform/config"
	"github.com/DoMinhHHung/beebox/internal/platform/httpserver"
)

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
	cfg, err := config.Load(lookup)
	if err != nil {
		return fmt.Errorf(
			"load configuration: %w",
			err,
		)
	}

	listener, err := net.Listen(
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
		httpserver.NewHandler(),
	)

	logger.Info(
		"HTTP server starting",
		"address",
		listener.Addr().String(),
	)

	if err := httpserver.Run(
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
