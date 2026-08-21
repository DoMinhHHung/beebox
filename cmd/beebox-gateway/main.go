package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/DoMinhHHung/beebox/internal/gateway"
	"github.com/DoMinhHHung/beebox/internal/platform/httpserver"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger, os.LookupEnv); err != nil {
		logger.Error("BeeBox Gateway stopped with error", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger, lookup gateway.LookupEnv) error {
	cfg, err := gateway.LoadConfig(lookup)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()

	server := httpserver.New(cfg.ListenAddress, gateway.NewHandler(cfg, logger))
	logger.Info("BeeBox Gateway starting", "address", listener.Addr().String(), "identity_upstream", cfg.IdentityBaseURL.Redacted())
	if err := httpserver.Run(ctx, server, listener, cfg.ShutdownTimeout); err != nil {
		return err
	}
	logger.Info("BeeBox Gateway stopped")
	return nil
}
