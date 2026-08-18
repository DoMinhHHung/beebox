package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/authentication/metricsdelivery"
	authpostgres "github.com/DoMinhHHung/beebox/internal/authentication/postgres"
	"github.com/DoMinhHHung/beebox/internal/authentication/smtpdelivery"
	"github.com/DoMinhHHung/beebox/internal/authentication/socialprovider"
	"github.com/DoMinhHHung/beebox/internal/httpapi"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/metrics"
	"github.com/DoMinhHHung/beebox/internal/platform/config"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/httpserver"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
	sessionpostgres "github.com/DoMinhHHung/beebox/internal/session/postgres"
)

const usageText = "usage: beebox [migrate]"

var errUsage = errors.New(usageText)

type processMode uint8

const (
	serveMode processMode = iota
	migrateMode
)

type databasePool interface {
	Ping(context.Context) error
	OpenSQLDB() *sql.DB
	Close()
}

type runtimeDependencies struct {
	openDatabase func(context.Context, string) (databasePool, error)
	listen       func(string, string) (net.Listener, error)
	serveHTTP    func(context.Context, *http.Server, net.Listener, time.Duration) error
	migrate      func(context.Context, databasePool) error
	buildHTTP    func(databasePool, config.LookupEnv, http.Handler) (http.Handler, error)
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger, os.LookupEnv, os.Args[1:]); err != nil {
		logger.Error("beebox stopped with error", "error", err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, lookup config.LookupEnv, args []string) error {
	if isOperatorCommand(args) {
		return runOperator(ctx, lookup, os.Stdout, args)
	}
	return runWithDependencies(ctx, logger, lookup, runtimeDependencies{
		openDatabase: func(ctx context.Context, databaseURL string) (databasePool, error) {
			return database.Open(ctx, databaseURL)
		},
		listen:    net.Listen,
		serveHTTP: httpserver.Run,
		migrate: func(ctx context.Context, pool databasePool) error {
			return migration.Up(ctx, pool.OpenSQLDB())
		},
		buildHTTP: buildProductHTTP,
	}, args)
}

func buildProductHTTP(pool databasePool, lookup config.LookupEnv, health http.Handler) (http.Handler, error) {
	concretePool, ok := pool.(*database.Pool)
	if !ok {
		return nil, errors.New("initialize product HTTP dependencies")
	}
	sender, err := smtpdelivery.FromLookup(smtpdelivery.LookupEnv(lookup))
	if err != nil {
		return nil, errors.New("load SMTP delivery configuration")
	}
	smsSender, smsEnabled, err := buildSMSDelivery(lookup)
	if err != nil {
		return nil, err
	}
	socialRegistry, socialProtector, err := socialprovider.Load(socialprovider.LookupEnv(lookup))
	if err != nil {
		return nil, errors.New("load social provider configuration")
	}
	recorder := metrics.New()
	recorder.SetDatabaseStatsProvider(func() metrics.DatabaseStats {
		stats := concretePool.Stats()
		return metrics.DatabaseStats{AcquiredConns: stats.AcquiredConns, IdleConns: stats.IdleConns, TotalConns: stats.TotalConns, MaxConns: stats.MaxConns}
	})
	delivery := metricsdelivery.New(sender, recorder)
	integrationStore := applicationpostgres.NewIntegrationStore(concretePool)
	integrationService := applicationinstance.NewIntegrationService(integrationStore)
	authStore := authpostgres.New(concretePool)
	verificationCore := authentication.NewEmailVerificationService(authStore, delivery)
	verification := authentication.NewPublicVerificationService(identitypostgres.New(concretePool), authStore, verificationCore)
	signup := authentication.NewPublicSignupService(authStore, delivery)
	reset := authentication.NewPasswordResetService(authStore, delivery)
	emailOTP := authentication.NewEmailOTPService(authStore, delivery)
	base := httpapi.New(health, integrationService, integrationStore, signup, verification)
	base = httpapi.WithPasswordReset(base, integrationService, integrationStore, reset)

	var phoneSignupIssuer httpapi.PhoneIssueService
	var phoneSigninIssuer httpapi.PhoneIssueService
	if smsEnabled {
		phoneDelivery := metricsdelivery.NewPhone(smsSender, recorder)
		phoneSignupIssuer = authentication.NewPhoneSignupService(authStore, phoneDelivery)
		phoneSigninIssuer = authentication.NewPhoneOTPService(authStore, phoneDelivery)
	}

	ring, err := session.KeyRingFromLookup(session.LookupEnv(lookup))
	if errors.Is(err, session.ErrTokenDisabled) {
		if socialRegistry.Enabled() {
			return nil, errors.New("social authentication requires access token signing configuration")
		}
		base = httpapi.WithEmailOTP(base, integrationService, integrationStore, nil, nil)
		base = httpapi.WithPhoneSMS(base, integrationService, integrationStore, nil, nil, nil, nil)
		return httpapi.WithMetrics(base, recorder), nil
	}
	if err != nil {
		return nil, errors.New("load access token signing configuration")
	}
	sessionStore := sessionpostgres.New(concretePool)
	sessionService := session.NewService(sessionStore, sessionStore, ring)
	emailOTPSession := session.NewEmailOTPService(authStore, ring)
	phoneSignupSession := session.NewPhoneSignupService(authStore, ring)
	phoneOTPSession := session.NewPhoneOTPService(authStore, ring)
	base = httpapi.WithSessions(base, integrationService, integrationStore, sessionService, ring)
	base = httpapi.WithEmailOTP(base, integrationService, integrationStore, emailOTP, emailOTPSession)
	base = httpapi.WithPhoneSMS(base, integrationService, integrationStore, phoneSignupIssuer, phoneSignupSession, phoneSigninIssuer, phoneOTPSession)
	if socialRegistry.Enabled() {
		socialCore := authentication.NewSocialService(authStore, integrationStore, authStore, socialRegistry, socialProtector)
		socialCompletion := session.NewSocialCompletionService(authStore, authStore, ring)
		base = httpapi.WithSocialAuth(base, integrationService, integrationStore, socialCore, socialCompletion)
	}
	base = httpapi.WithSessionManagement(base, integrationService, integrationService, sessionService)
	return httpapi.WithMetrics(base, recorder), nil
}

func runWithDependencies(ctx context.Context, logger *slog.Logger, lookup config.LookupEnv, dependencies runtimeDependencies, args []string) error {
	mode, err := parseMode(args)
	if err != nil {
		return err
	}
	if mode == migrateMode {
		return runMigrationMode(ctx, logger, lookup, dependencies)
	}
	return runServeMode(ctx, logger, lookup, dependencies)
}

func parseMode(args []string) (processMode, error) {
	switch {
	case len(args) == 0:
		return serveMode, nil
	case len(args) == 1 && args[0] == "migrate":
		return migrateMode, nil
	default:
		return 0, errUsage
	}
}

func runServeMode(ctx context.Context, logger *slog.Logger, lookup config.LookupEnv, dependencies runtimeDependencies, args []string) error {
	cfg, err := config.Load(lookup)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if err := authentication.ConfigureProcessKDFConcurrency(cfg.KDFConcurrency); err != nil {
		return errors.New("configure KDF concurrency")
	}
	startupCtx, cancelStartup := context.WithTimeout(ctx, cfg.DatabaseStartupTimeout)
	pool, err := dependencies.openDatabase(startupCtx, cfg.DatabaseURL)
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
	health := httpserver.NewHandler(pool.Ping, cfg.DatabaseReadinessTimeout)
	handler := health
	if dependencies.buildHTTP != nil {
		handler, err = dependencies.buildHTTP(pool, lookup, health)
		if err != nil {
			return err
		}
	}
	listener, err := dependencies.listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", cfg.HTTPAddr, err)
	}
	defer func() { _ = listener.Close() }()
	server := httpserver.New(cfg.HTTPAddr, handler)
	logger.Info("HTTP server starting", "address", listener.Addr().String())
	if err := dependencies.serveHTTP(ctx, server, listener, cfg.ShutdownTimeout); err != nil {
		return err
	}
	logger.Info("HTTP server stopped")
	return nil
}

func runMigrationMode(ctx context.Context, logger *slog.Logger, lookup config.LookupEnv, dependencies runtimeDependencies) error {
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		return fmt.Errorf("load migration configuration: %w", err)
	}
	startupCtx, cancelStartup := context.WithTimeout(ctx, cfg.DatabaseStartupTimeout)
	pool, err := dependencies.openDatabase(startupCtx, cfg.DatabaseURL)
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
	migrationCtx, cancelMigration := context.WithTimeout(ctx, cfg.DatabaseMigrationTimeout)
	err = dependencies.migrate(migrationCtx, pool)
	cancelMigration()
	if err != nil {
		return errors.New("apply PostgreSQL migrations")
	}
	logger.Info("PostgreSQL migrations applied")
	return nil
}
