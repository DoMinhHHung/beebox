package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-identity/internal/config"
	"github.com/DoMinhHHung/beebox/beebox-identity/internal/infrastructure/crypto"
	"github.com/DoMinhHHung/beebox/beebox-identity/internal/infrastructure/httpclient"
	"github.com/DoMinhHHung/beebox/beebox-identity/internal/infrastructure/postgres"
	httpapi "github.com/DoMinhHHung/beebox/beebox-identity/internal/interface/http"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	if err := postgres.Migrate(ctx, pool); err != nil {
		log.Fatal(err)
	}

	users := postgres.NewUserRepository(pool)
	sessions := postgres.NewSessionRepository(pool)
	hasher := crypto.Argon2id{}
	tokens := crypto.SessionTokens{}
	now := func() time.Time { return time.Now().UTC() }
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resolver := &httpclient.Projects{
		BaseURL: cfg.ProjectsBaseURL,
		Token:   cfg.InternalToken,
		HTTP:    httpClient,
	}
	identities := postgres.NewIdentityRepository(pool)
	oauthStates := postgres.NewOAuthStateRepository(pool)
	oauthCreds := &httpclient.OAuthCreds{
		BaseURL: cfg.ProjectsBaseURL,
		Token:   cfg.InternalToken,
		HTTP:    httpClient,
	}

	handler := httpapi.New(httpapi.Deps{
		SignUp: application.SignUp{
			Users: users, Sessions: sessions, Hasher: hasher, Tokens: tokens, Now: now, TTL: cfg.SessionTTL,
		},
		SignIn: application.SignIn{
			Users: users, Sessions: sessions, Hasher: hasher, Tokens: tokens, Now: now, TTL: cfg.SessionTTL,
		},
		SignOut:    application.SignOut{Sessions: sessions, Tokens: tokens, Now: now},
		Me:         application.Me{Users: users, Sessions: sessions, Tokens: tokens, Now: now},
		OAuthStart: application.OAuthStart{States: oauthStates, Creds: oauthCreds, Now: now},
		OAuthCallback: application.OAuthCallback{
			Users: users, Identities: identities, Sessions: sessions, States: oauthStates,
			Creds: oauthCreds, Tokens: tokens, Now: now, TTL: cfg.SessionTTL,
		},
		InternalToken: cfg.InternalToken,
		Resolver:      resolver,
		Ready:         pool,
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-sigCh:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Fatal(err)
		}
	}
}
