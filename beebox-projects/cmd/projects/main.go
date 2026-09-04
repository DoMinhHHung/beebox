package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/config"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/infrastructure/httpclient"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/infrastructure/postgres"
	httpapi "github.com/DoMinhHHung/beebox/beebox-projects/internal/interface/http"
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

	accounts := postgres.NewAccountRepository(pool)
	projects := postgres.NewProjectRepository(pool)
	catalog := httpclient.NewPlanCatalog(cfg.PlansBaseURL, nil)

	handler := httpapi.New(
		application.CreateAccount{Accounts: accounts},
		application.CreateProject{Projects: projects, Catalog: catalog},
		application.ListProjects{Projects: projects},
		application.GetProject{Projects: projects},
		application.UpdateProject{Projects: projects, Catalog: catalog},
		application.DeleteProject{Projects: projects},
		pool,
	)

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
