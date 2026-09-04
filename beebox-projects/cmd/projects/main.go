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
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/infrastructure/crypto"
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
	ownerSessions := postgres.NewOwnerSessionRepository(pool)
	hasher := crypto.Argon2id{}
	tokens := crypto.SessionTokens{}
	projects := postgres.NewProjectRepository(pool)
	keys := postgres.NewAPIKeyRepository(pool)
	origins := postgres.NewOriginRepository(pool)
	modules := postgres.NewModuleRepository(pool)
	fields := postgres.NewFieldRepository(pool)
	oauthProviders := postgres.NewOAuthProviderRepository(pool)
	collections := postgres.NewCollectionRepository(pool)
	documents := postgres.NewDocumentRepository(pool)
	catalog := httpclient.NewPlanCatalog(cfg.PlansBaseURL, nil)
	var box application.SecretBox
	if cfg.OAuthKEK != "" {
		if loaded, err := crypto.NewSecretBox(cfg.OAuthKEK); err == nil {
			box = loaded
		}
	}

	handler := httpapi.New(httpapi.Deps{
		CreateAccount: application.CreateAccount{Accounts: accounts, Hasher: hasher},
		CreateProject: application.CreateProject{Projects: projects, Catalog: catalog},
		ListProjects:  application.ListProjects{Projects: projects},
		GetProject:    application.GetProject{Projects: projects},
		UpdateProject: application.UpdateProject{Projects: projects, Catalog: catalog},
		DeleteProject: application.DeleteProject{Projects: projects},
		ListKeys:      application.ListKeys{Projects: projects, Keys: keys},
		CreateKey:     application.CreateKey{Projects: projects, Keys: keys},
		RevokeKey:     application.RevokeKey{Projects: projects, Keys: keys},
		ListOrigins:   application.ListOrigins{Projects: projects, Origins: origins},
		AddOrigin:     application.AddOrigin{Projects: projects, Origins: origins},
		DeleteOrigin:  application.DeleteOrigin{Projects: projects, Origins: origins},
		ListModules:   application.ListModules{Projects: projects, Modules: modules},
		PutModules:    application.PutModules{Projects: projects, Modules: modules, Catalog: catalog},
		ListFields:    application.ListFields{Projects: projects, Fields: fields},
		PutFields:     application.PutFields{Projects: projects, Fields: fields, Catalog: catalog},
		Resolve: application.ResolveProject{
			Projects: projects,
			Keys:     keys,
			Origins:  origins,
			Modules:  modules,
			Fields:   fields,
		},
		OwnerSignUp: application.OwnerSignUp{
			Accounts: accounts, Sessions: ownerSessions, Hasher: hasher, Tokens: tokens,
		},
		OwnerSignIn: application.OwnerSignIn{
			Accounts: accounts, Sessions: ownerSessions, Hasher: hasher, Tokens: tokens,
		},
		OwnerSignOut: application.OwnerSignOut{Sessions: ownerSessions, Tokens: tokens},
		OwnerMe: application.OwnerMe{
			Accounts: accounts, Sessions: ownerSessions, Tokens: tokens,
		},
		GetOAuth:         application.GetOAuthProvider{Projects: projects, OAuth: oauthProviders},
		PutOAuth:         application.PutOAuthProvider{Projects: projects, OAuth: oauthProviders, Catalog: catalog, Box: box},
		InternalOAuth:    application.InternalOAuthProvider{OAuth: oauthProviders, Box: box},
		ListCollections:  application.ListCollections{Projects: projects, Collections: collections},
		CreateCollection: application.CreateCollection{Projects: projects, Collections: collections},
		ListDocuments:    application.ListDocuments{Collections: collections, Documents: documents},
		GetDocument:      application.GetDocument{Documents: documents},
		CreateDocument:   application.CreateDocument{Projects: projects, Collections: collections, Documents: documents},
		UpdateDocument:   application.UpdateDocument{Documents: documents},
		DeleteDocument:   application.DeleteDocument{Documents: documents},
		AllowOwnerHeader: cfg.AllowOwnerHeader,
		InternalToken:    cfg.InternalToken,
		Ready:            pool,
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
