package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/config"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/signingkey"
)

var errOperatorUsage = errors.New("usage: beebox [migrate|generate-signing-key|bootstrap-application [origin...]|add-origin <app_id> <origin>|rotate-credential <app_id> <publishable|secret> <old_credential_id>|revoke-credential <credential_id>]")

func isOperatorCommand(args []string) bool {
	if len(args)==0 { return false }
	switch args[0] {
	case "generate-signing-key","bootstrap-application","add-origin","rotate-credential","revoke-credential": return true
	default: return false
	}
}

func runOperator(ctx context.Context, lookup config.LookupEnv, output io.Writer, args []string) error {
	if len(args)==0 { return errOperatorUsage }
	if args[0]=="generate-signing-key" {
		if len(args)!=1 { return errOperatorUsage }
		generated,err:=signingkey.Generate(); if err!=nil{return errors.New("generate signing key")}
		_,err=fmt.Fprintf(output,"kid=%s\nprivate_key=%s\npublic_key=%s\n",generated.KeyID,generated.PrivateKey,generated.PublicKey); if err!=nil{return errors.New("write signing key output")}; return nil
	}
	cfg,err:=config.LoadMigration(lookup); if err!=nil{return fmt.Errorf("load operator configuration: %w",err)}
	pool,err:=database.Open(ctx,cfg.DatabaseURL); if err!=nil{return errors.New("initialize PostgreSQL pool")}; defer pool.Close()
	if err:=pool.Ping(ctx);err!=nil{return errors.New("verify PostgreSQL connectivity")}
	apps:=applicationpostgres.New(pool); service:=applicationinstance.NewIntegrationService(applicationpostgres.NewIntegrationStore(pool))
	switch args[0] {
	case "bootstrap-application":
		app,err:=apps.Create(ctx); if err!=nil{return err}
		_,publishable,err:=service.CreateCredential(ctx,app.InternalID,applicationinstance.CredentialKindPublishable); if err!=nil{return err}
		_,secret,err:=service.CreateCredential(ctx,app.InternalID,applicationinstance.CredentialKindSecret); if err!=nil{return err}
		for _,origin:=range args[1:] { if _,err:=service.AddAllowedOrigin(ctx,app.InternalID,origin);err!=nil{return err} }
		_,err=fmt.Fprintf(output,"application_id=%s\npublishable_key=%s\nsecret_key=%s\n",app.PublicID,publishable,secret); if err!=nil{return errors.New("write bootstrap output")}; return nil
	case "add-origin":
		if len(args)!=3{return errOperatorUsage}; appID:=applicationinstance.PublicID(args[1]); app,err:=apps.ResolveByPublicID(ctx,appID); if err!=nil{return err}; origin,err:=service.AddAllowedOrigin(ctx,app.InternalID,args[2]); if err!=nil{return err}; _,err=fmt.Fprintf(output,"origin=%s\n",origin.CanonicalOrigin); return err
	case "rotate-credential":
		if len(args)!=4{return errOperatorUsage}; app,err:=apps.ResolveByPublicID(ctx,applicationinstance.PublicID(args[1])); if err!=nil{return err}; kind:=applicationinstance.CredentialKind(args[2]); newCredential,raw,err:=service.CreateCredential(ctx,app.InternalID,kind); if err!=nil{return err}; if err:=service.RevokeCredential(ctx,applicationinstance.CredentialPublicID(args[3]));err!=nil{return err}; _,err=fmt.Fprintf(output,"credential_id=%s\ncredential=%s\n",newCredential.PublicID,raw); return err
	case "revoke-credential":
		if len(args)!=2{return errOperatorUsage}; return service.RevokeCredential(ctx,applicationinstance.CredentialPublicID(args[1]))
	default:return errOperatorUsage
	}
}
