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

	"github.com/DoMinhHHung/beebox/internal/platform/config"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/httpserver"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

const usageText = "usage: beebox [migrate]"
var errUsage = errors.New(usageText)

type processMode uint8
const ( serveMode processMode = iota; migrateMode )

type databasePool interface { Ping(context.Context) error; OpenSQLDB() *sql.DB; Close() }

type runtimeDependencies struct {
	openDatabase func(context.Context,string)(databasePool,error)
	listen func(string,string)(net.Listener,error)
	serveHTTP func(context.Context,*http.Server,net.Listener,time.Duration) error
	migrate func(context.Context,databasePool) error
}

func main(){
	logger:=slog.New(slog.NewJSONHandler(os.Stdout,nil))
	ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM); defer stop()
	if err:=run(ctx,logger,os.LookupEnv,os.Args[1:]);err!=nil{logger.Error("beebox stopped with error","error",err.Error());os.Exit(1)}
}

func run(ctx context.Context,logger *slog.Logger,lookup config.LookupEnv,args []string) error{
	if isOperatorCommand(args){ return runOperator(ctx,lookup,os.Stdout,args) }
	return runWithDependencies(ctx,logger,lookup,runtimeDependencies{
		openDatabase:func(ctx context.Context,databaseURL string)(databasePool,error){return database.Open(ctx,databaseURL)},
		listen:net.Listen,serveHTTP:httpserver.Run,
		migrate:func(ctx context.Context,pool databasePool)error{return migration.Up(ctx,pool.OpenSQLDB())},
	},args)
}

func runWithDependencies(ctx context.Context,logger *slog.Logger,lookup config.LookupEnv,dependencies runtimeDependencies,args []string) error{
	mode,err:=parseMode(args); if err!=nil{return err}
	if mode==migrateMode{return runMigrationMode(ctx,logger,lookup,dependencies)}
	return runServeMode(ctx,logger,lookup,dependencies)
}

func parseMode(args []string)(processMode,error){
	switch{case len(args)==0:return serveMode,nil;case len(args)==1&&args[0]=="migrate":return migrateMode,nil;default:return 0,errUsage}
}

func runServeMode(ctx context.Context,logger *slog.Logger,lookup config.LookupEnv,dependencies runtimeDependencies)error{
	cfg,err:=config.Load(lookup);if err!=nil{return fmt.Errorf("load configuration: %w",err)}
	startupCtx,cancelStartup:=context.WithTimeout(ctx,cfg.DatabaseStartupTimeout)
	pool,err:=dependencies.openDatabase(startupCtx,cfg.DatabaseURL);if err!=nil{cancelStartup();return errors.New("initialize PostgreSQL pool")};defer pool.Close()
	if err:=pool.Ping(startupCtx);err!=nil{cancelStartup();return errors.New("verify PostgreSQL connectivity")};cancelStartup()
	listener,err:=dependencies.listen("tcp",cfg.HTTPAddr);if err!=nil{return fmt.Errorf("listen on %q: %w",cfg.HTTPAddr,err)};defer func(){_ = listener.Close()}()
	server:=httpserver.New(cfg.HTTPAddr,httpserver.NewHandler(pool.Ping,cfg.DatabaseReadinessTimeout))
	logger.Info("HTTP server starting","address",listener.Addr().String())
	if err:=dependencies.serveHTTP(ctx,server,listener,cfg.ShutdownTimeout);err!=nil{return err};logger.Info("HTTP server stopped");return nil
}

func runMigrationMode(ctx context.Context,logger *slog.Logger,lookup config.LookupEnv,dependencies runtimeDependencies)error{
	cfg,err:=config.LoadMigration(lookup);if err!=nil{return fmt.Errorf("load migration configuration: %w",err)}
	startupCtx,cancelStartup:=context.WithTimeout(ctx,cfg.DatabaseStartupTimeout)
	pool,err:=dependencies.openDatabase(startupCtx,cfg.DatabaseURL);if err!=nil{cancelStartup();return errors.New("initialize PostgreSQL pool")};defer pool.Close()
	if err:=pool.Ping(startupCtx);err!=nil{cancelStartup();return errors.New("verify PostgreSQL connectivity")};cancelStartup()
	migrationCtx,cancelMigration:=context.WithTimeout(ctx,cfg.DatabaseMigrationTimeout);err=dependencies.migrate(migrationCtx,pool);cancelMigration();if err!=nil{return errors.New("apply PostgreSQL migrations")}
	logger.Info("PostgreSQL migrations applied");return nil
}
