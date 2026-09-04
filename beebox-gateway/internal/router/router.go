package router

import (
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/config"
	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/http/handler"
	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/http/middleware"
)

func New(cfg config.Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", handler.Live)
	mux.HandleFunc("GET /health/ready", handler.Ready)
	mux.HandleFunc("GET /v1/client/config", handler.ClientConfig)
	mux.HandleFunc("/", handler.NotFound)

	return middleware.Chain(
		mux,
		middleware.RequestID,
		middleware.AccessLog,
		middleware.Recover,
		middleware.Timeout(cfg.RequestTimeout),
	)
}
