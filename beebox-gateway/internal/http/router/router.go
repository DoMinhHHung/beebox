package router

import (
	"net/http"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/config"
	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/http/handler"
	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/http/middleware"
	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/http/proxy"
	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/resolve"
	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
)

func New(cfg config.Config) http.Handler {
	client := &resolve.Client{
		BaseURL: cfg.ProjectsBaseURL,
		Token:   cfg.InternalToken,
		HTTP:    &http.Client{Timeout: cfg.RequestTimeout},
	}
	return NewWithResolver(cfg, middleware.HTTPResolver{Client: client})
}

func NewWithResolver(cfg config.Config, resolver middleware.Resolver) http.Handler {
	plansProxy, err := proxy.New(cfg.PlansBaseURL)
	if err != nil {
		plansProxy, _ = proxy.New("http://127.0.0.1:8081")
	}
	projectsProxy, err := proxy.New(cfg.ProjectsBaseURL)
	if err != nil {
		projectsProxy, _ = proxy.New("http://127.0.0.1:8082")
	}
	identityProxy, err := proxy.New(cfg.IdentityBaseURL)
	if err != nil {
		identityProxy, _ = proxy.New("http://127.0.0.1:8083")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", handler.Live)
	mux.HandleFunc("GET /health/ready", handler.Ready)
	mux.HandleFunc("GET /v1/client/config", handler.ClientConfig)
	mux.HandleFunc("/v1/plans", func(w http.ResponseWriter, r *http.Request) {
		plansProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/v1/plans/", func(w http.ResponseWriter, r *http.Request) {
		plansProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		projectsProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		projectsProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/v1/accounts", func(w http.ResponseWriter, r *http.Request) {
		projectsProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/v1/accounts/", func(w http.ResponseWriter, r *http.Request) {
		projectsProxy.ServeHTTP(w, r)
	})
	mux.Handle("/v1/auth", attachIdentityHeaders(cfg.InternalToken, identityProxy))
	mux.Handle("/v1/auth/", attachIdentityHeaders(cfg.InternalToken, identityProxy))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/internal/") {
			apperror.WriteJSON(w, apperror.New(apperror.CodeNotFound, "not found"))
			return
		}
		handler.NotFound(w, r)
	})

	h := middleware.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst).Middleware(mux)
	h = middleware.ResolveAndCORS(resolver, h)
	h = middleware.Timeout(cfg.RequestTimeout)(h)
	h = middleware.Recover(h)
	h = middleware.RequestID(h)
	return h
}

func attachIdentityHeaders(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.Clone(r.Context())
		if token != "" {
			r.Header.Set("X-BeeBox-Internal-Token", token)
		}
		if project, ok := middleware.ProjectFrom(r); ok {
			r.Header.Set("X-BeeBox-Project-Id", project.ProjectID)
			r.Header.Set("X-BeeBox-Env", project.Env)
			r.Header.Set("X-BeeBox-Modules", strings.Join(project.Modules, ","))
		}
		next.ServeHTTP(w, r)
	})
}
