package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/resolve"
	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
)

type ctxKey int

const projectCtxKey ctxKey = 1

type Resolver interface {
	Resolve(r *http.Request) (resolve.Project, error)
}

type HTTPResolver struct {
	Client *resolve.Client
}

func (h HTTPResolver) Resolve(r *http.Request) (resolve.Project, error) {
	pk, slug := resolve.IdentityFrom(r)
	if pk == "" && slug == "" {
		return resolve.Project{}, apperror.New(apperror.CodeUnauthorized, "project not resolved")
	}
	return h.Client.Resolve(r.Context(), pk, slug)
}

func ProjectFrom(r *http.Request) (resolve.Project, bool) {
	p, ok := r.Context().Value(projectCtxKey).(resolve.Project)
	return p, ok
}

func ResolveAndCORS(resolver Resolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isHealth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/internal/") {
			apperror.WriteJSON(w, apperror.New(apperror.CodeNotFound, "not found"))
			return
		}

		pk, slug := resolve.IdentityFrom(r)
		var project resolve.Project
		resolved := false
		if pk != "" || slug != "" {
			p, err := resolver.Resolve(r)
			if err != nil {
				if requiresProject(r.URL.Path) {
					apperror.WriteJSON(w, err)
					return
				}
			} else {
				project = p
				resolved = true
				r = r.WithContext(context.WithValue(r.Context(), projectCtxKey, project))
			}
		}

		if requiresProject(r.URL.Path) && !resolved {
			apperror.WriteJSON(w, apperror.New(apperror.CodeUnauthorized, "project not resolved"))
			return
		}

		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if resolved && origin != "" && !resolve.OriginAllowed(origin, project.Origins) {
			apperror.WriteJSON(w, apperror.New(apperror.CodeForbidden, "origin is not allowed"))
			return
		}
		if resolved && origin != "" {
			writeCORS(w, origin)
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requiresProject(path string) bool {
	return strings.HasPrefix(path, "/v1/client/config")
}

func writeCORS(w http.ResponseWriter, origin string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-BeeBox-Owner-Id, X-BeeBox-Publishable-Key, X-BeeBox-Project-Slug, X-Request-ID")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
}
