package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/http/middleware"
	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
)

func ClientConfig(w http.ResponseWriter, r *http.Request) {
	project, ok := middleware.ProjectFrom(r)
	if !ok || project.ProjectID == "" {
		apperror.WriteJSON(w, apperror.New(apperror.CodeUnauthorized, "project not resolved"))
		return
	}
	modules := project.Modules
	if modules == nil {
		modules = []string{}
	}
	password := false
	oauth := make([]string, 0)
	for _, name := range modules {
		if name == "auth.password" {
			password = true
		}
		if strings.HasPrefix(name, "auth.oauth.") {
			slug := strings.TrimPrefix(name, "auth.oauth.")
			if slug != "" {
				oauth = append(oauth, slug)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"project":   map[string]string{"id": project.ProjectID, "slug": project.Slug},
		"plan_slug": project.PlanSlug,
		"modules":   modules,
		"fields":    []any{},
		"auth":      map[string]any{"password": password, "oauth": oauth},
	})
}

func NotFound(w http.ResponseWriter, _ *http.Request) {
	apperror.WriteJSON(w, apperror.New(apperror.CodeNotFound, "not found"))
}
