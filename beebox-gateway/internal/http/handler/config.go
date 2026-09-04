package handler

import (
	"encoding/json"
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-apperror"
	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/http/middleware"
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"project":   map[string]string{"id": project.ProjectID, "slug": project.Slug},
		"plan_slug": project.PlanSlug,
		"modules":   modules,
		"fields":    []any{},
	})
}

func NotFound(w http.ResponseWriter, _ *http.Request) {
	apperror.WriteJSON(w, apperror.New(apperror.CodeNotFound, "not found"))
}
