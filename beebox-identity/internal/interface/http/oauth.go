package httpapi

import (
	"net/http"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
)

func (s *Server) getOAuthStart(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	result, err := s.OAuthStart.Execute(r.Context(), scope, r.PathValue("slug"))
	if err != nil {
		writeErr(w, err)
		return
	}
	http.Redirect(w, r, result.Location, http.StatusFound)
}

func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if err := r.ParseForm(); err != nil && r.Method == http.MethodPost {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	code := firstNonEmpty(r.FormValue("code"), r.URL.Query().Get("code"))
	state := firstNonEmpty(r.FormValue("state"), r.URL.Query().Get("state"))
	if firstNonEmpty(r.FormValue("error"), r.URL.Query().Get("error")) != "" {
		writeErr(w, domain.ErrUnauthorized)
		return
	}
	result, err := s.OAuthCallback.Execute(r.Context(), slug, code, state, r.FormValue("user"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAuthDTO(result))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
