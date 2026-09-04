package httpapi

import (
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
)

func (s *Server) getProjectOAuth(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	item, err := s.GetOAuth.Execute(r.Context(), ownerID, projectID, r.PathValue("slug"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOAuthDTO(item))
}

func (s *Server) putProjectOAuth(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		ClientID     string            `json:"client_id"`
		ClientSecret string            `json:"client_secret"`
		RedirectURI  string            `json:"redirect_uri"`
		Enabled      bool              `json:"enabled"`
		Extra        map[string]string `json:"extra"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	item, err := s.PutOAuth.Execute(r.Context(), application.PutOAuthInput{
		OwnerID:      ownerID,
		ProjectID:    projectID,
		Slug:         r.PathValue("slug"),
		ClientID:     body.ClientID,
		ClientSecret: body.ClientSecret,
		RedirectURI:  body.RedirectURI,
		Enabled:      body.Enabled,
		Extra:        body.Extra,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOAuthDTO(item))
}

func (s *Server) internalOAuth(w http.ResponseWriter, r *http.Request) {
	projectID, err := pathUUID(r, "projectId")
	if err != nil {
		writeErr(w, err)
		return
	}
	item, err := s.InternalOAuth.Execute(r.Context(), projectID, r.PathValue("slug"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"slug":          item.Slug,
		"client_id":     item.ClientID,
		"client_secret": item.ClientSecret,
		"redirect_uri":  item.RedirectURI,
		"enabled":       item.Enabled,
		"extra":         item.Extra,
	})
}

func toOAuthDTO(item domain.OAuthProvider) map[string]any {
	extra := item.Extra
	if extra == nil {
		extra = map[string]string{}
	}
	return map[string]any{
		"slug":         item.Slug,
		"client_id":    item.ClientID,
		"redirect_uri": item.RedirectURI,
		"enabled":      item.Enabled,
		"configured":   item.SecretConfigured,
		"extra":        extra,
	}
}
