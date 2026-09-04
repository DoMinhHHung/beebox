package httpapi

import (
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
)

func (s *Server) postProject(w http.ResponseWriter, r *http.Request) {
	ownerID, err := ownerFrom(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Name     string `json:"name"`
		Slug     string `json:"slug"`
		PlanSlug string `json:"plan_slug"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	result, err := s.CreateProject.Execute(r.Context(), application.CreateProjectInput{
		OwnerID: ownerID, Name: body.Name, Slug: body.Slug, PlanSlug: body.PlanSlug,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCreateProjectDTO(result))
}

func (s *Server) getProjects(w http.ResponseWriter, r *http.Request) {
	ownerID, err := ownerFrom(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	projects, err := s.ListProjects.Execute(r.Context(), ownerID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if projects == nil {
		projects = []domain.Project{}
	}
	out := make([]projectDTO, 0, len(projects))
	for _, p := range projects {
		out = append(out, toProjectDTO(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": out})
}

func (s *Server) getProjectByID(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	project, err := s.GetProject.Execute(r.Context(), ownerID, projectID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toProjectDTO(project))
}

func (s *Server) patchProject(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Name     *string `json:"name"`
		Slug     *string `json:"slug"`
		PlanSlug *string `json:"plan_slug"`
		Status   *string `json:"status"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	project, err := s.UpdateProject.Execute(r.Context(), application.UpdateProjectInput{
		OwnerID: ownerID, ID: projectID, Name: body.Name, Slug: body.Slug, PlanSlug: body.PlanSlug, Status: body.Status,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toProjectDTO(project))
}

func (s *Server) deleteProjectByID(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	if err := s.DeleteProject.Execute(r.Context(), ownerID, projectID, body.Confirmation); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getKeys(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	keys, err := s.ListKeys.Execute(r.Context(), ownerID, projectID)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]keyDTO, 0, len(keys))
	for _, k := range keys {
		out = append(out, toKeyDTO(k, ""))
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (s *Server) postKey(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Kind string `json:"kind"`
		Env  string `json:"env"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	issued, err := s.CreateKey.Execute(r.Context(), application.CreateKeyInput{
		OwnerID: ownerID, ProjectID: projectID, Kind: body.Kind, Env: body.Env,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toKeyDTO(issued.Key, issued.Secret))
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	keyID, err := pathUUID(r, "keyId")
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.RevokeKey.Execute(r.Context(), ownerID, projectID, keyID); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getOrigins(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	origins, err := s.ListOrigins.Execute(r.Context(), ownerID, projectID)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]originDTO, 0, len(origins))
	for _, item := range origins {
		out = append(out, toOriginDTO(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"origins": out})
}

func (s *Server) postOrigin(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Origin string `json:"origin"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	item, err := s.AddOrigin.Execute(r.Context(), ownerID, projectID, body.Origin)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toOriginDTO(item))
}

func (s *Server) deleteOrigin(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	originID, err := pathUUID(r, "originId")
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.DeleteOrigin.Execute(r.Context(), ownerID, projectID, originID); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getModules(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	names, err := s.ListModules.Execute(r.Context(), ownerID, projectID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if names == nil {
		names = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"modules": names})
}

func (s *Server) putModules(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Modules []string `json:"modules"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	names, err := s.PutModules.Execute(r.Context(), ownerID, projectID, body.Modules)
	if err != nil {
		writeErr(w, err)
		return
	}
	if names == nil {
		names = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"modules": names})
}

func (s *Server) resolve(w http.ResponseWriter, r *http.Request) {
	pk := r.URL.Query().Get("pk")
	slug := r.URL.Query().Get("slug")
	var result application.ResolveResult
	var err error
	switch {
	case pk != "":
		result, err = s.Resolve.ByPublishableKey(r.Context(), pk)
	case slug != "":
		result, err = s.Resolve.BySlug(r.Context(), slug)
	default:
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toResolveDTO(result))
}

func (s *Server) notFound(w http.ResponseWriter, _ *http.Request) {
	apperror.WriteJSON(w, apperror.New(apperror.CodeNotFound, "not found"))
}
