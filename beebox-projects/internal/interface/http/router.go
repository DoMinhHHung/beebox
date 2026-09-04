package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-apperror"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

const (
	ownerHeader    = "X-BeeBox-Owner-Id"
	internalHeader = "X-BeeBox-Internal-Token"
)

type ReadyPinger interface {
	Ping(ctx context.Context) error
}

type Deps struct {
	CreateAccount application.CreateAccount
	CreateProject application.CreateProject
	ListProjects  application.ListProjects
	GetProject    application.GetProject
	UpdateProject application.UpdateProject
	DeleteProject application.DeleteProject
	ListKeys      application.ListKeys
	CreateKey     application.CreateKey
	RevokeKey     application.RevokeKey
	ListOrigins   application.ListOrigins
	AddOrigin     application.AddOrigin
	DeleteOrigin  application.DeleteOrigin
	ListModules   application.ListModules
	PutModules    application.PutModules
	Resolve       application.ResolveProject
	InternalToken string
	Ready         ReadyPinger
}

type Server struct{ Deps }

func New(d Deps) http.Handler {
	s := &Server{Deps: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.readyHandler)
	mux.HandleFunc("POST /v1/accounts", s.postAccount)
	mux.Handle("POST /v1/projects", s.withOwner(http.HandlerFunc(s.postProject)))
	mux.Handle("GET /v1/projects", s.withOwner(http.HandlerFunc(s.getProjects)))
	mux.Handle("GET /v1/projects/{id}", s.withOwner(http.HandlerFunc(s.getProjectByID)))
	mux.Handle("PATCH /v1/projects/{id}", s.withOwner(http.HandlerFunc(s.patchProject)))
	mux.Handle("DELETE /v1/projects/{id}", s.withOwner(http.HandlerFunc(s.deleteProjectByID)))
	mux.Handle("GET /v1/projects/{id}/keys", s.withOwner(http.HandlerFunc(s.getKeys)))
	mux.Handle("POST /v1/projects/{id}/keys", s.withOwner(http.HandlerFunc(s.postKey)))
	mux.Handle("POST /v1/projects/{id}/keys/{keyId}/revoke", s.withOwner(http.HandlerFunc(s.revokeKey)))
	mux.Handle("GET /v1/projects/{id}/origins", s.withOwner(http.HandlerFunc(s.getOrigins)))
	mux.Handle("POST /v1/projects/{id}/origins", s.withOwner(http.HandlerFunc(s.postOrigin)))
	mux.Handle("DELETE /v1/projects/{id}/origins/{originId}", s.withOwner(http.HandlerFunc(s.deleteOrigin)))
	mux.Handle("GET /v1/projects/{id}/modules", s.withOwner(http.HandlerFunc(s.getModules)))
	mux.Handle("PUT /v1/projects/{id}/modules", s.withOwner(http.HandlerFunc(s.putModules)))
	mux.Handle("GET /internal/resolve", s.withInternal(http.HandlerFunc(s.resolve)))
	mux.HandleFunc("/", s.notFound)
	return recoverMW(mux)
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	if s.Ready != nil {
		if err := s.Ready.Ping(r.Context()); err != nil {
			http.Error(w, `{"status":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) postAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	account, err := s.CreateAccount.Execute(r.Context(), body.Email)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, accountDTO{ID: account.ID.String(), Email: account.Email})
}

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

type ctxKey int

const ownerCtxKey ctxKey = 1

func (s *Server) withOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get(ownerHeader)
		if raw == "" {
			writeErr(w, domain.ErrUnauthorized)
			return
		}
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil {
			writeErr(w, domain.ErrInvalidInput)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ownerCtxKey, id)))
	})
}

func (s *Server) withInternal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokenMatch(r.Header.Get(internalHeader), s.InternalToken) {
			writeErr(w, domain.ErrUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func tokenMatch(got, want string) bool {
	if want == "" {
		return false
	}
	gb, wb := []byte(got), []byte(want)
	if len(gb) != len(wb) {
		return false
	}
	return subtle.ConstantTimeCompare(gb, wb) == 1
}

func ownerFrom(ctx context.Context) (uuid.UUID, error) {
	id, ok := ctx.Value(ownerCtxKey).(uuid.UUID)
	if !ok || id == uuid.Nil {
		return uuid.Nil, domain.ErrUnauthorized
	}
	return id, nil
}

func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil || id == uuid.Nil {
		return uuid.Nil, domain.ErrInvalidInput
	}
	return id, nil
}

func ownerProject(r *http.Request) (uuid.UUID, uuid.UUID, error) {
	ownerID, err := ownerFrom(r.Context())
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	projectID, err := pathUUID(r, "id")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return ownerID, projectID, nil
}

func decodeJSON(r *http.Request, dest any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(dest)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		apperror.WriteJSON(w, apperror.New(apperror.CodeNotFound, "not found"))
	case errors.Is(err, domain.ErrInvalidInput):
		apperror.WriteJSON(w, apperror.New(apperror.CodeInvalidInput, "invalid input"))
	case errors.Is(err, domain.ErrConflict):
		apperror.WriteJSON(w, apperror.New(apperror.CodeConflict, "conflict"))
	case errors.Is(err, domain.ErrUnauthorized):
		apperror.WriteJSON(w, apperror.New(apperror.CodeUnauthorized, "unauthorized"))
	case errors.Is(err, domain.ErrForbidden):
		apperror.WriteJSON(w, apperror.New(apperror.CodeForbidden, "forbidden"))
	case errors.Is(err, domain.ErrPlanLimit):
		apperror.WriteJSON(w, apperror.New(apperror.CodePlanLimitFields, "plan limit"))
	default:
		apperror.WriteJSON(w, apperror.New(apperror.CodeInternal, "internal error"))
	}
}

func recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				apperror.WriteJSON(w, apperror.New(apperror.CodeInternal, "internal error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
