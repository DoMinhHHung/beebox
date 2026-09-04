package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-apperror"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

const ownerHeader = "X-BeeBox-Owner-Id"

type ReadyPinger interface {
	Ping(ctx context.Context) error
}

type Server struct {
	createAccount application.CreateAccount
	createProject application.CreateProject
	listProjects  application.ListProjects
	getProject    application.GetProject
	updateProject application.UpdateProject
	deleteProject application.DeleteProject
	ready         ReadyPinger
}

func New(
	createAccount application.CreateAccount,
	createProject application.CreateProject,
	listProjects application.ListProjects,
	getProject application.GetProject,
	updateProject application.UpdateProject,
	deleteProject application.DeleteProject,
	ready ReadyPinger,
) http.Handler {
	s := &Server{
		createAccount: createAccount,
		createProject: createProject,
		listProjects:  listProjects,
		getProject:    getProject,
		updateProject: updateProject,
		deleteProject: deleteProject,
		ready:         ready,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.readyHandler)
	mux.HandleFunc("POST /v1/accounts", s.postAccount)
	mux.Handle("POST /v1/projects", s.withOwner(http.HandlerFunc(s.postProject)))
	mux.Handle("GET /v1/projects", s.withOwner(http.HandlerFunc(s.getProjects)))
	mux.Handle("GET /v1/projects/{id}", s.withOwner(http.HandlerFunc(s.getProjectByID)))
	mux.Handle("PATCH /v1/projects/{id}", s.withOwner(http.HandlerFunc(s.patchProject)))
	mux.Handle("DELETE /v1/projects/{id}", s.withOwner(http.HandlerFunc(s.deleteProjectByID)))
	mux.HandleFunc("/", s.notFound)
	return recoverMW(mux)
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	if s.ready != nil {
		if err := s.ready.Ping(r.Context()); err != nil {
			http.Error(w, `{"status":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type accountBody struct {
	Email string `json:"email"`
}

func (s *Server) postAccount(w http.ResponseWriter, r *http.Request) {
	var body accountBody
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	account, err := s.createAccount.Execute(r.Context(), body.Email)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, accountDTO{ID: account.ID.String(), Email: account.Email})
}

type createProjectBody struct {
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	PlanSlug string `json:"plan_slug"`
}

func (s *Server) postProject(w http.ResponseWriter, r *http.Request) {
	ownerID, err := ownerFrom(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	var body createProjectBody
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	project, err := s.createProject.Execute(r.Context(), application.CreateProjectInput{
		OwnerID:  ownerID,
		Name:     body.Name,
		Slug:     body.Slug,
		PlanSlug: body.PlanSlug,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toProjectDTO(project))
}

func (s *Server) getProjects(w http.ResponseWriter, r *http.Request) {
	ownerID, err := ownerFrom(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	projects, err := s.listProjects.Execute(r.Context(), ownerID)
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
	ownerID, err := ownerFrom(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	project, err := s.getProject.Execute(r.Context(), ownerID, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toProjectDTO(project))
}

type patchProjectBody struct {
	Name     *string `json:"name"`
	Slug     *string `json:"slug"`
	PlanSlug *string `json:"plan_slug"`
	Status   *string `json:"status"`
}

func (s *Server) patchProject(w http.ResponseWriter, r *http.Request) {
	ownerID, err := ownerFrom(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	var body patchProjectBody
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	project, err := s.updateProject.Execute(r.Context(), application.UpdateProjectInput{
		OwnerID:  ownerID,
		ID:       id,
		Name:     body.Name,
		Slug:     body.Slug,
		PlanSlug: body.PlanSlug,
		Status:   body.Status,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toProjectDTO(project))
}

type deleteBody struct {
	Confirmation string `json:"confirmation"`
}

func (s *Server) deleteProjectByID(w http.ResponseWriter, r *http.Request) {
	ownerID, err := ownerFrom(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	var body deleteBody
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	if err := s.deleteProject.Execute(r.Context(), ownerID, id, body.Confirmation); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

func ownerFrom(ctx context.Context) (uuid.UUID, error) {
	id, ok := ctx.Value(ownerCtxKey).(uuid.UUID)
	if !ok || id == uuid.Nil {
		return uuid.Nil, domain.ErrUnauthorized
	}
	return id, nil
}

type accountDTO struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type projectDTO struct {
	ID       string `json:"id"`
	OwnerID  string `json:"owner_id"`
	PlanID   string `json:"plan_id"`
	PlanSlug string `json:"plan_slug"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Env      string `json:"env"`
	Status   string `json:"status"`
}

func toProjectDTO(p domain.Project) projectDTO {
	return projectDTO{
		ID: p.ID.String(), OwnerID: p.OwnerID.String(), PlanID: p.PlanID.String(),
		PlanSlug: p.PlanSlug, Name: p.Name, Slug: p.Slug, Env: p.Env, Status: p.Status,
	}
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
