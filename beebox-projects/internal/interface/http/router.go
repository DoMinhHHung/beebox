package httpapi

import (
	"context"
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
)

const (
	ownerHeader    = "X-BeeBox-Owner-Id"
	internalHeader = "X-BeeBox-Internal-Token"
)

type ReadyPinger interface {
	Ping(ctx context.Context) error
}

type Deps struct {
	CreateAccount    application.CreateAccount
	CreateProject    application.CreateProject
	ListProjects     application.ListProjects
	GetProject       application.GetProject
	UpdateProject    application.UpdateProject
	DeleteProject    application.DeleteProject
	ListKeys         application.ListKeys
	CreateKey        application.CreateKey
	RevokeKey        application.RevokeKey
	ListOrigins      application.ListOrigins
	AddOrigin        application.AddOrigin
	DeleteOrigin     application.DeleteOrigin
	ListModules      application.ListModules
	PutModules       application.PutModules
	ListFields       application.ListFields
	PutFields        application.PutFields
	Resolve          application.ResolveProject
	OwnerSignUp      application.OwnerSignUp
	OwnerSignIn      application.OwnerSignIn
	OwnerSignOut     application.OwnerSignOut
	OwnerMe          application.OwnerMe
	GetOAuth         application.GetOAuthProvider
	PutOAuth         application.PutOAuthProvider
	InternalOAuth    application.InternalOAuthProvider
	AllowOwnerHeader bool
	InternalToken    string
	Ready            ReadyPinger
}

type Server struct{ Deps }

func New(d Deps) http.Handler {
	s := &Server{Deps: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.readyHandler)
	mux.HandleFunc("POST /v1/owner/sign-up", s.postOwnerSignUp)
	mux.HandleFunc("POST /v1/owner/sign-in", s.postOwnerSignIn)
	mux.HandleFunc("POST /v1/owner/sign-out", s.postOwnerSignOut)
	mux.HandleFunc("GET /v1/owner/me", s.getOwnerMe)
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
	mux.Handle("GET /v1/projects/{id}/fields", s.withOwner(http.HandlerFunc(s.getFields)))
	mux.Handle("PUT /v1/projects/{id}/fields", s.withOwner(http.HandlerFunc(s.putFields)))
	mux.Handle("GET /v1/projects/{id}/oauth/{slug}", s.withOwner(http.HandlerFunc(s.getProjectOAuth)))
	mux.Handle("PUT /v1/projects/{id}/oauth/{slug}", s.withOwner(http.HandlerFunc(s.putProjectOAuth)))
	mux.Handle("GET /internal/resolve", s.withInternal(http.HandlerFunc(s.resolve)))
	mux.Handle("GET /internal/oauth/{projectId}/{slug}", s.withInternal(http.HandlerFunc(s.internalOAuth)))
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
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	account, err := s.CreateAccount.Execute(r.Context(), body.Email, body.Password)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, accountDTO{ID: account.ID.String(), Email: account.Email})
}
