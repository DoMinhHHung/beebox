package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
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
	ListFields    application.ListFields
	PutFields     application.PutFields
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
	mux.Handle("GET /v1/projects/{id}/fields", s.withOwner(http.HandlerFunc(s.getFields)))
	mux.Handle("PUT /v1/projects/{id}/fields", s.withOwner(http.HandlerFunc(s.putFields)))
	mux.Handle("GET /internal/resolve", s.withInternal(http.HandlerFunc(s.resolve)))
	mux.HandleFunc("/", s.notFound)
	return recoverMW(mux)
}
