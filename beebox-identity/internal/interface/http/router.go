package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
	"github.com/google/uuid"
)

const (
	headerInternalToken = "X-BeeBox-Internal-Token"
	headerProjectID     = "X-BeeBox-Project-Id"
	headerEnv           = "X-BeeBox-Env"
	headerModules       = "X-BeeBox-Modules"
	headerPublishable   = "X-BeeBox-Publishable-Key"
	headerProjectSlug   = "X-BeeBox-Project-Slug"
	headerOwnerID       = "X-BeeBox-Owner-Id"
)

type ReadyPinger interface {
	Ping(ctx context.Context) error
}

type ProjectResolver interface {
	Resolve(ctx context.Context, pk, slug string) (domain.Scope, error)
}

type Deps struct {
	SignUp        application.SignUp
	SignIn        application.SignIn
	SignOut       application.SignOut
	Me            application.Me
	InternalToken string
	Resolver      ProjectResolver
	Ready         ReadyPinger
}

type Server struct{ Deps }

func New(d Deps) http.Handler {
	s := &Server{Deps: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.readyHandler)
	mux.Handle("POST /v1/auth/sign-up", s.withInternal(http.HandlerFunc(s.postSignUp)))
	mux.Handle("POST /v1/auth/sign-in", s.withInternal(http.HandlerFunc(s.postSignIn)))
	mux.Handle("POST /v1/auth/sign-out", s.withInternal(http.HandlerFunc(s.postSignOut)))
	mux.Handle("GET /v1/auth/me", s.withInternal(http.HandlerFunc(s.getMe)))
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

func (s *Server) postSignUp(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	email, password, err := readCredentials(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	result, err := s.SignUp.Execute(r.Context(), scope, email, password)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAuthDTO(result))
}

func (s *Server) postSignIn(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	email, password, err := readCredentials(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	result, err := s.SignIn.Execute(r.Context(), scope, email, password)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAuthDTO(result))
}

func (s *Server) postSignOut(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scopeOptional(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.SignOut.Execute(r.Context(), scope, bearerToken(r)); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getMe(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scopeOptional(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	user, err := s.Me.Execute(r.Context(), scope, bearerToken(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserDTO(user))
}
