package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-apperror"
	"github.com/DoMinhHHung/beebox/beebox-plans/internal/application"
	"github.com/DoMinhHHung/beebox/beebox-plans/internal/domain"
)

type ReadyPinger interface {
	Ping(ctx context.Context) error
}

type Server struct {
	list  application.ListPlans
	get   application.GetPlan
	ready ReadyPinger
}

func New(list application.ListPlans, get application.GetPlan, ready ReadyPinger) http.Handler {
	s := &Server{list: list, get: get, ready: ready}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.readyHandler)
	mux.HandleFunc("GET /v1/plans", s.listPlans)
	mux.HandleFunc("GET /v1/plans/{slug}", s.getPlan)
	mux.HandleFunc("/", s.notFound)
	return recoverMW(mux)
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	writeOK(w)
}

func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	if s.ready != nil {
		if err := s.ready.Ping(r.Context()); err != nil {
			http.Error(w, `{"status":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
	}
	writeOK(w)
}

func (s *Server) listPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := s.list.Execute(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	if plans == nil {
		plans = []domain.Plan{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"plans": toDTOs(plans)})
}

func (s *Server) getPlan(w http.ResponseWriter, r *http.Request) {
	plan, err := s.get.Execute(r.Context(), r.PathValue("slug"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDTO(plan))
}

func (s *Server) notFound(w http.ResponseWriter, _ *http.Request) {
	apperror.WriteJSON(w, apperror.New(apperror.CodeNotFound, "not found"))
}

type planDTO struct {
	ID     string        `json:"id"`
	Slug   string        `json:"slug"`
	Name   string        `json:"name"`
	Limits domain.Limits `json:"limits"`
}

func toDTO(p domain.Plan) planDTO {
	return planDTO{ID: p.ID.String(), Slug: p.Slug, Name: p.Name, Limits: p.Limits}
}

func toDTOs(plans []domain.Plan) []planDTO {
	out := make([]planDTO, 0, len(plans))
	for _, p := range plans {
		out = append(out, toDTO(p))
	}
	return out
}

func writeOK(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
