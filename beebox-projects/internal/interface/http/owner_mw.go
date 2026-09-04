package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
	"github.com/google/uuid"
)

type ctxKey int

const ownerCtxKey ctxKey = 1

func (s *Server) withOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if strings.HasPrefix(token, domain.OwnerTokenPrefix) {
			account, err := s.OwnerMe.Execute(r.Context(), token)
			if err != nil {
				writeErr(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ownerCtxKey, account.ID)))
			return
		}
		if !s.AllowOwnerHeader {
			writeErr(w, domain.ErrUnauthorized)
			return
		}
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
