package httpapi

import (
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

func (s *Server) notFound(w http.ResponseWriter, _ *http.Request) {
	apperror.WriteJSON(w, apperror.New(apperror.CodeNotFound, "not found"))
}

func (s *Server) withInternal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokenMatch(r.Header.Get(headerInternalToken), s.InternalToken) {
			writeErr(w, domain.ErrUnauthorized)
			return
		}
		r.Header.Del(headerOwnerID)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) scope(r *http.Request) (domain.Scope, error) {
	scope, ok, err := s.scopeFromTrustedHeaders(r)
	if err != nil {
		return domain.Scope{}, err
	}
	if ok {
		return scope, nil
	}
	pk, slug := publishableOrSlug(r)
	if s.Resolver == nil {
		return domain.Scope{}, domain.ErrUnauthorized
	}
	return s.Resolver.Resolve(r.Context(), pk, slug)
}

func (s *Server) scopeOptional(r *http.Request) (domain.Scope, error) {
	scope, ok, err := s.scopeFromTrustedHeaders(r)
	if err != nil {
		return domain.Scope{}, err
	}
	if ok {
		return scope, nil
	}
	pk, slug := publishableOrSlug(r)
	if pk == "" && slug == "" {
		return domain.Scope{}, nil
	}
	if s.Resolver == nil {
		return domain.Scope{}, domain.ErrUnauthorized
	}
	return s.Resolver.Resolve(r.Context(), pk, slug)
}

func (s *Server) scopeFromTrustedHeaders(r *http.Request) (domain.Scope, bool, error) {
	rawID := strings.TrimSpace(r.Header.Get(headerProjectID))
	env := strings.TrimSpace(r.Header.Get(headerEnv))
	modules := domain.SplitModules(r.Header.Get(headerModules))
	if rawID == "" && env == "" && len(modules) == 0 {
		return domain.Scope{}, false, nil
	}
	if rawID == "" || env == "" {
		return domain.Scope{}, false, nil
	}
	projectID, err := uuid.Parse(rawID)
	if err != nil || projectID == uuid.Nil {
		return domain.Scope{}, false, domain.ErrUnauthorized
	}
	if !domain.ValidEnv(env) {
		return domain.Scope{}, false, domain.ErrUnauthorized
	}
	return domain.Scope{ProjectID: projectID, Env: env, Modules: modules}, true, nil
}

func publishableOrSlug(r *http.Request) (string, string) {
	if pk := strings.TrimSpace(r.Header.Get(headerPublishable)); pk != "" {
		return pk, ""
	}
	if pk := bearerPublishable(r.Header.Get("Authorization")); pk != "" {
		return pk, ""
	}
	return "", strings.TrimSpace(r.Header.Get(headerProjectSlug))
}

func bearerPublishable(auth string) string {
	tok := bearerTokenFrom(auth)
	if strings.HasPrefix(tok, "pk_") {
		return tok
	}
	return ""
}

func bearerToken(r *http.Request) string {
	return bearerTokenFrom(r.Header.Get("Authorization"))
}

func bearerTokenFrom(auth string) string {
	auth = strings.TrimSpace(auth)
	const scheme = "bearer "
	if len(auth) < len(scheme) || !strings.EqualFold(auth[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(auth[len(scheme):])
}

func readCredentials(r *http.Request) (string, string, error) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return "", "", domain.ErrInvalidInput
	}
	return body.Email, body.Password, nil
}

type userDTO struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	ProjectID string `json:"project_id"`
	Env       string `json:"env"`
}

type sessionDTO struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type authDTO struct {
	User    userDTO    `json:"user"`
	Session sessionDTO `json:"session"`
}

func toUserDTO(user domain.User) userDTO {
	return userDTO{
		ID:        user.ID.String(),
		Email:     user.Email,
		ProjectID: user.ProjectID.String(),
		Env:       user.Env,
	}
}

func toAuthDTO(result application.AuthResult) authDTO {
	return authDTO{
		User: toUserDTO(result.User),
		Session: sessionDTO{
			Token:     result.Token,
			ExpiresAt: result.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		},
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
	case errors.Is(err, domain.ErrForbidden):
		apperror.WriteJSON(w, apperror.New(apperror.CodeForbidden, "forbidden"))
	case errors.Is(err, domain.ErrModuleDisabled):
		apperror.WriteJSON(w, apperror.New(apperror.CodeModuleDisabled, "module disabled"))
	case errors.Is(err, domain.ErrProjectDisabled):
		apperror.WriteJSON(w, apperror.New(apperror.CodeForbidden, "project disabled"))
	default:
		apperror.WriteJSON(w, apperror.New(apperror.CodeInternal, "internal error"))
	}
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
