package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type SecretApplicationAuthenticator interface {
	AuthenticateSecret(context.Context, string) (applicationinstance.Instance, error)
}

type SessionManagementService interface {
	Current(context.Context, applicationinstance.InternalID, string, string) (session.Record, error)
	SignOut(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error
	GetSession(context.Context, applicationinstance.InternalID, string) (session.Record, error)
	RevokeSession(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) error
}

type sessionManagementHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	secrets      SecretApplicationAuthenticator
	sessions     SessionManagementService
}

type publicSessionResponse struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	Revoked   bool   `json:"revoked"`
}

func WithSessionManagement(base http.Handler, applications ApplicationResolver, secrets SecretApplicationAuthenticator, sessions SessionManagementService) http.Handler {
	return &sessionManagementHTTP{base: base, applications: applications, secrets: secrets, sessions: sessions}
}

func (h *sessionManagementHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/sessions/current":
		h.withContext(w, r, h.handleCurrent)
	case r.URL.Path == "/v1/sessions/sign-out":
		h.withContext(w, r, h.handleSignOut)
	case strings.HasPrefix(r.URL.Path, "/v1/backend/sessions/"):
		h.withContext(w, r, h.handleBackendSession)
	default:
		h.base.ServeHTTP(w, r)
	}
}

func (h *sessionManagementHTTP) withContext(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request, string, audit.CorrelationID)) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", "request_unavailable")
		return
	}
	requestID := hex.EncodeToString(correlationID[:])
	w.Header().Set(RequestIDHeader, requestID)
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	next(w, r.WithContext(ctx), requestID, correlationID)
}

func (h *sessionManagementHTTP) handleCurrent(w http.ResponseWriter, r *http.Request, requestID string, _ audit.CorrelationID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "The HTTP method is not allowed.", requestID)
		return
	}
	app, token, ok := h.resolveUserContext(w, r, requestID)
	if !ok {
		return
	}
	record, err := h.sessions.Current(r.Context(), app.InternalID, string(app.PublicID), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The session is invalid.", requestID)
		return
	}
	writeJSON(w, http.StatusOK, publicSession(record))
}

func (h *sessionManagementHTTP) handleSignOut(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, token, ok := h.resolveUserContext(w, r, requestID)
	if !ok {
		return
	}
	if err := h.sessions.SignOut(r.Context(), app.InternalID, string(app.PublicID), token, correlationID); err != nil && !errors.Is(err, session.ErrSessionRevoked) {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The session is invalid.", requestID)
		return
	}
	clearRefreshCookie(w, refreshCookieName(app.PublicID))
	writeJSON(w, http.StatusOK, statusEnvelope{Status: "signed_out"})
}

func (h *sessionManagementHTTP) handleBackendSession(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if h.secrets == nil || h.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Session management is temporarily unavailable.", requestID)
		return
	}
	secret, ok := bearerToken(r.Header.Values("Authorization"))
	if !ok || !strings.HasPrefix(secret, "bb_sk_") {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return
	}
	app, err := h.secrets.AuthenticateSecret(r.Context(), secret)
	if err != nil || !app.InternalID.Valid() {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/backend/sessions/")
	revoke := strings.HasSuffix(path, "/revoke")
	if revoke {
		path = strings.TrimSuffix(path, "/revoke")
	}
	if path == "" || strings.Contains(path, "/") || !session.ValidPublicID(path) {
		writeError(w, http.StatusNotFound, "session_not_found", "The session was not found.", requestID)
		return
	}
	if revoke {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, requestID)
			return
		}
		if err := h.sessions.RevokeSession(r.Context(), app.InternalID, path, correlationID); err != nil {
			writeError(w, http.StatusNotFound, "session_not_found", "The session was not found.", requestID)
			return
		}
		writeJSON(w, http.StatusOK, statusEnvelope{Status: "revoked"})
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "The HTTP method is not allowed.", requestID)
		return
	}
	record, err := h.sessions.GetSession(r.Context(), app.InternalID, path)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", "The session was not found.", requestID)
		return
	}
	writeJSON(w, http.StatusOK, publicSession(record))
}

func (h *sessionManagementHTTP) resolveUserContext(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, string, bool) {
	if h.applications == nil || h.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Session management is temporarily unavailable.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	values := r.Header.Values(PublishableKeyHeader)
	if len(values) != 1 || values[0] == "" {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	app, err := h.applications.ResolvePublishable(r.Context(), values[0])
	if err != nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	token, ok := bearerToken(r.Header.Values("Authorization"))
	if !ok || strings.HasPrefix(token, "bb_sk_") {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The session is invalid.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	return app, token, true
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Split(values[0], " ")
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func publicSession(record session.Record) publicSessionResponse {
	return publicSessionResponse{
		ID:        record.PublicID,
		UserID:    record.UserPublicID,
		CreatedAt: record.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt: record.ExpiresAt.UTC().Format(time.RFC3339),
		Revoked:   record.RevokedAt != nil,
	}
}
