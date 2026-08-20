package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
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

type SessionSelfService interface {
	ListSessions(context.Context, applicationinstance.InternalID, string, string, int, string) (session.Page, error)
	RevokeOwnSession(context.Context, applicationinstance.InternalID, string, string, string, audit.CorrelationID) (bool, error)
	RevokeOtherSessions(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error
	SignOutEverywhere(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error
}

type sessionManagementHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	secrets      SecretApplicationAuthenticator
	sessions     SessionManagementService
	selfService  SessionSelfService
}

type publicSessionResponse struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	Revoked   bool   `json:"revoked"`
}

type selfServiceSessionResponse struct {
	ID            string `json:"id"`
	CreatedAt     string `json:"created_at"`
	LastSeenAt    string `json:"last_seen_at"`
	IdleExpiresAt string `json:"idle_expires_at"`
	ExpiresAt     string `json:"expires_at"`
	Revoked       bool   `json:"revoked"`
	Current       bool   `json:"current"`
}

type selfServiceSessionPageResponse struct {
	Items      []selfServiceSessionResponse `json:"items"`
	NextCursor string                       `json:"next_cursor,omitempty"`
}

func WithSessionManagement(base http.Handler, applications ApplicationResolver, secrets SecretApplicationAuthenticator, sessions SessionManagementService) http.Handler {
	selfService, _ := sessions.(SessionSelfService)
	return &sessionManagementHTTP{base: base, applications: applications, secrets: secrets, sessions: sessions, selfService: selfService}
}

func (h *sessionManagementHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/sessions":
		h.withContext(w, r, h.handleListSessions)
	case r.URL.Path == "/v1/sessions/current":
		h.withContext(w, r, h.handleCurrent)
	case r.URL.Path == "/v1/sessions/sign-out":
		h.withContext(w, r, h.handleSignOut)
	case r.URL.Path == "/v1/sessions/revoke-others":
		h.withContext(w, r, h.handleRevokeOtherSessions)
	case r.URL.Path == "/v1/sessions/sign-out-everywhere":
		h.withContext(w, r, h.handleSignOutEverywhere)
	case strings.HasPrefix(r.URL.Path, "/v1/sessions/") && strings.HasSuffix(r.URL.Path, "/revoke"):
		h.withContext(w, r, h.handleRevokeOwnSession)
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

func (h *sessionManagementHTTP) handleListSessions(w http.ResponseWriter, r *http.Request, requestID string, _ audit.CorrelationID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "The HTTP method is not allowed.", requestID)
		return
	}
	if h.selfService == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Session management is temporarily unavailable.", requestID)
		return
	}
	limit, cursor, ok := parseSessionListQuery(w, r, requestID)
	if !ok {
		return
	}
	app, token, ok := h.resolveUserContext(w, r, requestID)
	if !ok {
		return
	}
	page, err := h.selfService.ListSessions(r.Context(), app.InternalID, string(app.PublicID), token, limit, cursor)
	if err != nil {
		if errors.Is(err, session.ErrSessionInvalidRequest) {
			writeError(w, http.StatusBadRequest, "invalid_request", "The session list request is invalid.", requestID)
			return
		}
		if errors.Is(err, session.ErrSessionRevoked) || errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrToken) {
			writeError(w, http.StatusUnauthorized, "invalid_session", "The session is invalid.", requestID)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Session management is temporarily unavailable.", requestID)
		return
	}
	response := selfServiceSessionPageResponse{Items: make([]selfServiceSessionResponse, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, item := range page.Items {
		response.Items = append(response.Items, selfServiceSessionResponse{
			ID:            item.PublicID,
			CreatedAt:     item.CreatedAt.UTC().Format(time.RFC3339),
			LastSeenAt:    item.LastSeenAt.UTC().Format(time.RFC3339),
			IdleExpiresAt: item.IdleExpiresAt.UTC().Format(time.RFC3339),
			ExpiresAt:     item.ExpiresAt.UTC().Format(time.RFC3339),
			Revoked:       item.RevokedAt != nil,
			Current:       item.Current,
		})
	}
	writeJSON(w, http.StatusOK, response)
}

func parseSessionListQuery(w http.ResponseWriter, r *http.Request, requestID string) (int, string, bool) {
	query := r.URL.Query()
	if values := query["limit"]; len(values) > 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "The session list request is invalid.", requestID)
		return 0, "", false
	}
	if values := query["cursor"]; len(values) > 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "The session list request is invalid.", requestID)
		return 0, "", false
	}
	limit := 0
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > session.SessionListMaxLimit {
			writeError(w, http.StatusBadRequest, "invalid_request", "The session list request is invalid.", requestID)
			return 0, "", false
		}
		limit = parsed
	}
	cursor := query.Get("cursor")
	if len(cursor) > 512 {
		writeError(w, http.StatusBadRequest, "invalid_request", "The session list request is invalid.", requestID)
		return 0, "", false
	}
	return limit, cursor, true
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

func (h *sessionManagementHTTP) handleRevokeOwnSession(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	if h.selfService == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Session management is temporarily unavailable.", requestID)
		return
	}
	selected := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/sessions/"), "/revoke")
	if selected == "" || strings.Contains(selected, "/") || !session.ValidPublicID(selected) {
		writeError(w, http.StatusNotFound, "session_not_found", "The session was not found.", requestID)
		return
	}
	app, token, ok := h.resolveUserContext(w, r, requestID)
	if !ok {
		return
	}
	revokedCurrent, err := h.selfService.RevokeOwnSession(r.Context(), app.InternalID, string(app.PublicID), token, selected, correlationID)
	if err != nil {
		h.writeSelfServiceMutationError(w, requestID, err)
		return
	}
	if revokedCurrent {
		clearRefreshCookie(w, refreshCookieName(app.PublicID))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *sessionManagementHTTP) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	if h.selfService == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Session management is temporarily unavailable.", requestID)
		return
	}
	app, token, ok := h.resolveUserContext(w, r, requestID)
	if !ok {
		return
	}
	if err := h.selfService.RevokeOtherSessions(r.Context(), app.InternalID, string(app.PublicID), token, correlationID); err != nil {
		h.writeSelfServiceMutationError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, statusEnvelope{Status: "other_sessions_revoked"})
}

func (h *sessionManagementHTTP) handleSignOutEverywhere(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	if h.selfService == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Session management is temporarily unavailable.", requestID)
		return
	}
	app, token, ok := h.resolveUserContext(w, r, requestID)
	if !ok {
		return
	}
	if err := h.selfService.SignOutEverywhere(r.Context(), app.InternalID, string(app.PublicID), token, correlationID); err != nil {
		h.writeSelfServiceMutationError(w, requestID, err)
		return
	}
	clearRefreshCookie(w, refreshCookieName(app.PublicID))
	writeJSON(w, http.StatusOK, statusEnvelope{Status: "signed_out_everywhere"})
}

func (h *sessionManagementHTTP) writeSelfServiceMutationError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, session.ErrSessionInvalidRequest):
		writeError(w, http.StatusBadRequest, "invalid_request", "The session request is invalid.", requestID)
	case errors.Is(err, session.ErrSessionReverification):
		writeError(w, http.StatusForbidden, "reverification_required", "Recent reverification is required for this operation.", requestID)
	case errors.Is(err, session.ErrSessionRevoked), errors.Is(err, session.ErrSessionNotFound), errors.Is(err, session.ErrToken):
		writeError(w, http.StatusUnauthorized, "invalid_session", "The session is invalid.", requestID)
	default:
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Session management is temporarily unavailable.", requestID)
	}
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
