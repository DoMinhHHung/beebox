package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type RecoveryCodeApplicationService interface {
	Regenerate(context.Context, authentication.TOTPSession, audit.CorrelationID) (authentication.RecoveryCodeSetResult, error)
	State(context.Context, authentication.TOTPSession) (authentication.RecoveryCodeState, error)
}

type RecoveryCodeCompletion interface {
	Complete(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error)
}

type recoveryCodeHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	sessions     SessionManagementService
	recovery     RecoveryCodeApplicationService
	completion   RecoveryCodeCompletion
}

type recoveryCodeCompleteRequest struct {
	PendingMFAToken string `json:"pending_mfa_token"`
	Code            string `json:"code"`
}

func WithRecoveryCodes(base http.Handler, applications ApplicationResolver, origins OriginPolicy, sessions SessionManagementService, recovery RecoveryCodeApplicationService, completion RecoveryCodeCompletion) http.Handler {
	return &recoveryCodeHTTP{base: base, applications: applications, origins: origins, sessions: sessions, recovery: recovery, completion: completion}
}

func (h *recoveryCodeHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/mfa/recovery-codes", "/v1/mfa/recovery-codes/regenerate", "/v1/mfa/recovery-codes/complete":
		h.serve(w, r)
	default:
		h.base.ServeHTTP(w, r)
	}
}

func (h *recoveryCodeHTTP) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, err := correlationForRequest(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Recovery is temporarily unavailable.", "request_unavailable")
		return
	}
	requestID := hex.EncodeToString(correlationID[:])
	w.Header().Set(RequestIDHeader, requestID)
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	if r.Method == http.MethodOptions {
		h.preflight(w, r, requestID)
		return
	}
	app, ok := h.applicationOrigin(w, r, requestID)
	if !ok {
		return
	}
	switch {
	case r.URL.Path == "/v1/mfa/recovery-codes/complete" && r.Method == http.MethodPost:
		h.complete(w, r, requestID, correlationID, app)
	case r.URL.Path == "/v1/mfa/recovery-codes/regenerate" && r.Method == http.MethodPost:
		current, ok := h.current(w, r, requestID, app)
		if !ok {
			return
		}
		result, err := h.recovery.Regenerate(r.Context(), current, correlationID)
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case r.URL.Path == "/v1/mfa/recovery-codes" && r.Method == http.MethodGet:
		current, ok := h.current(w, r, requestID, app)
		if !ok {
			return
		}
		state, err := h.recovery.State(r.Context(), current)
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusOK, state)
	default:
		methodNotAllowed(w, requestID)
	}
}

func (h *recoveryCodeHTTP) preflight(w http.ResponseWriter, r *http.Request, requestID string) {
	origins := r.Header.Values("Origin")
	if h.origins == nil || len(origins) != 1 || origins[0] == "" {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return
	}
	canonical, err := applicationinstance.CanonicalizeOrigin(origins[0])
	if err != nil || canonical != origins[0] {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return
	}
	allowed, err := h.origins.AnyAllowedOrigin(r.Context(), canonical)
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return
	}
	method := r.Header.Get("Access-Control-Request-Method")
	if method != http.MethodGet && method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	setCORSHeaders(w, canonical)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-BeeBox-Publishable-Key")
	w.Header().Set("Access-Control-Max-Age", "300")
	w.WriteHeader(http.StatusNoContent)
}

func (h *recoveryCodeHTTP) complete(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, app applicationinstance.Instance) {
	var input recoveryCodeCompleteRequest
	if decodeJSON(w, r, &input) != nil || input.PendingMFAToken == "" || input.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "The recovery completion request is invalid.", requestID)
		return
	}
	if h.completion == nil {
		h.unavailable(w, requestID)
		return
	}
	pair, err := h.completion.Complete(r.Context(), app.InternalID, input.PendingMFAToken, input.Code, correlationID)
	if err != nil {
		h.writeError(w, requestID, err)
		return
	}
	writeAuthenticationTokenPair(w, r, pair, app.PublicID)
}

func (h *recoveryCodeHTTP) current(w http.ResponseWriter, r *http.Request, requestID string, app applicationinstance.Instance) (authentication.TOTPSession, bool) {
	if h.sessions == nil || h.recovery == nil {
		h.unavailable(w, requestID)
		return authentication.TOTPSession{}, false
	}
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || len(authorization) <= len("Bearer ") {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return authentication.TOTPSession{}, false
	}
	record, err := h.sessions.Current(r.Context(), app.InternalID, string(app.PublicID), strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return authentication.TOTPSession{}, false
	}
	return authentication.TOTPSession{
		ApplicationInstanceID: record.ApplicationInstanceID,
		ApplicationPublicID:   app.PublicID,
		UserID:                record.UserInternalID,
		UserPublicID:          identity.PublicID(record.UserPublicID),
		SessionPublicID:       record.PublicID,
		CreatedAt:             record.CreatedAt,
		IdleExpiresAt:         record.IdleExpiresAt,
		ExpiresAt:             record.ExpiresAt,
		Revoked:               record.RevokedAt != nil,
	}, true
}

func (h *recoveryCodeHTTP) applicationOrigin(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, bool) {
	if h.applications == nil || h.origins == nil {
		h.unavailable(w, requestID)
		return applicationinstance.Instance{}, false
	}
	keys := r.Header.Values(PublishableKeyHeader)
	origins := r.Header.Values("Origin")
	if len(keys) != 1 || keys[0] == "" {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, false
	}
	app, err := h.applications.ResolvePublishable(r.Context(), keys[0])
	if err != nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, false
	}
	if len(origins) != 1 || origins[0] == "" {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, false
	}
	canonical, err := applicationinstance.CanonicalizeOrigin(origins[0])
	if err != nil || canonical != origins[0] {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, false
	}
	allowed, err := h.origins.IsAllowedOrigin(r.Context(), app.InternalID, canonical)
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, false
	}
	setCORSHeaders(w, canonical)
	return app, true
}

func (h *recoveryCodeHTTP) writeError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, authentication.ErrRecoveryInvalid), errors.Is(err, authentication.ErrRecoveryReplay):
		writeError(w, http.StatusUnauthorized, "invalid_recovery_proof", "The recovery proof is invalid or expired.", requestID)
	case errors.Is(err, authentication.ErrRecoveryReverification):
		writeError(w, http.StatusForbidden, "reverification_required", "Recent authentication is required for this recovery operation.", requestID)
	case errors.Is(err, authentication.ErrRecoveryRateLimited):
		w.Header().Set("Retry-After", "3600")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many recovery operations were received.", requestID)
	default:
		h.unavailable(w, requestID)
	}
}

func (h *recoveryCodeHTTP) unavailable(w http.ResponseWriter, requestID string) {
	writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Recovery is temporarily unavailable.", requestID)
}
