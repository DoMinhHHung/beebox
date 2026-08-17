package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

type PasswordResetService interface {
	RequestWithCorrelation(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) error
	ConfirmWithCorrelation(context.Context, applicationinstance.InternalID, string, string, string, audit.CorrelationID) error
}

type passwordResetHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	resets       PasswordResetService
}

type passwordResetRequest struct {
	Email string `json:"email"`
}

type passwordResetConfirmRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

func WithPasswordReset(base http.Handler, applications ApplicationResolver, origins OriginPolicy, resets PasswordResetService) http.Handler {
	return &passwordResetHTTP{base: base, applications: applications, origins: origins, resets: resets}
}

func (h *passwordResetHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/password-resets", "/v1/password-resets/confirm":
		h.withResetSecurityContext(w, r)
	default:
		h.base.ServeHTTP(w, r)
	}
}

func (h *passwordResetHTTP) withResetSecurityContext(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", "request_unavailable")
		return
	}
	requestID := hex.EncodeToString(correlationID[:])
	w.Header().Set(RequestIDHeader, requestID)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if r.Method == http.MethodOptions {
		h.handleResetPreflight(w, r, requestID)
		return
	}
	if r.URL.Path == "/v1/password-resets" {
		h.handlePasswordResetRequest(w, r, requestID, correlationID)
		return
	}
	h.handlePasswordResetConfirm(w, r, requestID, correlationID)
}

func (h *passwordResetHTTP) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.authorizeResetApplication(w, r, requestID)
	if !ok {
		return
	}
	var input passwordResetRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if h.resets == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	err := h.resets.RequestWithCorrelation(r.Context(), app.InternalID, input.Email, correlationID)
	if err != nil && errors.Is(err, identity.ErrInvalidEmail) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_input", "The supplied input is invalid.", requestID)
		return
	}
	// Eligible-account state, suppression, rate limiting and delivery failures are
	// intentionally collapsed to the same response to avoid account enumeration.
	writeJSON(w, http.StatusAccepted, statusEnvelope{Status: "accepted"})
}

func (h *passwordResetHTTP) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.authorizeResetApplication(w, r, requestID)
	if !ok {
		return
	}
	var input passwordResetConfirmRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if h.resets == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	err := h.resets.ConfirmWithCorrelation(r.Context(), app.InternalID, input.Email, input.Code, input.NewPassword, correlationID)
	if err == nil {
		writeJSON(w, http.StatusOK, statusEnvelope{Status: "password_reset"})
		return
	}
	switch {
	case errors.Is(err, identity.ErrInvalidEmail), errors.Is(err, authentication.ErrInvalidPasswordResetCode), errors.Is(err, authentication.ErrPublicPasswordPolicy):
		writeError(w, http.StatusUnprocessableEntity, "invalid_input", "The supplied input is invalid.", requestID)
	case errors.Is(err, authentication.ErrPasswordResetFailed), errors.Is(err, authentication.ErrPasswordResetStale):
		writeError(w, http.StatusBadRequest, "password_reset_failed", "The password reset could not be completed.", requestID)
	default:
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
	}
}

func (h *passwordResetHTTP) authorizeResetApplication(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, bool) {
	if h.applications == nil || h.origins == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return applicationinstance.Instance{}, false
	}
	values := r.Header.Values(PublishableKeyHeader)
	if len(values) != 1 || values[0] == "" {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, false
	}
	app, err := h.applications.ResolvePublishable(r.Context(), values[0])
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, false
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		allowed, err := h.origins.IsAllowedOrigin(r.Context(), app.InternalID, origin)
		if err != nil || !allowed {
			writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
			return applicationinstance.Instance{}, false
		}
		setCORSHeaders(w, origin)
	}
	return app, true
}

func (h *passwordResetHTTP) handleResetPreflight(w http.ResponseWriter, r *http.Request, requestID string) {
	origin := r.Header.Get("Origin")
	if h.origins == nil || origin == "" {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return
	}
	allowed, err := h.origins.AnyAllowedOrigin(r.Context(), origin)
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return
	}
	setCORSHeaders(w, origin)
	w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-BeeBox-Publishable-Key")
	w.Header().Set("Access-Control-Max-Age", "300")
	w.WriteHeader(http.StatusNoContent)
}
