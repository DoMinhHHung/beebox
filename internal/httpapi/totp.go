package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type TOTPApplicationService interface {
	StartEnrollment(context.Context, authentication.TOTPSession, audit.CorrelationID) (authentication.TOTPEnrollmentResult, error)
	ConfirmEnrollment(context.Context, authentication.TOTPSession, string, string, audit.CorrelationID) (authentication.TOTPCredentialView, error)
	Current(context.Context, authentication.TOTPSession) (authentication.TOTPCredentialView, error)
	Remove(context.Context, authentication.TOTPSession, audit.CorrelationID) error
}

type TOTPAuthenticationCompletion interface {
	Complete(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error)
}

type totpHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	sessions     SessionManagementService
	totp         TOTPApplicationService
	completion   TOTPAuthenticationCompletion
}

type totpEnrollmentConfirmRequest struct {
	EnrollmentID string `json:"enrollment_id"`
	Code         string `json:"code"`
}

type totpCompletionRequest struct {
	PendingMFAToken string `json:"pending_mfa_token"`
	Code            string `json:"code"`
}

type totpStateResponse struct {
	Enabled    bool   `json:"enabled"`
	Credential string `json:"credential_id,omitempty"`
}

func WithTOTP(
	base http.Handler,
	applications ApplicationResolver,
	origins OriginPolicy,
	sessions SessionManagementService,
	totp TOTPApplicationService,
	completion TOTPAuthenticationCompletion,
) http.Handler {
	return &totpHTTP{
		base:         base,
		applications: applications,
		origins:      origins,
		sessions:     sessions,
		totp:         totp,
		completion:   completion,
	}
}

func (h *totpHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/mfa/totp", "/v1/mfa/totp/enrollments", "/v1/mfa/totp/enrollments/confirm", "/v1/mfa/totp/complete":
		h.serve(w, r)
	default:
		h.base.ServeHTTP(w, r)
	}
}

func (h *totpHTTP) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		w.Header().Set(RequestIDHeader, "request_unavailable")
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "TOTP authentication is temporarily unavailable.", "request_unavailable")
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
	case r.URL.Path == "/v1/mfa/totp/enrollments" && r.Method == http.MethodPost:
		h.startEnrollment(w, r, requestID, correlationID, app)
	case r.URL.Path == "/v1/mfa/totp/enrollments/confirm" && r.Method == http.MethodPost:
		h.confirmEnrollment(w, r, requestID, correlationID, app)
	case r.URL.Path == "/v1/mfa/totp" && r.Method == http.MethodGet:
		h.currentState(w, r, requestID, app)
	case r.URL.Path == "/v1/mfa/totp" && r.Method == http.MethodDelete:
		h.remove(w, r, requestID, correlationID, app)
	case r.URL.Path == "/v1/mfa/totp/complete" && r.Method == http.MethodPost:
		h.complete(w, r, requestID, correlationID, app)
	default:
		methodNotAllowed(w, requestID)
	}
}

func (h *totpHTTP) startEnrollment(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, app applicationinstance.Instance) {
	current, ok := h.current(w, r, requestID, app)
	if !ok {
		return
	}
	if h.totp == nil {
		h.unavailable(w, requestID)
		return
	}
	result, err := h.totp.StartEnrollment(r.Context(), current, correlationID)
	if err != nil {
		h.writeError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *totpHTTP) confirmEnrollment(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, app applicationinstance.Instance) {
	current, ok := h.current(w, r, requestID, app)
	if !ok {
		return
	}
	var input totpEnrollmentConfirmRequest
	if decodeJSON(w, r, &input) != nil || input.EnrollmentID == "" || input.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "The TOTP enrollment confirmation request is invalid.", requestID)
		return
	}
	if h.totp == nil {
		h.unavailable(w, requestID)
		return
	}
	view, err := h.totp.ConfirmEnrollment(r.Context(), current, input.EnrollmentID, input.Code, correlationID)
	if err != nil {
		h.writeError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *totpHTTP) currentState(w http.ResponseWriter, r *http.Request, requestID string, app applicationinstance.Instance) {
	current, ok := h.current(w, r, requestID, app)
	if !ok {
		return
	}
	if h.totp == nil {
		writeJSON(w, http.StatusOK, totpStateResponse{Enabled: false})
		return
	}
	view, err := h.totp.Current(r.Context(), current)
	if errors.Is(err, authentication.ErrTOTPEnrollmentInvalid) {
		writeJSON(w, http.StatusOK, totpStateResponse{Enabled: false})
		return
	}
	if err != nil {
		h.writeError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, totpStateResponse{Enabled: true, Credential: view.ID})
}

func (h *totpHTTP) remove(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, app applicationinstance.Instance) {
	current, ok := h.current(w, r, requestID, app)
	if !ok {
		return
	}
	if h.totp == nil {
		h.unavailable(w, requestID)
		return
	}
	if err := h.totp.Remove(r.Context(), current, correlationID); err != nil {
		h.writeError(w, requestID, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *totpHTTP) complete(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, app applicationinstance.Instance) {
	var input totpCompletionRequest
	if decodeJSON(w, r, &input) != nil || input.PendingMFAToken == "" || input.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "The TOTP completion request is invalid.", requestID)
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

func (h *totpHTTP) current(w http.ResponseWriter, r *http.Request, requestID string, app applicationinstance.Instance) (authentication.TOTPSession, bool) {
	if h.sessions == nil {
		h.unavailable(w, requestID)
		return authentication.TOTPSession{}, false
	}
	token, ok := bearerToken(r.Header.Values("Authorization"))
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return authentication.TOTPSession{}, false
	}
	record, err := h.sessions.Current(r.Context(), app.InternalID, string(app.PublicID), token)
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

func (h *totpHTTP) applicationOrigin(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, bool) {
	if h.applications == nil || h.origins == nil {
		h.unavailable(w, requestID)
		return applicationinstance.Instance{}, false
	}
	keys := r.Header.Values(PublishableKeyHeader)
	if len(keys) != 1 || keys[0] == "" {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, false
	}
	app, err := h.applications.ResolvePublishable(r.Context(), keys[0])
	if err != nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, false
	}
	origins := r.Header.Values("Origin")
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

func (h *totpHTTP) preflight(w http.ResponseWriter, r *http.Request, requestID string) {
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
	if method != http.MethodPost && method != http.MethodGet && method != http.MethodDelete {
		methodNotAllowed(w, requestID)
		return
	}
	setCORSHeaders(w, canonical)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-BeeBox-Publishable-Key")
	w.Header().Set("Access-Control-Max-Age", "300")
	w.WriteHeader(http.StatusNoContent)
}

func (h *totpHTTP) writeError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, authentication.ErrTOTPInvalidSession):
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
	case errors.Is(err, authentication.ErrTOTPReverificationRequired):
		writeError(w, http.StatusForbidden, "reverification_required", "Recent authentication is required for this TOTP operation.", requestID)
	case errors.Is(err, authentication.ErrTOTPAlreadyActive):
		writeError(w, http.StatusConflict, "totp_already_active", "TOTP is already active.", requestID)
	case errors.Is(err, authentication.ErrLastAuthenticationMethod):
		writeError(w, http.StatusConflict, "last_authentication_method", "At least one usable primary authentication method must remain.", requestID)
	case errors.Is(err, authentication.ErrTOTPInvalidCode), errors.Is(err, authentication.ErrTOTPReplay), errors.Is(err, authentication.ErrPendingMFAInvalid), errors.Is(err, authentication.ErrPendingMFAExpired), errors.Is(err, authentication.ErrPendingMFAReplay):
		writeError(w, http.StatusUnauthorized, "invalid_totp_proof", "The TOTP proof is invalid or expired.", requestID)
	case errors.Is(err, authentication.ErrTOTPEnrollmentInvalid):
		writeError(w, http.StatusBadRequest, "invalid_totp_enrollment", "The TOTP enrollment is invalid or expired.", requestID)
	default:
		h.unavailable(w, requestID)
	}
}

func (h *totpHTTP) unavailable(w http.ResponseWriter, requestID string) {
	writeError(w, http.StatusServiceUnavailable, "service_unavailable", "TOTP authentication is temporarily unavailable.", requestID)
}
