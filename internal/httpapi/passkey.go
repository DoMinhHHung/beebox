package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type PasskeyApplicationService interface {
	BeginRegistration(context.Context, authentication.PasskeySession, string) (authentication.PasskeyBeginResult, error)
	FinishRegistration(context.Context, authentication.PasskeySession, string, string, string, json.RawMessage, audit.CorrelationID) (authentication.PasskeyView, error)
	BeginAuthentication(context.Context, applicationinstance.Instance, string) (authentication.PasskeyBeginResult, error)
	List(context.Context, authentication.PasskeySession) ([]authentication.PasskeyView, error)
	Remove(context.Context, authentication.PasskeySession, string, audit.CorrelationID) error
}

type PasskeyAuthenticationCompletion interface {
	CompleteAuthentication(context.Context, applicationinstance.Instance, string, string, json.RawMessage, audit.CorrelationID) (session.TokenPair, error)
}

type passkeyHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	sessions     SessionManagementService
	passkeys     PasskeyApplicationService
	completion   PasskeyAuthenticationCompletion
}

type passkeyRegistrationCompleteRequest struct {
	AttemptID  string          `json:"attempt_id"`
	Name       string          `json:"name,omitempty"`
	Credential json.RawMessage `json:"credential"`
}

type passkeyAuthenticationCompleteRequest struct {
	AttemptID  string          `json:"attempt_id"`
	Credential json.RawMessage `json:"credential"`
}

type passkeyListResponse struct {
	Items []authentication.PasskeyView `json:"items"`
}

func WithPasskeys(
	base http.Handler,
	applications ApplicationResolver,
	origins OriginPolicy,
	sessions SessionManagementService,
	passkeys PasskeyApplicationService,
	completion PasskeyAuthenticationCompletion,
) http.Handler {
	return &passkeyHTTP{
		base:         base,
		applications: applications,
		origins:      origins,
		sessions:     sessions,
		passkeys:     passkeys,
		completion:   completion,
	}
}

func (h *passkeyHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v1/passkeys") {
		h.base.ServeHTTP(w, r)
		return
	}
	h.serve(w, r)
}

func (h *passkeyHTTP) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, err := correlationForRequest(r)
	if err != nil {
		w.Header().Set(RequestIDHeader, "request_unavailable")
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Passkey authentication is temporarily unavailable.", "request_unavailable")
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
	app, origin, ok := h.applicationOrigin(w, r, requestID)
	if !ok {
		return
	}

	switch {
	case r.URL.Path == "/v1/passkeys/authentication/attempts" && r.Method == http.MethodPost:
		h.handleAuthenticationBegin(w, r, requestID, app, origin)
	case r.URL.Path == "/v1/passkeys/authentication/complete" && r.Method == http.MethodPost:
		h.handleAuthenticationComplete(w, r, requestID, correlationID, app, origin)
	case r.URL.Path == "/v1/passkeys/registration/attempts" && r.Method == http.MethodPost:
		h.handleRegistrationBegin(w, r, requestID, app, origin)
	case r.URL.Path == "/v1/passkeys/registration/complete" && r.Method == http.MethodPost:
		h.handleRegistrationComplete(w, r, requestID, correlationID, app, origin)
	case r.URL.Path == "/v1/passkeys" && r.Method == http.MethodGet:
		h.handleList(w, r, requestID, app)
	case strings.HasPrefix(r.URL.Path, "/v1/passkeys/") && r.Method == http.MethodDelete:
		h.handleRemove(w, r, requestID, correlationID, app)
	default:
		methodNotAllowed(w, requestID)
	}
}

func (h *passkeyHTTP) handleAuthenticationBegin(w http.ResponseWriter, r *http.Request, requestID string, app applicationinstance.Instance, origin string) {
	if h.passkeys == nil {
		h.unavailable(w, requestID)
		return
	}
	result, err := h.passkeys.BeginAuthentication(r.Context(), app, origin)
	if err != nil {
		h.writePasskeyError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *passkeyHTTP) handleAuthenticationComplete(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, app applicationinstance.Instance, origin string) {
	if h.completion == nil {
		h.unavailable(w, requestID)
		return
	}
	var input passkeyAuthenticationCompleteRequest
	if decodeJSON(w, r, &input) != nil || !authentication.ValidPasskeyAttemptPublicID(input.AttemptID) || len(input.Credential) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "The passkey authentication request is invalid.", requestID)
		return
	}
	pair, err := h.completion.CompleteAuthentication(r.Context(), app, origin, input.AttemptID, input.Credential, correlationID)
	if err != nil {
		h.writePasskeyError(w, requestID, err)
		return
	}
	writeAuthenticationTokenPair(w, r, pair, app.PublicID)
}

func (h *passkeyHTTP) handleRegistrationBegin(w http.ResponseWriter, r *http.Request, requestID string, app applicationinstance.Instance, origin string) {
	current, ok := h.current(w, r, requestID, app)
	if !ok {
		return
	}
	if h.passkeys == nil {
		h.unavailable(w, requestID)
		return
	}
	result, err := h.passkeys.BeginRegistration(r.Context(), current, origin)
	if err != nil {
		h.writePasskeyError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *passkeyHTTP) handleRegistrationComplete(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, app applicationinstance.Instance, origin string) {
	current, ok := h.current(w, r, requestID, app)
	if !ok {
		return
	}
	if h.passkeys == nil {
		h.unavailable(w, requestID)
		return
	}
	var input passkeyRegistrationCompleteRequest
	if decodeJSON(w, r, &input) != nil || !authentication.ValidPasskeyAttemptPublicID(input.AttemptID) || len(input.Credential) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "The passkey registration request is invalid.", requestID)
		return
	}
	view, err := h.passkeys.FinishRegistration(r.Context(), current, origin, input.AttemptID, input.Name, input.Credential, correlationID)
	if err != nil {
		h.writePasskeyError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (h *passkeyHTTP) handleList(w http.ResponseWriter, r *http.Request, requestID string, app applicationinstance.Instance) {
	current, ok := h.current(w, r, requestID, app)
	if !ok {
		return
	}
	if h.passkeys == nil {
		h.unavailable(w, requestID)
		return
	}
	items, err := h.passkeys.List(r.Context(), current)
	if err != nil {
		h.writePasskeyError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, passkeyListResponse{Items: items})
}

func (h *passkeyHTTP) handleRemove(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, app applicationinstance.Instance) {
	publicID := strings.TrimPrefix(r.URL.Path, "/v1/passkeys/")
	if strings.Contains(publicID, "/") || !authentication.ValidPasskeyPublicID(publicID) {
		writeError(w, http.StatusBadRequest, "invalid_request", "The passkey resource identifier is invalid.", requestID)
		return
	}
	current, ok := h.current(w, r, requestID, app)
	if !ok {
		return
	}
	if h.passkeys == nil {
		h.unavailable(w, requestID)
		return
	}
	if err := h.passkeys.Remove(r.Context(), current, publicID, correlationID); err != nil {
		h.writePasskeyError(w, requestID, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *passkeyHTTP) applicationOrigin(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, string, bool) {
	if h.applications == nil || h.origins == nil {
		h.unavailable(w, requestID)
		return applicationinstance.Instance{}, "", false
	}
	keys := r.Header.Values(PublishableKeyHeader)
	if len(keys) != 1 || keys[0] == "" {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	app, err := h.applications.ResolvePublishable(r.Context(), keys[0])
	if err != nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] == "" {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	canonical, err := applicationinstance.CanonicalizeOrigin(origins[0])
	if err != nil || canonical != origins[0] {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	allowed, err := h.origins.IsAllowedOrigin(r.Context(), app.InternalID, canonical)
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	setCORSHeaders(w, canonical)
	return app, canonical, true
}

func (h *passkeyHTTP) current(w http.ResponseWriter, r *http.Request, requestID string, app applicationinstance.Instance) (authentication.PasskeySession, bool) {
	if h.sessions == nil {
		h.unavailable(w, requestID)
		return authentication.PasskeySession{}, false
	}
	token, ok := bearerToken(r.Header.Values("Authorization"))
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return authentication.PasskeySession{}, false
	}
	record, err := h.sessions.Current(r.Context(), app.InternalID, string(app.PublicID), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return authentication.PasskeySession{}, false
	}
	return authentication.PasskeySession{
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

func (h *passkeyHTTP) writePasskeyError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, authentication.ErrPasskeyInvalidRequest):
		writeError(w, http.StatusBadRequest, "invalid_request", "The passkey request is invalid.", requestID)
	case errors.Is(err, authentication.ErrPasskeyInvalidSession):
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
	case errors.Is(err, authentication.ErrPasskeyReverificationRequired):
		writeError(w, http.StatusForbidden, "reverification_required", "Recent authentication is required for this passkey operation.", requestID)
	case errors.Is(err, authentication.ErrPasskeyInvalidAttempt), errors.Is(err, authentication.ErrPasskeyProof):
		writeError(w, http.StatusUnauthorized, "invalid_passkey_proof", "The passkey proof is invalid or expired.", requestID)
	case errors.Is(err, authentication.ErrLastAuthenticationMethod):
		writeError(w, http.StatusConflict, "last_authentication_method", "At least one usable authentication method must remain.", requestID)
	default:
		h.unavailable(w, requestID)
	}
}

func (h *passkeyHTTP) unavailable(w http.ResponseWriter, requestID string) {
	writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Passkey authentication is temporarily unavailable.", requestID)
}

func (h *passkeyHTTP) preflight(w http.ResponseWriter, r *http.Request, requestID string) {
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
