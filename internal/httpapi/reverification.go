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
	"github.com/DoMinhHHung/beebox/internal/session"
)

const ReverificationHeader = "X-BeeBox-Reverification"

type ReverificationApplicationService interface {
	Mint(context.Context, authentication.ReverificationSessionEvidence, authentication.ReverificationSessionEvidence, string, audit.CorrelationID) (authentication.ReverificationGrant, error)
	Consume(context.Context, authentication.ReverificationSessionEvidence, string, string, audit.CorrelationID) (context.Context, error)
}

type reverificationHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	sessions     SessionManagementService
	service      ReverificationApplicationService
}

type reverificationRequest struct {
	Purpose          string `json:"purpose"`
	ProofAccessToken string `json:"proof_access_token"`
}

func WithReverification(base http.Handler, applications ApplicationResolver, origins OriginPolicy, sessions SessionManagementService, service ReverificationApplicationService) http.Handler {
	return &reverificationHTTP{base: base, applications: applications, origins: origins, sessions: sessions, service: service}
}

func (h *reverificationHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		requestedMethod := r.Header.Get("Access-Control-Request-Method")
		if r.URL.Path == "/v1/reverifications" || requiredReverificationPurposeFor(requestedMethod, r.URL.Path) != "" {
			h.preflight(w, r)
			return
		}
		h.base.ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/v1/reverifications" {
		h.mint(w, r)
		return
	}
	purpose := requiredReverificationPurpose(r)
	if purpose == "" {
		h.base.ServeHTTP(w, r)
		return
	}
	h.authorizeMutation(w, r, purpose)
}

func (h *reverificationHTTP) mint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, requestID, ok := newReverificationRequestID(w)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	app, current, ok := h.current(w, r, requestID)
	if !ok {
		return
	}
	var input reverificationRequest
	if decodeJSON(w, r, &input) != nil || !authentication.ValidReverificationPurpose(input.Purpose) || input.ProofAccessToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "The reverification request is invalid.", requestID)
		return
	}
	if h.service == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Reverification is temporarily unavailable.", requestID)
		return
	}
	proof, err := h.sessions.Current(r.Context(), app.InternalID, string(app.PublicID), input.ProofAccessToken)
	if err != nil {
		writeError(w, http.StatusForbidden, "reverification_failed", "The reverification proof is invalid.", requestID)
		return
	}
	grant, err := h.service.Mint(r.Context(), reverificationEvidence(current), reverificationEvidence(proof), input.Purpose, correlationID)
	if err != nil {
		h.writeReverificationError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusCreated, grant)
}

func (h *reverificationHTTP) authorizeMutation(w http.ResponseWriter, r *http.Request, purpose string) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, requestID, ok := newReverificationRequestID(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	_, current, ok := h.current(w, r, requestID)
	if !ok {
		return
	}
	if h.service == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Reverification is temporarily unavailable.", requestID)
		return
	}
	values := r.Header.Values(ReverificationHeader)
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		writeError(w, http.StatusForbidden, "reverification_required", "Recent reverification is required for this operation.", requestID)
		return
	}
	authorizedCtx, err := h.service.Consume(r.Context(), reverificationEvidence(current), purpose, strings.TrimSpace(values[0]), correlationID)
	if err != nil {
		h.writeReverificationError(w, requestID, err)
		return
	}
	h.base.ServeHTTP(w, r.WithContext(authorizedCtx))
}

func reverificationEvidence(record session.Record) authentication.ReverificationSessionEvidence {
	return authentication.ReverificationSessionEvidence{
		ApplicationInstanceID: record.ApplicationInstanceID,
		UserID:                record.UserInternalID,
		SessionPublicID:       record.PublicID,
		AuthenticatedAt:       record.CreatedAt.UTC(),
		IdleExpiresAt:         record.IdleExpiresAt.UTC(),
		ExpiresAt:             record.ExpiresAt.UTC(),
		Revoked:               record.RevokedAt != nil,
		MFAMethod:             record.MFAMethod,
	}
}

func (h *reverificationHTTP) current(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, session.Record, bool) {
	if h.applications == nil || h.origins == nil || h.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Reverification is temporarily unavailable.", requestID)
		return applicationinstance.Instance{}, session.Record{}, false
	}
	keys := r.Header.Values(PublishableKeyHeader)
	if len(keys) != 1 || keys[0] == "" {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, session.Record{}, false
	}
	app, err := h.applications.ResolvePublishable(r.Context(), keys[0])
	if err != nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return applicationinstance.Instance{}, session.Record{}, false
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] == "" {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, session.Record{}, false
	}
	canonical, err := applicationinstance.CanonicalizeOrigin(origins[0])
	if err != nil || canonical != origins[0] {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, session.Record{}, false
	}
	allowed, err := h.origins.IsAllowedOrigin(r.Context(), app.InternalID, canonical)
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, session.Record{}, false
	}
	setCORSHeaders(w, canonical)
	token, ok := bearerToken(r.Header.Values("Authorization"))
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return applicationinstance.Instance{}, session.Record{}, false
	}
	record, err := h.sessions.Current(r.Context(), app.InternalID, string(app.PublicID), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return applicationinstance.Instance{}, session.Record{}, false
	}
	return app, record, true
}

func (h *reverificationHTTP) writeReverificationError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, authentication.ErrReverificationExpired),
		errors.Is(err, authentication.ErrReverificationReplay),
		errors.Is(err, authentication.ErrReverificationRecovery),
		errors.Is(err, authentication.ErrReverificationInvalid):
		writeError(w, http.StatusForbidden, "reverification_failed", "The reverification proof is invalid or expired.", requestID)
	default:
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Reverification is temporarily unavailable.", requestID)
	}
}

func newReverificationRequestID(w http.ResponseWriter) (audit.CorrelationID, string, bool) {
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		w.Header().Set(RequestIDHeader, "request_unavailable")
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Reverification is temporarily unavailable.", "request_unavailable")
		return audit.CorrelationID{}, "", false
	}
	requestID := hex.EncodeToString(correlationID[:])
	w.Header().Set(RequestIDHeader, requestID)
	return correlationID, requestID, true
}

func (h *reverificationHTTP) preflight(w http.ResponseWriter, r *http.Request) {
	_, requestID, ok := newReverificationRequestID(w)
	if !ok {
		return
	}
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
	if r.URL.Path == "/v1/reverifications" {
		if method != http.MethodPost {
			methodNotAllowed(w, requestID)
			return
		}
	} else if requiredReverificationPurposeFor(method, r.URL.Path) == "" {
		methodNotAllowed(w, requestID)
		return
	}
	setCORSHeaders(w, canonical)
	w.Header().Set("Access-Control-Allow-Methods", method)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-BeeBox-Publishable-Key, "+ReverificationHeader)
	w.Header().Set("Access-Control-Max-Age", "300")
	w.WriteHeader(http.StatusNoContent)
}

func requiredReverificationPurpose(r *http.Request) string {
	return requiredReverificationPurposeFor(r.Method, r.URL.Path)
}

func requiredReverificationPurposeFor(method, path string) string {
	switch {
	case method == http.MethodPost && path == "/v1/mfa/totp/enrollments":
		return authentication.ReverificationPurposeTOTPEnroll
	case method == http.MethodDelete && path == "/v1/mfa/totp":
		return authentication.ReverificationPurposeTOTPRemove
	case method == http.MethodPost && path == "/v1/mfa/totp/replacements":
		return authentication.ReverificationPurposeTOTPReplace
	case method == http.MethodPost && path == "/v1/mfa/recovery-codes/regenerate":
		return authentication.ReverificationPurposeRecoveryRegenerate
	case method == http.MethodPost && path == "/v1/passkeys/registration/attempts":
		return authentication.ReverificationPurposePasskeyRegister
	case method == http.MethodDelete && strings.HasPrefix(path, "/v1/passkeys/"):
		return authentication.ReverificationPurposePasskeyRemove
	case method == http.MethodPost && path == "/v1/social-links/attempts":
		return authentication.ReverificationPurposeSocialLink
	case method == http.MethodDelete && strings.HasPrefix(path, "/v1/social-links/"):
		return authentication.ReverificationPurposeSocialUnlink
	case method == http.MethodPost && strings.HasPrefix(path, "/v1/sessions/") && strings.HasSuffix(path, "/revoke"):
		return authentication.ReverificationPurposeSessionRevoke
	case method == http.MethodPost && path == "/v1/sessions/revoke-others":
		return authentication.ReverificationPurposeSessionRevokeOthers
	case method == http.MethodPost && path == "/v1/sessions/sign-out-everywhere":
		return authentication.ReverificationPurposeSignOutEverywhere
	case method == http.MethodPost && (path == "/v1/identifiers/emails" || path == "/v1/identifiers/phones"):
		return authentication.ReverificationPurposeIdentifierAdd
	case method == http.MethodDelete && (strings.HasPrefix(path, "/v1/identifiers/emails/") || strings.HasPrefix(path, "/v1/identifiers/phones/")):
		return authentication.ReverificationPurposeIdentifierRemove
	case method == http.MethodPost && strings.HasSuffix(path, "/primary") && (strings.HasPrefix(path, "/v1/identifiers/emails/") || strings.HasPrefix(path, "/v1/identifiers/phones/")):
		return authentication.ReverificationPurposeIdentifierPrimary
	default:
		return ""
	}
}
