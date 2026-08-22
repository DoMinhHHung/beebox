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

type EmailLinkIssueService interface {
	RequestWithCorrelation(context.Context, applicationinstance.Instance, string, string, string, audit.CorrelationID) error
}

type EmailLinkConfirmService interface {
	Confirm(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.EmailLinkConfirmResult, error)
}

type emailLinkHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	issuer       EmailLinkIssueService
	confirmer    EmailLinkConfirmService
}

type emailLinkIssueRequest struct {
	Email         string `json:"email"`
	CompletionURL string `json:"completion_url"`
}

type emailLinkConfirmRequest struct {
	ChallengeID string `json:"challenge_id"`
	Secret      string `json:"secret"`
}

func WithEmailLinks(base http.Handler, applications ApplicationResolver, origins OriginPolicy, issuer EmailLinkIssueService, confirmer EmailLinkConfirmService) http.Handler {
	return &emailLinkHTTP{base: base, applications: applications, origins: origins, issuer: issuer, confirmer: confirmer}
}

func (h *emailLinkHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/sign-ins/email-link", "/v1/sign-ins/email-link/confirm":
		h.withEmailLinkSecurityContext(w, r)
	default:
		h.base.ServeHTTP(w, r)
	}
}

func (h *emailLinkHTTP) withEmailLinkSecurityContext(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, err := correlationForRequest(r)
	if err != nil {
		w.Header().Set(RequestIDHeader, "request_unavailable")
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", "request_unavailable")
		return
	}
	requestID := hex.EncodeToString(correlationID[:])
	w.Header().Set(RequestIDHeader, requestID)
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	if r.Method == http.MethodOptions {
		h.handleEmailLinkPreflight(w, r, requestID)
		return
	}
	if r.URL.Path == "/v1/sign-ins/email-link" {
		h.handleEmailLinkIssue(w, r, requestID, correlationID)
		return
	}
	h.handleEmailLinkConfirm(w, r, requestID, correlationID)
}

func (h *emailLinkHTTP) handleEmailLinkIssue(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, publishableKey, ok := h.authorizeEmailLinkApplication(w, r, requestID)
	if !ok {
		return
	}
	var input emailLinkIssueRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if h.issuer == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	err := h.issuer.RequestWithCorrelation(r.Context(), app, publishableKey, input.Email, input.CompletionURL, correlationID)
	switch {
	case errors.Is(err, identity.ErrInvalidEmail), errors.Is(err, authentication.ErrEmailLinkInvalidDestination):
		writeError(w, http.StatusUnprocessableEntity, "invalid_input", "The supplied input is invalid.", requestID)
		return
	case err == nil, errors.Is(err, authentication.ErrEmailLinkDelivery), errors.Is(err, authentication.ErrEmailLinkInvalid), errors.Is(err, authentication.ErrEmailLinkRateLimited):
		writeJSON(w, http.StatusAccepted, statusEnvelope{Status: "accepted"})
		return
	default:
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
	}
}

func (h *emailLinkHTTP) handleEmailLinkConfirm(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, _, ok := h.authorizeEmailLinkApplication(w, r, requestID)
	if !ok {
		return
	}
	var input emailLinkConfirmRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if h.confirmer == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	result, err := h.confirmer.Confirm(r.Context(), app.InternalID, input.ChallengeID, input.Secret, correlationID)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
		case errors.Is(err, session.ErrSignInRateLimited):
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests were received.", requestID)
		default:
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		}
		return
	}
	writeAuthenticationTokenPair(w, r, result.TokenPair, app.PublicID)
}

func (h *emailLinkHTTP) authorizeEmailLinkApplication(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, string, bool) {
	if h.applications == nil || h.origins == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
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
	origin := r.Header.Get("Origin")
	if origin != "" {
		allowed, err := h.origins.IsAllowedOrigin(r.Context(), app.InternalID, origin)
		if err != nil || !allowed {
			writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
			return applicationinstance.Instance{}, "", false
		}
		setCORSHeaders(w, origin)
	}
	return app, values[0], true
}

func (h *emailLinkHTTP) handleEmailLinkPreflight(w http.ResponseWriter, r *http.Request, requestID string) {
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
	if r.Header.Get("Access-Control-Request-Method") != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	setCORSHeaders(w, origin)
	w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-BeeBox-Publishable-Key")
	w.Header().Set("Access-Control-Max-Age", "300")
	w.WriteHeader(http.StatusNoContent)
}
