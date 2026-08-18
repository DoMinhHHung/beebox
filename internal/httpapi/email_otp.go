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
	"github.com/DoMinhHHung/beebox/internal/session"
)

type EmailOTPIssueService interface {
	RequestWithCorrelation(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) error
}

type EmailOTPConfirmService interface {
	Confirm(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error)
}

type emailOTPHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	issuer       EmailOTPIssueService
	confirmer    EmailOTPConfirmService
}

type emailOTPRequest struct {
	Email string `json:"email"`
}

type emailOTPConfirmRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func WithEmailOTP(base http.Handler, applications ApplicationResolver, origins OriginPolicy, issuer EmailOTPIssueService, confirmer EmailOTPConfirmService) http.Handler {
	return &emailOTPHTTP{base: base, applications: applications, origins: origins, issuer: issuer, confirmer: confirmer}
}

func (h *emailOTPHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/sign-ins/email-otp", "/v1/sign-ins/email-otp/confirm":
		h.withEmailOTPSecurityContext(w, r)
	default:
		h.base.ServeHTTP(w, r)
	}
}

func (h *emailOTPHTTP) withEmailOTPSecurityContext(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, err := audit.NewCorrelationID()
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
		h.handleEmailOTPPreflight(w, r, requestID)
		return
	}
	if r.URL.Path == "/v1/sign-ins/email-otp" {
		h.handleEmailOTPIssue(w, r, requestID, correlationID)
		return
	}
	h.handleEmailOTPConfirm(w, r, requestID, correlationID)
}

func (h *emailOTPHTTP) handleEmailOTPIssue(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.authorizeEmailOTPApplication(w, r, requestID)
	if !ok {
		return
	}
	var input emailOTPRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if h.issuer == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	err := h.issuer.RequestWithCorrelation(r.Context(), app.InternalID, input.Email, correlationID)
	if errors.Is(err, identity.ErrInvalidEmail) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_input", "The supplied input is invalid.", requestID)
		return
	}
	if err != nil && !errors.Is(err, authentication.ErrEmailOTPDelivery) && !errors.Is(err, authentication.ErrEmailOTPInvalid) && !errors.Is(err, authentication.ErrEmailOTPRateLimited) {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	// Eligible delivery, unknown/unverified state, cooldown/window suppression,
	// and account-dependent delivery failure intentionally converge here.
	writeJSON(w, http.StatusAccepted, statusEnvelope{Status: "accepted"})
}

func (h *emailOTPHTTP) handleEmailOTPConfirm(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.authorizeEmailOTPApplication(w, r, requestID)
	if !ok {
		return
	}
	var input emailOTPConfirmRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if h.confirmer == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	pair, err := h.confirmer.Confirm(r.Context(), app.InternalID, input.Email, input.Code, correlationID)
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
	writeEmailOTPTokenPair(w, r, pair, app.PublicID)
}

func (h *emailOTPHTTP) authorizeEmailOTPApplication(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, bool) {
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
	if err != nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
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

func (h *emailOTPHTTP) handleEmailOTPPreflight(w http.ResponseWriter, r *http.Request, requestID string) {
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

func writeEmailOTPTokenPair(w http.ResponseWriter, r *http.Request, pair session.TokenPair, appPublicID applicationinstance.PublicID) {
	response := tokenResponse{
		AccessToken: pair.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   pair.ExpiresIn,
		SessionID:   pair.SessionID,
	}
	if r.Header.Get("Origin") != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     refreshCookieName(appPublicID),
			Value:    pair.RefreshToken,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(session.AbsoluteLifetime / time.Second),
		})
	} else {
		response.RefreshToken = pair.RefreshToken
	}
	writeJSON(w, http.StatusOK, response)
}
