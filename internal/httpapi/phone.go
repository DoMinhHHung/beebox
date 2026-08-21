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

type PhoneIssueService interface {
	RequestWithCorrelation(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) error
}

type PhoneConfirmService interface {
	Confirm(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error)
}

type phoneHTTP struct {
	base            http.Handler
	applications    ApplicationResolver
	origins         OriginPolicy
	signupIssuer    PhoneIssueService
	signupConfirmer PhoneConfirmService
	signinIssuer    PhoneIssueService
	signinConfirmer PhoneConfirmService
}

type phoneRequest struct {
	Phone string `json:"phone"`
}

type phoneConfirmRequest struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

func WithPhoneSMS(base http.Handler, applications ApplicationResolver, origins OriginPolicy, signupIssuer PhoneIssueService, signupConfirmer PhoneConfirmService, signinIssuer PhoneIssueService, signinConfirmer PhoneConfirmService) http.Handler {
	return &phoneHTTP{
		base: base, applications: applications, origins: origins,
		signupIssuer: signupIssuer, signupConfirmer: signupConfirmer,
		signinIssuer: signinIssuer, signinConfirmer: signinConfirmer,
	}
}

func (h *phoneHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/sign-ups/phone", "/v1/sign-ups/phone/confirm", "/v1/sign-ins/phone-otp", "/v1/sign-ins/phone-otp/confirm":
		h.withPhoneSecurityContext(w, r)
	default:
		h.base.ServeHTTP(w, r)
	}
}

func (h *phoneHTTP) withPhoneSecurityContext(w http.ResponseWriter, r *http.Request) {
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
		h.handlePhonePreflight(w, r, requestID)
		return
	}
	switch r.URL.Path {
	case "/v1/sign-ups/phone":
		h.handlePhoneIssue(w, r, requestID, correlationID, h.signupIssuer)
	case "/v1/sign-ups/phone/confirm":
		h.handlePhoneConfirm(w, r, requestID, correlationID, h.signupConfirmer)
	case "/v1/sign-ins/phone-otp":
		h.handlePhoneIssue(w, r, requestID, correlationID, h.signinIssuer)
	case "/v1/sign-ins/phone-otp/confirm":
		h.handlePhoneConfirm(w, r, requestID, correlationID, h.signinConfirmer)
	}
}

func (h *phoneHTTP) handlePhoneIssue(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, issuer PhoneIssueService) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.authorizePhoneApplication(w, r, requestID)
	if !ok {
		return
	}
	var input phoneRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if issuer == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "SMS authentication is unavailable.", requestID)
		return
	}
	err := issuer.RequestWithCorrelation(r.Context(), app.InternalID, input.Phone, correlationID)
	if errors.Is(err, identity.ErrInvalidPhone) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_input", "The supplied input is invalid.", requestID)
		return
	}
	if err != nil && !errors.Is(err, authentication.ErrPhoneSignupDelivery) && !errors.Is(err, authentication.ErrPhoneOTPDelivery) && !errors.Is(err, authentication.ErrPhoneSignupInvalid) && !errors.Is(err, authentication.ErrPhoneOTPInvalid) && !errors.Is(err, authentication.ErrPhoneSignupRateLimited) && !errors.Is(err, authentication.ErrPhoneOTPRateLimited) {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	writeJSON(w, http.StatusAccepted, statusEnvelope{Status: "accepted"})
}

func (h *phoneHTTP) handlePhoneConfirm(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, confirmer PhoneConfirmService) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.authorizePhoneApplication(w, r, requestID)
	if !ok {
		return
	}
	var input phoneConfirmRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if confirmer == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	pair, err := confirmer.Confirm(r.Context(), app.InternalID, input.Phone, input.Code, correlationID)
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
	writeAuthenticationTokenPair(w, r, pair, app.PublicID)
}

func (h *phoneHTTP) authorizePhoneApplication(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, bool) {
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

func (h *phoneHTTP) handlePhonePreflight(w http.ResponseWriter, r *http.Request, requestID string) {
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

func writePhoneTokenPair(w http.ResponseWriter, r *http.Request, pair session.TokenPair, appPublicID applicationinstance.PublicID) {
	writeAuthenticationTokenPair(w, r, pair, appPublicID)
}
