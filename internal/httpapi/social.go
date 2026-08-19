package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type SocialAttemptService interface {
	CreateAttempt(context.Context, applicationinstance.Instance, authentication.Provider, string, string, string) (authentication.SocialAttemptResult, error)
	CompleteCallback(context.Context, authentication.Provider, string, string, bool, audit.CorrelationID) (authentication.SocialCallbackResult, error)
}

type SocialExchangeService interface {
	Exchange(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error)
}

type socialHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	social       SocialAttemptService
	exchange     SocialExchangeService
}

type socialAttemptRequest struct {
	Provider            authentication.Provider `json:"provider"`
	RedirectURL         string                  `json:"redirect_url"`
	CodeChallenge       string                  `json:"code_challenge"`
	CodeChallengeMethod string                  `json:"code_challenge_method"`
}

type socialAttemptResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	ExpiresIn        int64  `json:"expires_in"`
}

type socialExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

func WithSocialAuth(base http.Handler, applications ApplicationResolver, origins OriginPolicy, social SocialAttemptService, exchange SocialExchangeService) http.Handler {
	return &socialHTTP{base: base, applications: applications, origins: origins, social: social, exchange: exchange}
}

func (h *socialHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/social-auth/attempts" || r.URL.Path == "/v1/social-auth/exchange" || strings.HasPrefix(r.URL.Path, "/v1/social-auth/callback/") {
		h.withSocialSecurityContext(w, r)
		return
	}
	h.base.ServeHTTP(w, r)
}

func (h *socialHTTP) withSocialSecurityContext(w http.ResponseWriter, r *http.Request) {
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
		if r.URL.Path == "/v1/social-auth/attempts" || r.URL.Path == "/v1/social-auth/exchange" {
			h.handleSocialPreflight(w, r, requestID)
			return
		}
		methodNotAllowed(w, requestID)
		return
	}
	switch {
	case r.URL.Path == "/v1/social-auth/attempts":
		h.handleSocialAttempt(w, r, requestID)
	case r.URL.Path == "/v1/social-auth/exchange":
		h.handleSocialExchange(w, r, requestID, correlationID)
	case strings.HasPrefix(r.URL.Path, "/v1/social-auth/callback/"):
		h.handleSocialCallback(w, r, requestID, correlationID)
	default:
		h.base.ServeHTTP(w, r)
	}
}

func (h *socialHTTP) handleSocialAttempt(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, origin, ok := h.authorizeSocialBrowser(w, r, requestID)
	if !ok {
		return
	}
	var input socialAttemptRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	redirectOrigin, err := applicationinstance.RedirectOrigin(input.RedirectURL)
	if err != nil || redirectOrigin != origin {
		writeError(w, http.StatusUnprocessableEntity, "invalid_redirect", "The redirect URL is invalid or not allowed.", requestID)
		return
	}
	if h.social == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is unavailable.", requestID)
		return
	}
	result, err := h.social.CreateAttempt(r.Context(), app, input.Provider, input.RedirectURL, input.CodeChallenge, input.CodeChallengeMethod)
	if err != nil {
		switch {
		case errors.Is(err, authentication.ErrSocialUnsupportedProvider):
			writeError(w, http.StatusUnprocessableEntity, "unsupported_provider", "The social provider is not available for this application.", requestID)
		case errors.Is(err, authentication.ErrSocialInvalidRequest):
			writeError(w, http.StatusUnprocessableEntity, "invalid_request", "The supplied social authentication request is invalid.", requestID)
		case errors.Is(err, authentication.ErrSocialRateLimited):
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests were received.", requestID)
		default:
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is temporarily unavailable.", requestID)
		}
		return
	}
	writeJSON(w, http.StatusCreated, socialAttemptResponse{AuthorizationURL: result.AuthorizationURL, ExpiresIn: result.ExpiresIn})
}

func (h *socialHTTP) handleSocialCallback(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, requestID)
		return
	}
	providerText := strings.TrimPrefix(r.URL.Path, "/v1/social-auth/callback/")
	if providerText == "" || strings.Contains(providerText, "/") {
		writeError(w, http.StatusBadRequest, "invalid_social_state", "The social authentication callback is invalid.", requestID)
		return
	}
	provider := authentication.Provider(providerText)
	if !provider.Valid() || h.social == nil {
		writeError(w, http.StatusBadRequest, "invalid_social_state", "The social authentication callback is invalid.", requestID)
		return
	}
	query := r.URL.Query()
	states := query["state"]
	if len(states) != 1 || states[0] == "" {
		writeError(w, http.StatusBadRequest, "invalid_social_state", "The social authentication callback is invalid.", requestID)
		return
	}
	codes := query["code"]
	providerCode := ""
	if len(codes) == 1 {
		providerCode = codes[0]
	} else if len(codes) > 1 {
		writeError(w, http.StatusBadRequest, "invalid_social_state", "The social authentication callback is invalid.", requestID)
		return
	}
	providerDenied := len(query["error"]) > 0
	result, err := h.social.CompleteCallback(r.Context(), provider, states[0], providerCode, providerDenied, correlationID)
	if err != nil {
		if errors.Is(err, authentication.ErrSocialInvalidState) {
			writeError(w, http.StatusBadRequest, "invalid_social_state", "The social authentication callback is invalid.", requestID)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is temporarily unavailable.", requestID)
		return
	}
	redirect, err := url.Parse(result.RedirectURL)
	if err != nil || redirect.RawQuery != "" || redirect.Fragment != "" {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is temporarily unavailable.", requestID)
		return
	}
	q := redirect.Query()
	if result.Failed {
		q.Set("beebox_error", "social_auth_failed")
	} else if result.CompletionCode != "" {
		q.Set("beebox_code", result.CompletionCode)
	} else {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is temporarily unavailable.", requestID)
		return
	}
	redirect.RawQuery = q.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

func (h *socialHTTP) handleSocialExchange(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, _, ok := h.authorizeSocialBrowser(w, r, requestID)
	if !ok {
		return
	}
	var input socialExchangeRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if h.exchange == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is unavailable.", requestID)
		return
	}
	pair, err := h.exchange.Exchange(r.Context(), app.InternalID, input.Code, input.CodeVerifier, correlationID)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_social_completion", "The social completion credential is invalid.", requestID)
		case errors.Is(err, session.ErrSignInRateLimited):
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests were received.", requestID)
		default:
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is temporarily unavailable.", requestID)
		}
		return
	}
	writePhoneTokenPair(w, r, pair, app.PublicID)
}

func (h *socialHTTP) authorizeSocialBrowser(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, string, bool) {
	if h.applications == nil || h.origins == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is unavailable.", requestID)
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
	canonicalOrigin, err := applicationinstance.CanonicalizeOrigin(origins[0])
	if err != nil || canonicalOrigin != origins[0] {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	allowed, err := h.origins.IsAllowedOrigin(r.Context(), app.InternalID, canonicalOrigin)
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return applicationinstance.Instance{}, "", false
	}
	setCORSHeaders(w, canonicalOrigin)
	return app, canonicalOrigin, true
}

func (h *socialHTTP) handleSocialPreflight(w http.ResponseWriter, r *http.Request, requestID string) {
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
	if r.Header.Get("Access-Control-Request-Method") != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	setCORSHeaders(w, canonical)
	w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-BeeBox-Publishable-Key")
	w.Header().Set("Access-Control-Max-Age", "300")
	w.WriteHeader(http.StatusNoContent)
}
