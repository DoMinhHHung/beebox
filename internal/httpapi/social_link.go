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
)

type SocialLinkService interface {
	CreateLinkAttempt(context.Context, applicationinstance.Instance, authentication.SocialLinkSession, authentication.Provider, string) (authentication.SocialLinkResult, error)
	CompleteLinkCallback(context.Context, authentication.Provider, string, string, bool, audit.CorrelationID) (authentication.SocialLinkCallbackResult, error)
}

type socialLinkHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	sessions     SessionManagementService
	links        SocialLinkService
}

type socialLinkAttemptRequest struct {
	Provider    authentication.Provider `json:"provider"`
	RedirectURL string                  `json:"redirect_url"`
}

type socialLinkAttemptResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	ExpiresIn        int64  `json:"expires_in"`
}

func WithSocialLinks(base http.Handler, applications ApplicationResolver, origins OriginPolicy, sessions SessionManagementService, links SocialLinkService) http.Handler {
	return &socialLinkHTTP{base: base, applications: applications, origins: origins, sessions: sessions, links: links}
}

func (h *socialLinkHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/social-links/attempts" || h.isLinkCallback(r) {
		h.withSocialLinkSecurityContext(w, r)
		return
	}
	h.base.ServeHTTP(w, r)
}

func (h *socialLinkHTTP) isLinkCallback(r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/v1/social-auth/callback/") {
		return false
	}
	states := r.URL.Query()["state"]
	return len(states) == 1 && authentication.ValidSocialLinkStateWire(states[0])
}

func (h *socialLinkHTTP) withSocialLinkSecurityContext(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		w.Header().Set(RequestIDHeader, "request_unavailable")
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social linking is temporarily unavailable.", "request_unavailable")
		return
	}
	requestID := hex.EncodeToString(correlationID[:])
	w.Header().Set(RequestIDHeader, requestID)
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	if r.Method == http.MethodOptions {
		if r.URL.Path == "/v1/social-links/attempts" {
			h.handleSocialLinkPreflight(w, r, requestID)
			return
		}
		methodNotAllowed(w, requestID)
		return
	}
	if r.URL.Path == "/v1/social-links/attempts" {
		h.handleSocialLinkAttempt(w, r, requestID)
		return
	}
	h.handleSocialLinkCallback(w, r, requestID, correlationID)
}

func (h *socialLinkHTTP) handleSocialLinkAttempt(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, origin, ok := h.authorizeSocialLinkBrowser(w, r, requestID)
	if !ok {
		return
	}
	accessToken, ok := bearerToken(r.Header.Values("Authorization"))
	if !ok || h.sessions == nil {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return
	}
	current, err := h.sessions.Current(r.Context(), app.InternalID, string(app.PublicID), accessToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return
	}
	var input socialLinkAttemptRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	redirectOrigin, err := applicationinstance.RedirectOrigin(input.RedirectURL)
	if err != nil || redirectOrigin != origin {
		writeError(w, http.StatusUnprocessableEntity, "invalid_redirect", "The redirect URL is invalid or not allowed.", requestID)
		return
	}
	if h.links == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social linking is temporarily unavailable.", requestID)
		return
	}
	result, err := h.links.CreateLinkAttempt(r.Context(), app, authentication.SocialLinkSession{
		ApplicationInstanceID: current.ApplicationInstanceID,
		UserID:                current.UserInternalID,
		PublicID:              current.PublicID,
		CreatedAt:             current.CreatedAt,
		IdleExpiresAt:         current.IdleExpiresAt,
		ExpiresAt:             current.ExpiresAt,
		Revoked:               current.RevokedAt != nil,
	}, input.Provider, input.RedirectURL)
	if err != nil {
		switch {
		case errors.Is(err, authentication.ErrSocialUnsupportedProvider):
			writeError(w, http.StatusUnprocessableEntity, "unsupported_provider", "The social provider is not available for this application.", requestID)
		case errors.Is(err, authentication.ErrSocialLinkInvalidRedirect), errors.Is(err, authentication.ErrSocialLinkInvalidRequest):
			writeError(w, http.StatusUnprocessableEntity, "invalid_redirect", "The redirect URL is invalid or not allowed.", requestID)
		case errors.Is(err, authentication.ErrSocialLinkReverificationRequired):
			writeError(w, http.StatusForbidden, "reverification_required", "Recent authentication is required before linking a social account.", requestID)
		case errors.Is(err, authentication.ErrSocialLinkInvalidSession):
			writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		case errors.Is(err, authentication.ErrSocialLinkRateLimited):
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests were received.", requestID)
		default:
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social linking is temporarily unavailable.", requestID)
		}
		return
	}
	writeJSON(w, http.StatusCreated, socialLinkAttemptResponse{AuthorizationURL: result.AuthorizationURL, ExpiresIn: result.ExpiresIn})
}

func (h *socialLinkHTTP) handleSocialLinkCallback(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, requestID)
		return
	}
	providerText := strings.TrimPrefix(r.URL.Path, "/v1/social-auth/callback/")
	if providerText == "" || strings.Contains(providerText, "/") {
		writeError(w, http.StatusBadRequest, "invalid_social_state", "The social callback state is invalid.", requestID)
		return
	}
	provider := authentication.Provider(providerText)
	if !provider.Valid() || h.links == nil {
		writeError(w, http.StatusBadRequest, "invalid_social_state", "The social callback state is invalid.", requestID)
		return
	}
	query := r.URL.Query()
	states := query["state"]
	if len(states) != 1 || !authentication.ValidSocialLinkStateWire(states[0]) {
		writeError(w, http.StatusBadRequest, "invalid_social_state", "The social callback state is invalid.", requestID)
		return
	}
	codes := query["code"]
	providerCode := ""
	if len(codes) == 1 {
		providerCode = codes[0]
	} else if len(codes) > 1 {
		writeError(w, http.StatusBadRequest, "invalid_social_state", "The social callback state is invalid.", requestID)
		return
	}
	result, err := h.links.CompleteLinkCallback(r.Context(), provider, states[0], providerCode, len(query["error"]) > 0, correlationID)
	if err != nil {
		if errors.Is(err, authentication.ErrSocialLinkInvalidState) {
			writeError(w, http.StatusBadRequest, "invalid_social_state", "The social callback state is invalid.", requestID)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social linking is temporarily unavailable.", requestID)
		return
	}
	redirect, err := url.Parse(result.RedirectURL)
	if err != nil || redirect.RawQuery != "" || redirect.Fragment != "" {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social linking is temporarily unavailable.", requestID)
		return
	}
	queryValues := redirect.Query()
	if result.Failed {
		queryValues.Set("beebox_error", "social_link_failed")
	} else {
		queryValues.Set("beebox_link", "success")
	}
	redirect.RawQuery = queryValues.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

func (h *socialLinkHTTP) authorizeSocialLinkBrowser(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, string, bool) {
	if h.applications == nil || h.origins == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social linking is temporarily unavailable.", requestID)
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

func (h *socialLinkHTTP) handleSocialLinkPreflight(w http.ResponseWriter, r *http.Request, requestID string) {
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
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-BeeBox-Publishable-Key")
	w.Header().Set("Access-Control-Max-Age", "300")
	w.WriteHeader(http.StatusNoContent)
}
