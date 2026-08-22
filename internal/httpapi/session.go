package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/session"
)

const refreshCookiePrefix = "__Host-beebox-refresh-"

type SessionService interface {
	SignIn(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error)
	Refresh(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) (session.TokenPair, error)
}

type sessionHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	sessions     SessionService
	ring         *session.KeyRing
}

type signInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type authenticationSessionResponse struct {
	ID string `json:"id"`
}

type tokenResponse struct {
	Status           string                         `json:"status"`
	Session          *authenticationSessionResponse `json:"session,omitempty"`
	AccessToken      string                         `json:"access_token,omitempty"`
	TokenType        string                         `json:"token_type,omitempty"`
	ExpiresIn        int64                          `json:"expires_in,omitempty"`
	SessionID        string                         `json:"session_id,omitempty"`
	RefreshToken     string                         `json:"refresh_token,omitempty"`
	PendingMFAToken  string                         `json:"pending_mfa_token,omitempty"`
	ExpiresAt        *time.Time                     `json:"expires_at,omitempty"`
	AvailableMethods []string                       `json:"available_methods,omitempty"`
}

func WithSessions(base http.Handler, applications ApplicationResolver, origins OriginPolicy, sessions SessionService, ring *session.KeyRing) http.Handler {
	return &sessionHTTP{base: base, applications: applications, origins: origins, sessions: sessions, ring: ring}
}

func (h *sessionHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/jwks.json":
		h.handleJWKS(w, r)
	case "/v1/sign-ins":
		if r.Method == http.MethodOptions {
			h.withSecurityContext(w, r, h.handleSessionPreflight)
			return
		}
		h.withSecurityContext(w, r, h.handleSignIn)
	case "/v1/sessions/refresh":
		if r.Method == http.MethodOptions {
			h.withSecurityContext(w, r, h.handleSessionPreflight)
			return
		}
		h.withSecurityContext(w, r, h.handleRefresh)
	default:
		h.base.ServeHTTP(w, r)
	}
}

func (h *sessionHTTP) withSecurityContext(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request, string, audit.CorrelationID)) {
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
	next(w, r.WithContext(ctx), requestID, correlationID)
}

func (h *sessionHTTP) handleSignIn(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.resolveApplication(w, r, requestID)
	if !ok || !h.validateOrigin(w, r, requestID, app.InternalID, false) {
		return
	}
	var input signInRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if h.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	pair, err := h.sessions.SignIn(r.Context(), app.InternalID, input.Email, input.Password, correlationID)
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

func (h *sessionHTTP) handleRefresh(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.resolveApplication(w, r, requestID)
	if !ok {
		return
	}
	cookieName := refreshCookieName(app.PublicID)
	cookie, cookieErr := r.Cookie(cookieName)
	cookieMode := cookieErr == nil && cookie.Value != ""
	if !h.validateOrigin(w, r, requestID, app.InternalID, cookieMode) {
		return
	}

	var refresh string
	if cookieMode {
		refresh = cookie.Value
	} else {
		var input refreshRequest
		if decodeJSON(w, r, &input) != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
			return
		}
		refresh = input.RefreshToken
	}
	if h.sessions == nil || refresh == "" {
		writeError(w, http.StatusUnauthorized, "invalid_refresh", "The refresh credential is invalid.", requestID)
		return
	}
	pair, err := h.sessions.Refresh(r.Context(), app.InternalID, refresh, correlationID)
	if err != nil {
		if errors.Is(err, session.ErrRefreshInvalid) || errors.Is(err, session.ErrRefreshReused) {
			clearRefreshCookie(w, cookieName)
			writeError(w, http.StatusUnauthorized, "invalid_refresh", "The refresh credential is invalid.", requestID)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	writeAuthenticationTokenPair(w, r, pair, app.PublicID)
}

func (h *sessionHTTP) resolveApplication(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, bool) {
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
	return app, true
}

func (h *sessionHTTP) validateOrigin(w http.ResponseWriter, r *http.Request, requestID string, appID applicationinstance.InternalID, requireOrigin bool) bool {
	origin := r.Header.Get("Origin")
	if requireOrigin && origin == "" {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return false
	}
	if origin == "" {
		return true
	}
	allowed, err := h.origins.IsAllowedOrigin(r.Context(), appID, origin)
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return false
	}
	setCORSHeaders(w, origin)
	return true
}

func (h *sessionHTTP) handleSessionPreflight(w http.ResponseWriter, r *http.Request, requestID string, _ audit.CorrelationID) {
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

func writeAuthenticationTokenPair(w http.ResponseWriter, r *http.Request, pair session.TokenPair, appPublicID applicationinstance.PublicID) {
	if pair.PendingMFA != nil {
		expiresAt := pair.PendingMFA.ExpiresAt.UTC()
		writeJSON(w, http.StatusOK, tokenResponse{
			Status:           "mfa_required",
			PendingMFAToken:  pair.PendingMFA.Token,
			ExpiresAt:        &expiresAt,
			AvailableMethods: append([]string(nil), pair.PendingMFA.AvailableMethods...),
		})
		return
	}
	response := tokenResponse{
		Status:      "authenticated",
		Session:     &authenticationSessionResponse{ID: pair.SessionID},
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

func (h *sessionHTTP) writeTokenPair(w http.ResponseWriter, r *http.Request, pair session.TokenPair, appPublicID applicationinstance.PublicID) {
	writeAuthenticationTokenPair(w, r, pair, appPublicID)
}

func (h *sessionHTTP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.ring == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, h.ring.JWKS())
}

func refreshCookieName(appPublicID applicationinstance.PublicID) string {
	return refreshCookiePrefix + string(appPublicID)
}

func clearRefreshCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
