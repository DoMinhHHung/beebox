package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/session"
)

const refreshCookieName = "__Host-beebox-refresh"

type SessionService interface {
	SignIn(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error)
	Refresh(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) (session.TokenPair, error)
}

type sessionHTTP struct {
	base http.Handler
	applications ApplicationResolver
	origins OriginPolicy
	sessions SessionService
	ring *session.KeyRing
}

type signInRequest struct {
	Email string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int64 `json:"expires_in"`
	SessionID string `json:"session_id"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func WithSessions(base http.Handler, applications ApplicationResolver, origins OriginPolicy, sessions SessionService, ring *session.KeyRing) http.Handler {
	return &sessionHTTP{base: base, applications: applications, origins: origins, sessions: sessions, ring: ring}
}

func (h *sessionHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/jwks.json":
		h.handleJWKS(w, r)
	case "/v1/sign-ins":
		h.withSecurityContext(w, r, h.handleSignIn)
	case "/v1/sessions/refresh":
		h.withSecurityContext(w, r, h.handleRefresh)
	default:
		h.base.ServeHTTP(w, r)
	}
}

func (h *sessionHTTP) withSecurityContext(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request, string, audit.CorrelationID)) {
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
	next(w, r.WithContext(ctx), requestID, correlationID)
}

func (h *sessionHTTP) handleSignIn(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost { methodNotAllowed(w, requestID); return }
	app, ok := h.authorizeApplication(w, r, requestID, false)
	if !ok { return }
	var input signInRequest
	if decodeJSON(w, r, &input) != nil { writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID); return }
	if h.sessions == nil { writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID); return }
	pair, err := h.sessions.SignIn(r.Context(), app.InternalID, input.Email, input.Password, correlationID)
	if err != nil {
		if errors.Is(err, session.ErrInvalidCredentials) { writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID); return }
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID); return
	}
	h.writeTokenPair(w, r, pair)
}

func (h *sessionHTTP) handleRefresh(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost { methodNotAllowed(w, requestID); return }
	cookie, cookieErr := r.Cookie(refreshCookieName)
	cookieMode := cookieErr == nil && cookie.Value != ""
	app, ok := h.authorizeApplication(w, r, requestID, cookieMode)
	if !ok { return }
	var refresh string
	if cookieMode {
		refresh = cookie.Value
	} else {
		var input refreshRequest
		if decodeJSON(w, r, &input) != nil { writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID); return }
		refresh = input.RefreshToken
	}
	if h.sessions == nil || refresh == "" { writeError(w, http.StatusUnauthorized, "invalid_refresh", "The refresh credential is invalid.", requestID); return }
	pair, err := h.sessions.Refresh(r.Context(), app.InternalID, refresh, correlationID)
	if err != nil {
		if errors.Is(err, session.ErrRefreshInvalid) || errors.Is(err, session.ErrRefreshReused) { clearRefreshCookie(w); writeError(w, http.StatusUnauthorized, "invalid_refresh", "The refresh credential is invalid.", requestID); return }
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID); return
	}
	h.writeTokenPair(w, r, pair)
}

func (h *sessionHTTP) authorizeApplication(w http.ResponseWriter, r *http.Request, requestID string, requireOrigin bool) (applicationinstance.Instance, bool) {
	if h.applications == nil || h.origins == nil { writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID); return applicationinstance.Instance{}, false }
	values := r.Header.Values(PublishableKeyHeader)
	if len(values) != 1 || values[0] == "" { writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID); return applicationinstance.Instance{}, false }
	app, err := h.applications.ResolvePublishable(r.Context(), values[0])
	if err != nil { writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID); return applicationinstance.Instance{}, false }
	origin := r.Header.Get("Origin")
	if requireOrigin && origin == "" { writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID); return applicationinstance.Instance{}, false }
	if origin != "" {
		allowed, err := h.origins.IsAllowedOrigin(r.Context(), app.InternalID, origin)
		if err != nil || !allowed { writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID); return applicationinstance.Instance{}, false }
		setCORSHeaders(w, origin)
	}
	return app, true
}

func (h *sessionHTTP) writeTokenPair(w http.ResponseWriter, r *http.Request, pair session.TokenPair) {
	origin := r.Header.Get("Origin")
	response := tokenResponse{AccessToken: pair.AccessToken, TokenType: "Bearer", ExpiresIn: pair.ExpiresIn, SessionID: pair.SessionID}
	if origin != "" {
		http.SetCookie(w, &http.Cookie{Name: refreshCookieName, Value: pair.RefreshToken, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(session.AbsoluteLifetime / time.Second)})
	} else {
		response.RefreshToken = pair.RefreshToken
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *sessionHTTP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { w.Header().Set("Allow", http.MethodGet); http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	if h.ring == nil { http.Error(w, "not found", http.StatusNotFound); return }
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, h.ring.JWKS())
}

func clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: refreshCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

var _ = strings.Builder{}
