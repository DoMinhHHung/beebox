package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

const (
	hostedCSRFCookie = "__Host-beebox-hosted-csrf"
	hostedMFACookie  = "__Host-beebox-hosted-mfa"
)

type HostedTOTPCompletion interface {
	Complete(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error)
}

type HostedRecoveryCompletion interface {
	Complete(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error)
}

type HostedEmailLinkCompletionLoader interface {
	LoadConsumedEmailLinkCompletion(context.Context, applicationinstance.InternalID, string) (string, error)
}

type hostedHTTP struct {
	base         http.Handler
	origin       string
	applications ApplicationResolver
	redirects    authentication.EmailLinkRedirectPolicy
	emailLinks   EmailLinkConfirmService
	pending      session.PendingMFAContextLoader
	totp         HostedTOTPCompletion
	recovery     HostedRecoveryCompletion
	destinations HostedEmailLinkCompletionLoader
}

type hostedEmailLinkConfirmRequest struct {
	ChallengeID string `json:"challenge_id"`
	Secret      string `json:"secret"`
}

type hostedMFARequest struct {
	Code string `json:"code"`
}

type hostedTokenResponse struct {
	Status           string                         `json:"status"`
	Session          *authenticationSessionResponse `json:"session,omitempty"`
	AccessToken      string                         `json:"access_token,omitempty"`
	TokenType        string                         `json:"token_type,omitempty"`
	ExpiresIn        int64                          `json:"expires_in,omitempty"`
	SessionID        string                         `json:"session_id,omitempty"`
	ExpiresAt        *time.Time                     `json:"expires_at,omitempty"`
	AvailableMethods []string                       `json:"available_methods,omitempty"`
	CompletionURL    string                         `json:"completion_url,omitempty"`
}

func WithHostedAuth(
	base http.Handler,
	hostedOrigin string,
	applications ApplicationResolver,
	redirects authentication.EmailLinkRedirectPolicy,
	emailLinks EmailLinkConfirmService,
	pending session.PendingMFAContextLoader,
	totp HostedTOTPCompletion,
	recovery HostedRecoveryCompletion,
	destinations HostedEmailLinkCompletionLoader,
) http.Handler {
	if base == nil || hostedOrigin == "" {
		return base
	}
	return &hostedHTTP{
		base: base, origin: hostedOrigin, applications: applications, redirects: redirects,
		emailLinks: emailLinks, pending: pending, totp: totp, recovery: recovery, destinations: destinations,
	}
}

func (h *hostedHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/auth") {
		h.base.ServeHTTP(w, r)
		return
	}
	h.setSecurityHeaders(w)
	switch {
	case r.URL.Path == "/auth" || r.URL.Path == "/auth/" || r.URL.Path == "/auth/email-link":
		h.servePage(w, r)
	case r.URL.Path == "/auth/app.js":
		h.serveAsset(w, r, "text/javascript; charset=utf-8", hostedJS)
	case r.URL.Path == "/auth/app.css":
		h.serveAsset(w, r, "text/css; charset=utf-8", hostedCSS)
	case r.URL.Path == "/auth/api/email-link/confirm":
		h.withMutationContext(w, r, h.confirmEmailLink)
	case r.URL.Path == "/auth/api/email-link/mfa/totp":
		h.withMutationContext(w, r, func(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
			h.completeEmailLinkMFA(w, r, requestID, correlationID, false)
		})
	case r.URL.Path == "/auth/api/email-link/mfa/recovery":
		h.withMutationContext(w, r, func(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
			h.completeEmailLinkMFA(w, r, requestID, correlationID, true)
		})
	case strings.HasPrefix(r.URL.Path, "/auth/api/v1/"):
		h.proxyHeadless(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *hostedHTTP) setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func (h *hostedHTTP) servePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	csrf, err := h.csrfToken(w, r)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	locale := r.URL.Query().Get("lang")
	if locale != "vi" {
		locale = "en"
	}
	theme := r.URL.Query().Get("theme")
	if theme != "light" && theme != "dark" {
		theme = "system"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	page := strings.NewReplacer(
		"{{LANG}}", html.EscapeString(locale),
		"{{THEME}}", html.EscapeString(theme),
		"{{CSRF}}", html.EscapeString(csrf),
	).Replace(hostedHTML)
	_, _ = w.Write([]byte(page))
}

func (h *hostedHTTP) serveAsset(w http.ResponseWriter, r *http.Request, contentType, body string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", contentType)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(body))
	}
}

func (h *hostedHTTP) csrfToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if cookie, err := r.Cookie(hostedCSRFCookie); err == nil && validHostedSecret(cookie.Value) {
		return cookie.Value, nil
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(raw[:])
	http.SetCookie(w, &http.Cookie{
		Name: hostedCSRFCookie, Value: value, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int((24 * time.Hour) / time.Second),
	})
	return value, nil
}

func validHostedSecret(value string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 32
}

func (h *hostedHTTP) mutationAllowed(r *http.Request) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch && r.Method != http.MethodDelete {
		return false
	}
	if r.Header.Get("Origin") != h.origin {
		return false
	}
	cookie, err := r.Cookie(hostedCSRFCookie)
	if err != nil || !validHostedSecret(cookie.Value) {
		return false
	}
	provided := r.Header.Get("X-BeeBox-CSRF")
	if len(provided) != len(cookie.Value) || subtle.ConstantTimeCompare([]byte(provided), []byte(cookie.Value)) != 1 {
		return false
	}
	return true
}

func (h *hostedHTTP) withMutationContext(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request, string, audit.CorrelationID)) {
	if !h.mutationAllowed(r) {
		writeError(w, http.StatusForbidden, "csrf_failed", "The hosted authentication request was rejected.", "request_unavailable")
		return
	}
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", "request_unavailable")
		return
	}
	requestID := hex.EncodeToString(correlationID[:])
	w.Header().Set(RequestIDHeader, requestID)
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	next(w, r.WithContext(ctx), requestID, correlationID)
}

func (h *hostedHTTP) proxyHeadless(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !h.mutationAllowed(r) {
		writeError(w, http.StatusForbidden, "csrf_failed", "The hosted authentication request was rejected.", "request_unavailable")
		return
	}
	target := strings.TrimPrefix(r.URL.Path, "/auth/api")
	if !strings.HasPrefix(target, "/v1/") {
		http.NotFound(w, r)
		return
	}
	clone := r.Clone(r.Context())
	clone.URL.Path = target
	clone.URL.RawPath = ""
	clone.Header = r.Header.Clone()
	clone.Header.Del("X-BeeBox-CSRF")
	clone.Header.Set("Origin", h.origin)
	h.base.ServeHTTP(w, clone)
}

func (h *hostedHTTP) resolveHostedApplication(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, bool) {
	if h.applications == nil {
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

func (h *hostedHTTP) confirmEmailLink(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.resolveHostedApplication(w, r, requestID)
	if !ok {
		return
	}
	var input hostedEmailLinkConfirmRequest
	if decodeJSON(w, r, &input) != nil || h.emailLinks == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The hosted authentication request is invalid.", requestID)
		return
	}
	result, err := h.emailLinks.Confirm(r.Context(), app.InternalID, input.ChallengeID, input.Secret, correlationID)
	if err != nil {
		h.writeHostedAuthenticationError(w, requestID, err)
		return
	}
	if result.TokenPair.PendingMFA != nil {
		http.SetCookie(w, &http.Cookie{
			Name: hostedMFACookie, Value: result.TokenPair.PendingMFA.Token, Path: "/auth", Secure: true, HttpOnly: true,
			SameSite: http.SameSiteLaxMode, MaxAge: int(authentication.PendingMFATTL / time.Second),
		})
		expiresAt := result.TokenPair.PendingMFA.ExpiresAt.UTC()
		writeJSON(w, http.StatusOK, hostedTokenResponse{
			Status: "mfa_required", ExpiresAt: &expiresAt,
			AvailableMethods: append([]string(nil), result.TokenPair.PendingMFA.AvailableMethods...),
		})
		return
	}
	if !h.currentRedirectAllowed(r.Context(), app.InternalID, result.CompletionURL) {
		writeError(w, http.StatusBadRequest, "invalid_destination", "The hosted authentication destination is invalid.", requestID)
		return
	}
	h.writeHostedAuthenticated(w, app.PublicID, result.TokenPair, result.CompletionURL)
}

func (h *hostedHTTP) completeEmailLinkMFA(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, recovery bool) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.resolveHostedApplication(w, r, requestID)
	if !ok {
		return
	}
	var input hostedMFARequest
	if decodeJSON(w, r, &input) != nil || input.Code == "" || h.pending == nil || h.destinations == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The hosted authentication request is invalid.", requestID)
		return
	}
	cookie, err := r.Cookie(hostedMFACookie)
	if err != nil || cookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
		return
	}
	binding, err := session.ResolvePendingMFAContext(r.Context(), h.pending, cookie.Value)
	if err != nil || binding.ApplicationInstanceID != app.InternalID || binding.PrimaryMethod != authentication.PrimaryMethodEmailLink || !authentication.ValidEmailLinkChallengeID(binding.PrimaryContext) {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
		return
	}
	var pair session.TokenPair
	if recovery {
		if h.recovery == nil {
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
			return
		}
		pair, err = h.recovery.Complete(r.Context(), app.InternalID, cookie.Value, input.Code, correlationID)
	} else {
		if h.totp == nil {
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
			return
		}
		pair, err = h.totp.Complete(r.Context(), app.InternalID, cookie.Value, input.Code, correlationID)
	}
	if err != nil {
		h.writeHostedAuthenticationError(w, requestID, err)
		return
	}
	completionURL, err := h.destinations.LoadConsumedEmailLinkCompletion(r.Context(), app.InternalID, binding.PrimaryContext)
	if err != nil || !h.currentRedirectAllowed(r.Context(), app.InternalID, completionURL) {
		writeError(w, http.StatusBadRequest, "invalid_destination", "The hosted authentication destination is invalid.", requestID)
		return
	}
	clearHostedMFACookie(w)
	h.writeHostedAuthenticated(w, app.PublicID, pair, completionURL)
}

func (h *hostedHTTP) currentRedirectAllowed(ctx context.Context, appID applicationinstance.InternalID, completionURL string) bool {
	if h.redirects == nil || completionURL == "" {
		return false
	}
	allowed, err := h.redirects.IsAllowedRedirectURL(ctx, appID, completionURL)
	return err == nil && allowed
}

func (h *hostedHTTP) writeHostedAuthenticated(w http.ResponseWriter, appPublicID applicationinstance.PublicID, pair session.TokenPair, completionURL string) {
	if pair.PendingMFA != nil || pair.AccessToken == "" || pair.RefreshToken == "" || pair.SessionID == "" || completionURL == "" {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", "request_unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: refreshCookieName(appPublicID), Value: pair.RefreshToken, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(session.AbsoluteLifetime / time.Second),
	})
	writeJSON(w, http.StatusOK, hostedTokenResponse{
		Status: "authenticated", Session: &authenticationSessionResponse{ID: pair.SessionID},
		AccessToken: pair.AccessToken, TokenType: "Bearer", ExpiresIn: pair.ExpiresIn,
		SessionID: pair.SessionID, CompletionURL: completionURL,
	})
}

func clearHostedMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: hostedMFACookie, Value: "", Path: "/auth", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func (h *hostedHTTP) writeHostedAuthenticationError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, session.ErrInvalidCredentials), errors.Is(err, authentication.ErrTOTPInvalidCode), errors.Is(err, authentication.ErrTOTPReplay), errors.Is(err, authentication.ErrRecoveryInvalid), errors.Is(err, authentication.ErrRecoveryReplay):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
	case errors.Is(err, session.ErrSignInRateLimited), errors.Is(err, authentication.ErrRecoveryRateLimited):
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests were received.", requestID)
	default:
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
	}
}
