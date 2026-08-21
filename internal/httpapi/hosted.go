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
	hostedCSRFCookie   = "__Host-beebox-hosted-csrf"
	hostedMFACookie    = "__Host-beebox-hosted-mfa"
	hostedSocialCookie = "__Host-beebox-hosted-social"
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

type HostedSocialAttemptService interface {
	CreateAttempt(context.Context, applicationinstance.Instance, authentication.Provider, string, string, string) (authentication.SocialAttemptResult, error)
}

type HostedSocialExchangeService interface {
	Exchange(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) (session.TokenPair, error)
}

type hostedHTTP struct {
	base            http.Handler
	origin          string
	applications    ApplicationResolver
	redirects       authentication.EmailLinkRedirectPolicy
	emailLinks      EmailLinkConfirmService
	pending         session.PendingMFAContextLoader
	totp            HostedTOTPCompletion
	recovery        HostedRecoveryCompletion
	destinations    HostedEmailLinkCompletionLoader
	socialAttempts  HostedSocialAttemptService
	socialExchange  HostedSocialExchangeService
	socialProtector *authentication.SocialStateProtector
}

type hostedEmailLinkConfirmRequest struct {
	ChallengeID string `json:"challenge_id"`
	Secret      string `json:"secret"`
}

type hostedMFARequest struct {
	Code string `json:"code"`
}

type hostedSocialStartRequest struct {
	Provider      string `json:"provider"`
	CompletionURL string `json:"completion_url"`
}

type hostedSocialExchangeRequest struct {
	Code string `json:"code"`
}

type hostedSocialStartResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	ExpiresIn        int64  `json:"expires_in"`
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
	socialAttempts HostedSocialAttemptService,
	socialExchange HostedSocialExchangeService,
	socialProtector *authentication.SocialStateProtector,
) http.Handler {
	if base == nil || hostedOrigin == "" {
		return base
	}
	return &hostedHTTP{
		base: base, origin: hostedOrigin, applications: applications, redirects: redirects,
		emailLinks: emailLinks, pending: pending, totp: totp, recovery: recovery, destinations: destinations,
		socialAttempts: socialAttempts, socialExchange: socialExchange, socialProtector: socialProtector,
	}
}

func (h *hostedHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/auth") {
		h.base.ServeHTTP(w, r)
		return
	}
	h.setSecurityHeaders(w)
	switch {
	case r.URL.Path == "/auth" || r.URL.Path == "/auth/" || r.URL.Path == "/auth/email-link" || r.URL.Path == "/auth/social/callback":
		h.servePage(w, r)
	case r.URL.Path == "/auth/app.js":
		h.serveAsset(w, r, "text/javascript; charset=utf-8", hostedJS)
	case r.URL.Path == "/auth/app.css":
		h.serveAsset(w, r, "text/css; charset=utf-8", hostedCSS)
	case r.URL.Path == "/auth/api/email-link/confirm":
		h.withMutationContext(w, r, h.confirmEmailLink)
	case r.URL.Path == "/auth/api/social/start":
		h.withMutationContext(w, r, h.startSocial)
	case r.URL.Path == "/auth/api/social/exchange":
		h.withMutationContext(w, r, h.exchangeSocial)
	case r.URL.Path == "/auth/api/mfa/totp":
		h.withMutationContext(w, r, func(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
			h.completeHostedMFA(w, r, requestID, correlationID, false)
		})
	case r.URL.Path == "/auth/api/mfa/recovery":
		h.withMutationContext(w, r, func(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
			h.completeHostedMFA(w, r, requestID, correlationID, true)
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
		setHostedMFACookie(w, result.TokenPair.PendingMFA.Token)
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

func (h *hostedHTTP) startSocial(w http.ResponseWriter, r *http.Request, requestID string, _ audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.resolveHostedApplication(w, r, requestID)
	if !ok {
		return
	}
	var input hostedSocialStartRequest
	if decodeJSON(w, r, &input) != nil || h.socialAttempts == nil || h.socialProtector == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The hosted social request is invalid.", requestID)
		return
	}
	provider := authentication.Provider(input.Provider)
	if !provider.Valid() || !h.currentRedirectAllowed(r.Context(), app.InternalID, input.CompletionURL) {
		writeError(w, http.StatusBadRequest, "invalid_request", "The hosted social request is invalid.", requestID)
		return
	}
	callbackURL := h.origin + "/auth/social/callback"
	if !h.currentRedirectAllowed(r.Context(), app.InternalID, callbackURL) {
		writeError(w, http.StatusBadRequest, "invalid_destination", "The hosted social callback is not configured for this application.", requestID)
		return
	}
	verifier, err := authentication.NewSocialPKCEVerifier()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is temporarily unavailable.", requestID)
		return
	}
	challenge, ok := authentication.S256Challenge(verifier)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is temporarily unavailable.", requestID)
		return
	}
	attempt, err := h.socialAttempts.CreateAttempt(r.Context(), app, provider, callbackURL, challenge, "S256")
	if err != nil {
		h.writeHostedSocialError(w, requestID, err)
		return
	}
	now := time.Now().UTC()
	sealed, err := h.socialProtector.SealHostedContext(authentication.HostedSocialContext{
		ApplicationInstanceID: app.InternalID,
		ApplicationPublicID:   app.PublicID,
		PKCEVerifier:          verifier,
		CompletionURL:         input.CompletionURL,
		IssuedAt:              now,
		ExpiresAt:             now.Add(authentication.SocialAttemptTTL),
	})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is temporarily unavailable.", requestID)
		return
	}
	setHostedSocialCookie(w, sealed)
	writeJSON(w, http.StatusOK, hostedSocialStartResponse{AuthorizationURL: attempt.AuthorizationURL, ExpiresIn: attempt.ExpiresIn})
}

func (h *hostedHTTP) exchangeSocial(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	var input hostedSocialExchangeRequest
	if decodeJSON(w, r, &input) != nil || input.Code == "" || h.socialExchange == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The hosted social request is invalid.", requestID)
		return
	}
	context, ok := h.hostedSocialContext(w, r, requestID)
	if !ok {
		return
	}
	if !h.currentRedirectAllowed(r.Context(), context.ApplicationInstanceID, context.CompletionURL) {
		clearHostedSocialCookie(w)
		writeError(w, http.StatusBadRequest, "invalid_destination", "The hosted authentication destination is invalid.", requestID)
		return
	}
	pair, err := h.socialExchange.Exchange(r.Context(), context.ApplicationInstanceID, input.Code, context.PKCEVerifier, correlationID)
	if err != nil {
		h.writeHostedAuthenticationError(w, requestID, err)
		return
	}
	if pair.PendingMFA != nil {
		setHostedMFACookie(w, pair.PendingMFA.Token)
		expiresAt := pair.PendingMFA.ExpiresAt.UTC()
		writeJSON(w, http.StatusOK, hostedTokenResponse{
			Status: "mfa_required", ExpiresAt: &expiresAt,
			AvailableMethods: append([]string(nil), pair.PendingMFA.AvailableMethods...),
		})
		return
	}
	clearHostedSocialCookie(w)
	h.writeHostedAuthenticated(w, context.ApplicationPublicID, pair, context.CompletionURL)
}

func (h *hostedHTTP) completeHostedMFA(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, recovery bool) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	var input hostedMFARequest
	if decodeJSON(w, r, &input) != nil || input.Code == "" || h.pending == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The hosted authentication request is invalid.", requestID)
		return
	}
	cookie, err := r.Cookie(hostedMFACookie)
	if err != nil || cookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
		return
	}
	binding, err := session.ResolvePendingMFAContext(r.Context(), h.pending, cookie.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
		return
	}
	appPublicID, completionURL, socialFlow, ok := h.resolveMFACompletion(w, r, requestID, binding)
	if !ok {
		return
	}
	if !h.currentRedirectAllowed(r.Context(), binding.ApplicationInstanceID, completionURL) {
		writeError(w, http.StatusBadRequest, "invalid_destination", "The hosted authentication destination is invalid.", requestID)
		return
	}
	var pair session.TokenPair
	if recovery {
		if h.recovery == nil {
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
			return
		}
		pair, err = h.recovery.Complete(r.Context(), binding.ApplicationInstanceID, cookie.Value, input.Code, correlationID)
	} else {
		if h.totp == nil {
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
			return
		}
		pair, err = h.totp.Complete(r.Context(), binding.ApplicationInstanceID, cookie.Value, input.Code, correlationID)
	}
	if err != nil {
		h.writeHostedAuthenticationError(w, requestID, err)
		return
	}
	if !h.currentRedirectAllowed(r.Context(), binding.ApplicationInstanceID, completionURL) {
		writeError(w, http.StatusBadRequest, "invalid_destination", "The hosted authentication destination is invalid.", requestID)
		return
	}
	clearHostedMFACookie(w)
	if socialFlow {
		clearHostedSocialCookie(w)
	}
	h.writeHostedAuthenticated(w, appPublicID, pair, completionURL)
}

func (h *hostedHTTP) resolveMFACompletion(w http.ResponseWriter, r *http.Request, requestID string, binding session.PendingMFAContext) (applicationinstance.PublicID, string, bool, bool) {
	switch binding.PrimaryMethod {
	case authentication.PrimaryMethodEmailLink:
		if h.destinations == nil || !authentication.ValidEmailLinkChallengeID(binding.PrimaryContext) {
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
			return "", "", false, false
		}
		app, ok := h.resolveHostedApplication(w, r, requestID)
		if !ok || app.InternalID != binding.ApplicationInstanceID {
			if ok {
				writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
			}
			return "", "", false, false
		}
		completionURL, err := h.destinations.LoadConsumedEmailLinkCompletion(r.Context(), app.InternalID, binding.PrimaryContext)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
			return "", "", false, false
		}
		return app.PublicID, completionURL, false, true
	case authentication.PrimaryMethodSocial:
		if binding.PrimaryContext != "social_completion" {
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
			return "", "", false, false
		}
		context, ok := h.hostedSocialContext(w, r, requestID)
		if !ok || context.ApplicationInstanceID != binding.ApplicationInstanceID {
			if ok {
				writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
			}
			return "", "", false, false
		}
		return context.ApplicationPublicID, context.CompletionURL, true, true
	default:
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
		return "", "", false, false
	}
}

func (h *hostedHTTP) hostedSocialContext(w http.ResponseWriter, r *http.Request, requestID string) (authentication.HostedSocialContext, bool) {
	if h.socialProtector == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is temporarily unavailable.", requestID)
		return authentication.HostedSocialContext{}, false
	}
	cookie, err := r.Cookie(hostedSocialCookie)
	if err != nil || cookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
		return authentication.HostedSocialContext{}, false
	}
	context, err := h.socialProtector.OpenHostedContext(cookie.Value, time.Now().UTC())
	if err != nil {
		clearHostedSocialCookie(w)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "The supplied credentials are invalid.", requestID)
		return authentication.HostedSocialContext{}, false
	}
	return context, true
}

func (h *hostedHTTP) currentRedirectAllowed(ctx context.Context, appID applicationinstance.InternalID, completionURL string) bool {
	if h.redirects == nil || completionURL == "" {
		return false
	}
	allowed, err := h.redirects.IsAllowedRedirectURL(ctx, appID, completionURL)
	return err == nil && allowed
}

func (h *hostedHTTP) writeHostedAuthenticated(w http.ResponseWriter, appPublicID applicationinstance.PublicID, pair session.TokenPair, completionURL string) {
	if !appPublicID.Valid() || pair.PendingMFA != nil || pair.AccessToken == "" || pair.RefreshToken == "" || pair.SessionID == "" || completionURL == "" {
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

func setHostedMFACookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: hostedMFACookie, Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(authentication.PendingMFATTL / time.Second),
	})
}

func clearHostedMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: hostedMFACookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func setHostedSocialCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: hostedSocialCookie, Value: value, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(authentication.SocialAttemptTTL / time.Second),
	})
}

func clearHostedSocialCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: hostedSocialCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func (h *hostedHTTP) writeHostedSocialError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, authentication.ErrSocialInvalidRequest), errors.Is(err, authentication.ErrSocialUnsupportedProvider):
		writeError(w, http.StatusBadRequest, "invalid_request", "The hosted social request is invalid.", requestID)
	case errors.Is(err, authentication.ErrSocialRateLimited):
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests were received.", requestID)
	default:
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social authentication is temporarily unavailable.", requestID)
	}
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
