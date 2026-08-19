package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

type SocialAccountManagementService interface {
	List(context.Context, authentication.SocialAccountSession, int, string) (authentication.SocialAccountPage, error)
	Unlink(context.Context, authentication.SocialAccountSession, string, audit.CorrelationID) error
}

type socialAccountManagementHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	sessions     SessionManagementService
	management  SocialAccountManagementService
}

type linkedSocialAccountResponse struct {
	ID        string                  `json:"id"`
	Provider  authentication.Provider `json:"provider"`
	CreatedAt time.Time               `json:"created_at"`
}

type linkedSocialAccountPageResponse struct {
	Items      []linkedSocialAccountResponse `json:"items"`
	NextCursor string                        `json:"next_cursor,omitempty"`
}

func WithSocialAccountManagement(base http.Handler, applications ApplicationResolver, origins OriginPolicy, sessions SessionManagementService, management SocialAccountManagementService) http.Handler {
	return &socialAccountManagementHTTP{base: base, applications: applications, origins: origins, sessions: sessions, management: management}
}

func (h *socialAccountManagementHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/social-links" || strings.HasPrefix(r.URL.Path, "/v1/social-links/") {
		h.serve(w, r)
		return
	}
	h.base.ServeHTTP(w, r)
}

func (h *socialAccountManagementHTTP) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		w.Header().Set(RequestIDHeader, "request_unavailable")
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social account management is temporarily unavailable.", "request_unavailable")
		return
	}
	requestID := hex.EncodeToString(correlationID[:])
	w.Header().Set(RequestIDHeader, requestID)
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	if r.Method == http.MethodOptions {
		h.preflight(w, r, requestID)
		return
	}
	current, ok := h.authorize(w, r, requestID)
	if !ok {
		return
	}
	if r.URL.Path == "/v1/social-links" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, requestID)
			return
		}
		h.list(w, r, requestID, current)
		return
	}
	if r.Method != http.MethodDelete {
		methodNotAllowed(w, requestID)
		return
	}
	publicID := strings.TrimPrefix(r.URL.Path, "/v1/social-links/")
	if publicID == "" || strings.Contains(publicID, "/") || !authentication.ValidSocialLinkPublicID(publicID) {
		writeError(w, http.StatusBadRequest, "invalid_request", "The social-link resource identifier is invalid.", requestID)
		return
	}
	if h.management == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social account management is temporarily unavailable.", requestID)
		return
	}
	err = h.management.Unlink(r.Context(), current, publicID, correlationID)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, authentication.ErrSocialAccountReverification):
		writeError(w, http.StatusForbidden, "reverification_required", "Recent authentication is required before unlinking a social account.", requestID)
	case errors.Is(err, authentication.ErrSocialAccountInvalidSession):
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
	case errors.Is(err, authentication.ErrLastAuthenticationMethod):
		writeError(w, http.StatusConflict, "last_authentication_method", "At least one usable authentication method must remain.", requestID)
	case errors.Is(err, authentication.ErrSocialAccountInvalidRequest):
		writeError(w, http.StatusBadRequest, "invalid_request", "The social account management request is invalid.", requestID)
	default:
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social account management is temporarily unavailable.", requestID)
	}
}

func (h *socialAccountManagementHTTP) authorize(w http.ResponseWriter, r *http.Request, requestID string) (authentication.SocialAccountSession, bool) {
	if h.applications == nil || h.origins == nil || h.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social account management is temporarily unavailable.", requestID)
		return authentication.SocialAccountSession{}, false
	}
	keys := r.Header.Values(PublishableKeyHeader)
	if len(keys) != 1 || keys[0] == "" {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return authentication.SocialAccountSession{}, false
	}
	app, err := h.applications.ResolvePublishable(r.Context(), keys[0])
	if err != nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return authentication.SocialAccountSession{}, false
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] == "" {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return authentication.SocialAccountSession{}, false
	}
	canonical, err := applicationinstance.CanonicalizeOrigin(origins[0])
	if err != nil || canonical != origins[0] {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return authentication.SocialAccountSession{}, false
	}
	allowed, err := h.origins.IsAllowedOrigin(r.Context(), app.InternalID, canonical)
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return authentication.SocialAccountSession{}, false
	}
	token, ok := bearerToken(r.Header.Values("Authorization"))
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return authentication.SocialAccountSession{}, false
	}
	record, err := h.sessions.Current(r.Context(), app.InternalID, string(app.PublicID), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The current session is invalid.", requestID)
		return authentication.SocialAccountSession{}, false
	}
	setCORSHeaders(w, canonical)
	return authentication.SocialAccountSession{
		ApplicationInstanceID: record.ApplicationInstanceID,
		ApplicationPublicID: app.PublicID,
		UserID: record.UserInternalID,
		SessionPublicID: record.PublicID,
		CreatedAt: record.CreatedAt,
		IdleExpiresAt: record.IdleExpiresAt,
		ExpiresAt: record.ExpiresAt,
		Revoked: record.RevokedAt != nil,
	}, true
}

func (h *socialAccountManagementHTTP) list(w http.ResponseWriter, r *http.Request, requestID string, current authentication.SocialAccountSession) {
	if h.management == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social account management is temporarily unavailable.", requestID)
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > authentication.SocialLinkListMaxLimit {
			writeError(w, http.StatusBadRequest, "invalid_request", "The pagination parameters are invalid.", requestID)
			return
		}
		limit = parsed
	}
	if len(r.URL.Query()["limit"]) > 1 || len(r.URL.Query()["cursor"]) > 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "The pagination parameters are invalid.", requestID)
		return
	}
	page, err := h.management.List(r.Context(), current, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		if errors.Is(err, authentication.ErrSocialAccountInvalidRequest) {
			writeError(w, http.StatusBadRequest, "invalid_request", "The pagination parameters are invalid.", requestID)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Social account management is temporarily unavailable.", requestID)
		return
	}
	items := make([]linkedSocialAccountResponse, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, linkedSocialAccountResponse{ID: item.PublicID, Provider: item.Provider, CreatedAt: item.CreatedAt.UTC()})
	}
	writeJSON(w, http.StatusOK, linkedSocialAccountPageResponse{Items: items, NextCursor: page.NextCursor})
}

func (h *socialAccountManagementHTTP) preflight(w http.ResponseWriter, r *http.Request, requestID string) {
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
	requestedMethod := r.Header.Get("Access-Control-Request-Method")
	if requestedMethod != http.MethodGet && requestedMethod != http.MethodDelete {
		methodNotAllowed(w, requestID)
		return
	}
	setCORSHeaders(w, canonical)
	w.Header().Set("Access-Control-Allow-Methods", "GET, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-BeeBox-Publishable-Key")
	w.Header().Set("Access-Control-Max-Age", "300")
	w.WriteHeader(http.StatusNoContent)
}
