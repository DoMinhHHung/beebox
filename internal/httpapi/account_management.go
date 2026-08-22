package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type accountSessionResolver interface {
	Current(context.Context, applicationinstance.InternalID, string, string) (session.Record, error)
}

type accountManagementService interface {
	ListEmails(context.Context, authentication.AccountManagementSession, int, string) (authentication.ManagedEmailPage, error)
	ListPhones(context.Context, authentication.AccountManagementSession, int, string) (authentication.ManagedPhonePage, error)
	AddEmail(context.Context, authentication.AccountManagementSession, string, audit.CorrelationID) (authentication.ManagedEmailIdentifier, error)
	AddPhone(context.Context, authentication.AccountManagementSession, string, audit.CorrelationID) (authentication.ManagedPhoneIdentifier, error)
	IssueEmailVerification(context.Context, authentication.AccountManagementSession, string, audit.CorrelationID) error
	ConfirmEmailVerification(context.Context, authentication.AccountManagementSession, string, string, audit.CorrelationID) (authentication.ManagedEmailIdentifier, error)
	IssuePhoneVerification(context.Context, authentication.AccountManagementSession, string, audit.CorrelationID) error
	ConfirmPhoneVerification(context.Context, authentication.AccountManagementSession, string, string, audit.CorrelationID) (authentication.ManagedPhoneIdentifier, error)
	SetPrimaryEmail(context.Context, authentication.AccountManagementSession, string, audit.CorrelationID) error
	SetPrimaryPhone(context.Context, authentication.AccountManagementSession, string, audit.CorrelationID) error
	RemoveEmail(context.Context, authentication.AccountManagementSession, string, audit.CorrelationID) error
	RemovePhone(context.Context, authentication.AccountManagementSession, string, audit.CorrelationID) error
	GetProfile(context.Context, authentication.AccountManagementSession) (authentication.AccountProfile, error)
	PatchProfile(context.Context, authentication.AccountManagementSession, authentication.ProfilePatch, audit.CorrelationID) (authentication.AccountProfile, error)
}

type accountManagementHTTP struct {
	base         http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	sessions     accountSessionResolver
	accounts     accountManagementService
}

type managedEmailResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Verified  bool   `json:"verified"`
	Primary   bool   `json:"primary"`
	CreatedAt string `json:"created_at"`
}

type managedPhoneResponse struct {
	ID        string `json:"id"`
	Phone     string `json:"phone"`
	Verified  bool   `json:"verified"`
	Primary   bool   `json:"primary"`
	CreatedAt string `json:"created_at"`
}

type accountProfileResponse struct {
	DisplayName *string `json:"display_name"`
	GivenName   *string `json:"given_name"`
	FamilyName  *string `json:"family_name"`
	Locale      *string `json:"locale"`
}

type managedEmailPageResponse struct {
	Items      []managedEmailResponse `json:"items"`
	NextCursor string                 `json:"next_cursor,omitempty"`
}

type managedPhonePageResponse struct {
	Items      []managedPhoneResponse `json:"items"`
	NextCursor string                 `json:"next_cursor,omitempty"`
}

func WithAccountManagement(base http.Handler, applications ApplicationResolver, origins OriginPolicy, sessions accountSessionResolver, accounts accountManagementService) http.Handler {
	return &accountManagementHTTP{base: base, applications: applications, origins: origins, sessions: sessions, accounts: accounts}
}

func (h *accountManagementHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v1/identifiers/") && r.URL.Path != "/v1/profile" {
		h.base.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	correlationID, err := correlationForRequest(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Account management is temporarily unavailable.", "request_unavailable")
		return
	}
	requestID := encodeCorrelationID(correlationID)
	w.Header().Set(RequestIDHeader, requestID)
	if r.Method == http.MethodOptions {
		h.preflight(w, r, requestID)
		return
	}
	current, ok := h.resolve(w, r, requestID)
	if !ok {
		return
	}
	if r.URL.Path == "/v1/profile" {
		h.handleProfile(w, r, requestID, correlationID, current)
		return
	}
	kind, publicID, action, ok := parseIdentifierPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "The resource was not found.", requestID)
		return
	}
	if publicID == "" {
		h.handleIdentifierCollection(w, r, requestID, correlationID, current, kind)
		return
	}
	h.handleIdentifierResource(w, r, requestID, correlationID, current, kind, publicID, action)
}

func (h *accountManagementHTTP) preflight(w http.ResponseWriter, r *http.Request, requestID string) {
	origin, ok := h.allowedOrigin(r.Context(), r, requestID, w)
	if !ok {
		return
	}
	method := r.Header.Get("Access-Control-Request-Method")
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPatch && method != http.MethodDelete {
		methodNotAllowed(w, requestID)
		return
	}
	setCORSHeaders(w, origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-BeeBox-Publishable-Key, "+ReverificationHeader)
	w.Header().Set("Access-Control-Max-Age", "300")
	w.WriteHeader(http.StatusNoContent)
}

func (h *accountManagementHTTP) resolve(w http.ResponseWriter, r *http.Request, requestID string) (authentication.AccountManagementSession, bool) {
	if h.applications == nil || h.origins == nil || h.sessions == nil || h.accounts == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Account management is temporarily unavailable.", requestID)
		return authentication.AccountManagementSession{}, false
	}
	values := r.Header.Values(PublishableKeyHeader)
	if len(values) != 1 || values[0] == "" {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return authentication.AccountManagementSession{}, false
	}
	app, err := h.applications.ResolvePublishable(r.Context(), values[0])
	if err != nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
		writeError(w, http.StatusUnauthorized, "invalid_application", "The application credential is invalid.", requestID)
		return authentication.AccountManagementSession{}, false
	}
	origin, ok := h.allowedOriginForApp(r.Context(), r, app.InternalID, requestID, w)
	if !ok {
		return authentication.AccountManagementSession{}, false
	}
	setCORSHeaders(w, origin)
	token, ok := bearerToken(r.Header.Values("Authorization"))
	if !ok || strings.HasPrefix(token, "bb_sk_") {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The session is invalid.", requestID)
		return authentication.AccountManagementSession{}, false
	}
	record, err := h.sessions.Current(r.Context(), app.InternalID, string(app.PublicID), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session", "The session is invalid.", requestID)
		return authentication.AccountManagementSession{}, false
	}
	return authentication.AccountManagementSession{
		ApplicationInstanceID: record.ApplicationInstanceID,
		UserID:                record.UserInternalID,
		SessionPublicID:       record.PublicID,
		IdleExpiresAt:         record.IdleExpiresAt,
		ExpiresAt:             record.ExpiresAt,
		Revoked:               record.RevokedAt != nil,
	}, true
}

func (h *accountManagementHTTP) allowedOrigin(ctx context.Context, r *http.Request, requestID string, w http.ResponseWriter) (string, bool) {
	values := r.Header.Values("Origin")
	if h.origins == nil || len(values) != 1 || values[0] == "" {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return "", false
	}
	canonical, err := applicationinstance.CanonicalizeOrigin(values[0])
	if err != nil || canonical != values[0] {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return "", false
	}
	allowed, err := h.origins.AnyAllowedOrigin(ctx, canonical)
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return "", false
	}
	return canonical, true
}

func (h *accountManagementHTTP) allowedOriginForApp(ctx context.Context, r *http.Request, appID applicationinstance.InternalID, requestID string, w http.ResponseWriter) (string, bool) {
	values := r.Header.Values("Origin")
	if len(values) != 1 || values[0] == "" {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return "", false
	}
	canonical, err := applicationinstance.CanonicalizeOrigin(values[0])
	if err != nil || canonical != values[0] {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return "", false
	}
	allowed, err := h.origins.IsAllowedOrigin(ctx, appID, canonical)
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.", requestID)
		return "", false
	}
	return canonical, true
}

func parseIdentifierPath(path string) (kind, publicID, action string, ok bool) {
	rest := strings.TrimPrefix(path, "/v1/identifiers/")
	parts := strings.Split(rest, "/")
	if len(parts) == 1 && identifierKind(parts[0]) {
		return parts[0], "", "", true
	}
	if len(parts) == 2 && identifierKind(parts[0]) && parts[1] != "" {
		return parts[0], parts[1], "", true
	}
	if len(parts) == 3 && identifierKind(parts[0]) && parts[1] != "" && (parts[2] == "verification" || parts[2] == "primary") {
		return parts[0], parts[1], parts[2], true
	}
	if len(parts) == 4 && identifierKind(parts[0]) && parts[1] != "" && parts[2] == "verification" && parts[3] == "confirm" {
		return parts[0], parts[1], "verification_confirm", true
	}
	return "", "", "", false
}

func identifierKind(kind string) bool {
	return kind == "emails" || kind == "phones"
}

func (h *accountManagementHTTP) handleIdentifierCollection(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, current authentication.AccountManagementSession, kind string) {
	if r.Method == http.MethodGet {
		limit, cursor, ok := identifierPageQuery(w, r, requestID)
		if !ok {
			return
		}
		if kind == "emails" {
			page, err := h.accounts.ListEmails(r.Context(), current, limit, cursor)
			if err != nil {
				h.writeError(w, requestID, err)
				return
			}
			out := make([]managedEmailResponse, 0, len(page.Items))
			for _, item := range page.Items {
				out = append(out, emailResponse(item))
			}
			writeJSON(w, http.StatusOK, managedEmailPageResponse{Items: out, NextCursor: page.NextCursor})
			return
		}
		page, err := h.accounts.ListPhones(r.Context(), current, limit, cursor)
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		out := make([]managedPhoneResponse, 0, len(page.Items))
		for _, item := range page.Items {
			out = append(out, phoneResponse(item))
		}
		writeJSON(w, http.StatusOK, managedPhonePageResponse{Items: out, NextCursor: page.NextCursor})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "The account management request is invalid.", requestID)
		return
	}
	if kind == "emails" {
		var body struct {
			Email string `json:"email"`
		}
		if !decodeStrictJSON(w, r, requestID, &body) {
			return
		}
		item, err := h.accounts.AddEmail(r.Context(), current, body.Email, correlationID)
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusCreated, emailResponse(item))
		return
	}
	var body struct {
		Phone string `json:"phone"`
	}
	if !decodeStrictJSON(w, r, requestID, &body) {
		return
	}
	item, err := h.accounts.AddPhone(r.Context(), current, body.Phone, correlationID)
	if err != nil {
		h.writeError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusCreated, phoneResponse(item))
}

func identifierPageQuery(w http.ResponseWriter, r *http.Request, requestID string) (int, string, bool) {
	query := r.URL.Query()
	for key := range query {
		if key != "limit" && key != "cursor" {
			writeError(w, http.StatusBadRequest, "invalid_request", "The account management request is invalid.", requestID)
			return 0, "", false
		}
	}
	limit := 0
	if values, ok := query["limit"]; ok {
		if len(values) != 1 || values[0] == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "The account management request is invalid.", requestID)
			return 0, "", false
		}
		parsed, err := strconv.Atoi(values[0])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "The account management request is invalid.", requestID)
			return 0, "", false
		}
		limit = parsed
	}
	cursor := ""
	if values, ok := query["cursor"]; ok {
		if len(values) != 1 || values[0] == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "The account management request is invalid.", requestID)
			return 0, "", false
		}
		cursor = values[0]
	}
	return limit, cursor, true
}

func (h *accountManagementHTTP) handleIdentifierResource(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, current authentication.AccountManagementSession, kind, publicID, action string) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "The account management request is invalid.", requestID)
		return
	}
	switch action {
	case "verification":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, requestID)
			return
		}
		var err error
		if kind == "emails" {
			err = h.accounts.IssueEmailVerification(r.Context(), current, publicID, correlationID)
		} else {
			err = h.accounts.IssuePhoneVerification(r.Context(), current, publicID, correlationID)
		}
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusAccepted, statusEnvelope{Status: "verification_sent"})
	case "verification_confirm":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, requestID)
			return
		}
		var body struct {
			Code string `json:"code"`
		}
		if !decodeStrictJSON(w, r, requestID, &body) {
			return
		}
		if kind == "emails" {
			item, err := h.accounts.ConfirmEmailVerification(r.Context(), current, publicID, body.Code, correlationID)
			if err != nil {
				h.writeError(w, requestID, err)
				return
			}
			writeJSON(w, http.StatusOK, emailResponse(item))
			return
		}
		item, err := h.accounts.ConfirmPhoneVerification(r.Context(), current, publicID, body.Code, correlationID)
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusOK, phoneResponse(item))
	case "primary":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, requestID)
			return
		}
		var err error
		if kind == "emails" {
			err = h.accounts.SetPrimaryEmail(r.Context(), current, publicID, correlationID)
		} else {
			err = h.accounts.SetPrimaryPhone(r.Context(), current, publicID, correlationID)
		}
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusOK, statusEnvelope{Status: "primary_updated"})
	default:
		if r.Method != http.MethodDelete {
			methodNotAllowed(w, requestID)
			return
		}
		var err error
		if kind == "emails" {
			err = h.accounts.RemoveEmail(r.Context(), current, publicID, correlationID)
		} else {
			err = h.accounts.RemovePhone(r.Context(), current, publicID, correlationID)
		}
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *accountManagementHTTP) handleProfile(w http.ResponseWriter, r *http.Request, requestID string, correlationID audit.CorrelationID, current authentication.AccountManagementSession) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "The profile request is invalid.", requestID)
		return
	}
	if r.Method == http.MethodGet {
		profile, err := h.accounts.GetProfile(r.Context(), current)
		if err != nil {
			h.writeError(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusOK, profileResponse(profile))
		return
	}
	if r.Method != http.MethodPatch {
		methodNotAllowed(w, requestID)
		return
	}
	patch, ok := decodeProfilePatch(w, r, requestID)
	if !ok {
		return
	}
	profile, err := h.accounts.PatchProfile(r.Context(), current, patch, correlationID)
	if err != nil {
		h.writeError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, profileResponse(profile))
}

func decodeProfilePatch(w http.ResponseWriter, r *http.Request, requestID string) (authentication.ProfilePatch, bool) {
	var raw map[string]json.RawMessage
	if !decodeStrictJSON(w, r, requestID, &raw) {
		return authentication.ProfilePatch{}, false
	}
	if len(raw) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "The profile request is invalid.", requestID)
		return authentication.ProfilePatch{}, false
	}
	patch := authentication.ProfilePatch{}
	for key, value := range raw {
		var target *authentication.OptionalStringPatch
		switch key {
		case "display_name":
			target = &patch.DisplayName
		case "given_name":
			target = &patch.GivenName
		case "family_name":
			target = &patch.FamilyName
		case "locale":
			target = &patch.Locale
		default:
			writeError(w, http.StatusBadRequest, "invalid_request", "The profile request is invalid.", requestID)
			return authentication.ProfilePatch{}, false
		}
		target.Present = true
		if string(value) == "null" {
			target.Value = nil
			continue
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "The profile request is invalid.", requestID)
			return authentication.ProfilePatch{}, false
		}
		target.Value = &text
	}
	return patch, true
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, requestID string, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return false
	}
	return true
}

func (h *accountManagementHTTP) writeError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, authentication.ErrAccountManagementInvalid), errors.Is(err, authentication.ErrAccountIdentifierNotFound):
		writeError(w, http.StatusBadRequest, "invalid_request", "The account management request is invalid.", requestID)
	case errors.Is(err, authentication.ErrAccountManagementSession):
		writeError(w, http.StatusUnauthorized, "invalid_session", "The session is invalid.", requestID)
	case errors.Is(err, authentication.ErrAccountManagementReverification):
		writeError(w, http.StatusForbidden, "reverification_required", "Recent reverification is required for this operation.", requestID)
	case errors.Is(err, authentication.ErrAccountIdentifierUnavailable):
		writeError(w, http.StatusConflict, "identifier_unavailable", "The identifier cannot be used.", requestID)
	case errors.Is(err, authentication.ErrAccountIdentifierUnverified):
		writeError(w, http.StatusConflict, "identifier_unverified", "The identifier must be verified first.", requestID)
	case errors.Is(err, authentication.ErrLastAuthenticationMethod):
		writeError(w, http.StatusConflict, "last_authentication_method", "At least one usable authentication method must remain.", requestID)
	case errors.Is(err, authentication.ErrPublicRateLimited):
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests.", requestID)
	default:
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Account management is temporarily unavailable.", requestID)
	}
}

func emailResponse(item authentication.ManagedEmailIdentifier) managedEmailResponse {
	return managedEmailResponse{ID: item.PublicID, Email: item.Email, Verified: item.Verified, Primary: item.Primary, CreatedAt: item.CreatedAt.UTC().Format(time.RFC3339)}
}

func phoneResponse(item authentication.ManagedPhoneIdentifier) managedPhoneResponse {
	return managedPhoneResponse{ID: item.PublicID, Phone: item.Phone, Verified: item.Verified, Primary: item.Primary, CreatedAt: item.CreatedAt.UTC().Format(time.RFC3339)}
}

func profileResponse(profile authentication.AccountProfile) accountProfileResponse {
	return accountProfileResponse{DisplayName: profile.DisplayName, GivenName: profile.GivenName, FamilyName: profile.FamilyName, Locale: profile.Locale}
}

func encodeCorrelationID(id audit.CorrelationID) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(id)*2)
	for i, b := range id {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&15]
	}
	return string(out)
}
