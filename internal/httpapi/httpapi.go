package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	PublishableKeyHeader = "X-BeeBox-Publishable-Key"
	IdempotencyKeyHeader = "Idempotency-Key"
	RequestIDHeader      = "X-Request-ID"
	maxJSONBodyBytes     = 16 << 10
	requestTimeout       = 10 * time.Second
)

type correlationContextKey struct{}

type ApplicationResolver interface {
	ResolvePublishable(context.Context, string) (applicationinstance.Instance, error)
}

type OriginPolicy interface {
	IsAllowedOrigin(context.Context, applicationinstance.InternalID, string) (bool, error)
	AnyAllowedOrigin(context.Context, string) (bool, error)
}

type SignupService interface {
	SignUpWithCorrelation(context.Context, applicationinstance.InternalID, string, string, string, audit.CorrelationID) error
}

type VerificationService interface {
	RequestWithCorrelation(context.Context, applicationinstance.InternalID, string, audit.CorrelationID) error
	ConfirmWithCorrelation(context.Context, applicationinstance.InternalID, string, string, audit.CorrelationID) error
}

type Handler struct {
	health       http.Handler
	applications ApplicationResolver
	origins      OriginPolicy
	signup       SignupService
	verification VerificationService
	mux          *http.ServeMux
}

type errorEnvelope struct {
	Error publicError `json:"error"`
}

type publicError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type statusEnvelope struct {
	Status string `json:"status"`
}

type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type verificationRequest struct {
	Email string `json:"email"`
}

type verificationConfirmRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func New(
	health http.Handler,
	applications ApplicationResolver,
	origins OriginPolicy,
	signup SignupService,
	verification VerificationService,
) http.Handler {
	h := &Handler{
		health:       health,
		applications: applications,
		origins:      origins,
		signup:       signup,
		verification: verification,
		mux:          http.NewServeMux(),
	}
	h.mux.HandleFunc("/v1/sign-ups", h.handleSignUp)
	h.mux.HandleFunc("/v1/email-verifications", h.handleVerificationRequest)
	h.mux.HandleFunc("/v1/email-verifications/confirm", h.handleVerificationConfirm)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/health/") && h.health != nil {
		h.health.ServeHTTP(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		http.NotFound(w, r)
		return
	}
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
	ctx = context.WithValue(ctx, correlationContextKey{}, correlationID)
	r = r.WithContext(ctx)
	if r.Method == http.MethodOptions {
		h.handlePreflight(w, r, requestID)
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) handleSignUp(w http.ResponseWriter, r *http.Request) {
	requestID := w.Header().Get(RequestIDHeader)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.authorizeApplication(w, r, requestID)
	if !ok {
		return
	}
	var input signupRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	idempotencyValues := r.Header.Values(IdempotencyKeyHeader)
	if len(idempotencyValues) != 1 || idempotencyValues[0] == "" {
		writeError(w, http.StatusBadRequest, "idempotency_required", "A valid Idempotency-Key header is required.", requestID)
		return
	}
	if h.signup == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	correlationID, ok := correlationFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	if err := h.signup.SignUpWithCorrelation(r.Context(), app.InternalID, input.Email, input.Password, idempotencyValues[0], correlationID); err != nil {
		h.writeSignupError(w, err, requestID)
		return
	}
	writeJSON(w, http.StatusAccepted, statusEnvelope{Status: "verification_pending"})
}

func (h *Handler) handleVerificationRequest(w http.ResponseWriter, r *http.Request) {
	requestID := w.Header().Get(RequestIDHeader)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.authorizeApplication(w, r, requestID)
	if !ok {
		return
	}
	var input verificationRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if h.verification == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	correlationID, ok := correlationFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	if err := h.verification.RequestWithCorrelation(r.Context(), app.InternalID, input.Email, correlationID); err != nil {
		if errors.Is(err, identity.ErrInvalidEmail) {
			writeError(w, http.StatusUnprocessableEntity, "invalid_input", "The supplied input is invalid.", requestID)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	writeJSON(w, http.StatusAccepted, statusEnvelope{Status: "accepted"})
}

func (h *Handler) handleVerificationConfirm(w http.ResponseWriter, r *http.Request) {
	requestID := w.Header().Get(RequestIDHeader)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	app, ok := h.authorizeApplication(w, r, requestID)
	if !ok {
		return
	}
	var input verificationConfirmRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "The request body is invalid.", requestID)
		return
	}
	if h.verification == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	correlationID, ok := correlationFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		return
	}
	if err := h.verification.ConfirmWithCorrelation(r.Context(), app.InternalID, input.Email, input.Code, correlationID); err != nil {
		switch {
		case errors.Is(err, identity.ErrInvalidEmail), errors.Is(err, authentication.ErrInvalidVerificationCode):
			writeError(w, http.StatusUnprocessableEntity, "invalid_input", "The supplied input is invalid.", requestID)
		case errors.Is(err, authentication.ErrEmailVerificationChallengeNotFound),
			errors.Is(err, authentication.ErrEmailVerificationAlreadyCompleted),
			errors.Is(err, authentication.ErrEmailVerificationExpired),
			errors.Is(err, authentication.ErrEmailVerificationMismatch),
			errors.Is(err, authentication.ErrEmailVerificationAttemptLimit),
			errors.Is(err, authentication.ErrEmailVerificationStaleChallenge):
			writeError(w, http.StatusBadRequest, "verification_failed", "The verification could not be completed.", requestID)
		default:
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
		}
		return
	}
	writeJSON(w, http.StatusOK, statusEnvelope{Status: "verified"})
}

func (h *Handler) authorizeApplication(w http.ResponseWriter, r *http.Request, requestID string) (applicationinstance.Instance, bool) {
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
	if err != nil {
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

func (h *Handler) handlePreflight(w http.ResponseWriter, r *http.Request, requestID string) {
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
	requestedMethod := r.Header.Get("Access-Control-Request-Method")
	if requestedMethod != http.MethodPost {
		methodNotAllowed(w, requestID)
		return
	}
	setCORSHeaders(w, origin)
	w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-BeeBox-Publishable-Key, Idempotency-Key")
	w.Header().Set("Access-Control-Max-Age", "300")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeSignupError(w http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, identity.ErrInvalidEmail), errors.Is(err, authentication.ErrPublicPasswordPolicy):
		writeError(w, http.StatusUnprocessableEntity, "invalid_input", "The supplied input is invalid.", requestID)
	case errors.Is(err, authentication.ErrPublicIdempotencyKey):
		writeError(w, http.StatusBadRequest, "invalid_idempotency_key", "The Idempotency-Key header is invalid.", requestID)
	case errors.Is(err, authentication.ErrPublicIdempotencyConflict):
		writeError(w, http.StatusConflict, "idempotency_conflict", "The idempotency key was used for a different request.", requestID)
	case errors.Is(err, authentication.ErrPublicRateLimited):
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests were received.", requestID)
	case errors.Is(err, authentication.ErrEmailVerificationDelivery):
		writeError(w, http.StatusServiceUnavailable, "delivery_unavailable", "Verification delivery is temporarily unavailable.", requestID)
	default:
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", requestID)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("invalid content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func setCORSHeaders(w http.ResponseWriter, origin string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Add("Vary", "Origin")
}

func methodNotAllowed(w http.ResponseWriter, requestID string) {
	w.Header().Set("Allow", http.MethodPost)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "The HTTP method is not allowed.", requestID)
}

func writeError(w http.ResponseWriter, status int, code, message, requestID string) {
	writeJSON(w, status, errorEnvelope{Error: publicError{Code: code, Message: message, RequestID: requestID}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func correlationFromContext(ctx context.Context) (audit.CorrelationID, bool) {
	correlationID, ok := ctx.Value(correlationContextKey{}).(audit.CorrelationID)
	return correlationID, ok && correlationID != (audit.CorrelationID{})
}
