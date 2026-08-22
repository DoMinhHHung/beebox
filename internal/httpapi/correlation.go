package httpapi

import (
	"context"
	"net/http"

	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/requestcorrelation"
)

type publicRequestIDContextKey struct{}

func correlationForRequest(r *http.Request) (audit.CorrelationID, error) {
	if r != nil {
		if correlationID, ok := correlationFromContext(r.Context()); ok {
			return correlationID, nil
		}
	}
	return audit.NewCorrelationID()
}

func publicRequestIDForRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	requestID, ok := r.Context().Value(publicRequestIDContextKey{}).(string)
	if !ok {
		return ""
	}
	id, ok := requestcorrelation.ParseID(requestID)
	if !ok {
		return ""
	}
	return id.String()
}

func WithTrustedRequestCorrelation(base http.Handler, key requestcorrelation.Key) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicID, auditCorrelation, err := publicAndAuditCorrelation(r, key)
		if err != nil {
			w.Header().Set(RequestIDHeader, "request_unavailable")
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", "request_unavailable")
			return
		}
		requestID := publicID.String()
		r.Header.Del(RequestIDHeader)
		r.Header.Del(requestcorrelation.InternalIDHeader)
		r.Header.Del(requestcorrelation.InternalSignatureHeader)
		r.Header.Set(RequestIDHeader, requestID)
		ctx := context.WithValue(r.Context(), correlationContextKey{}, auditCorrelation)
		ctx = context.WithValue(ctx, publicRequestIDContextKey{}, requestID)
		base.ServeHTTP(&correlationResponseWriter{ResponseWriter: w, requestID: requestID}, r.WithContext(ctx))
	})
}

func publicAndAuditCorrelation(r *http.Request, key requestcorrelation.Key) (requestcorrelation.ID, audit.CorrelationID, error) {
	if candidate, signature, ok := gatewayDiagnosticEnvelope(r); ok {
		if key != (requestcorrelation.Key{}) {
			if trusted, verified := requestcorrelation.Verify(key, candidate.String(), signature); verified {
				return candidate, audit.CorrelationID(trusted), nil
			}
		}
		fresh, err := audit.NewCorrelationID()
		if err != nil {
			return requestcorrelation.ID{}, audit.CorrelationID{}, err
		}
		return candidate, fresh, nil
	}
	fresh, err := audit.NewCorrelationID()
	if err != nil {
		return requestcorrelation.ID{}, audit.CorrelationID{}, err
	}
	return requestcorrelation.ID(fresh), fresh, nil
}

func gatewayDiagnosticEnvelope(r *http.Request) (requestcorrelation.ID, string, bool) {
	if r == nil {
		return requestcorrelation.ID{}, "", false
	}
	publicIDs := r.Header.Values(RequestIDHeader)
	internalIDs := r.Header.Values(requestcorrelation.InternalIDHeader)
	signatures := r.Header.Values(requestcorrelation.InternalSignatureHeader)
	if len(publicIDs) != 1 || len(internalIDs) != 1 || len(signatures) != 1 {
		return requestcorrelation.ID{}, "", false
	}
	candidate, ok := requestcorrelation.ParseID(internalIDs[0])
	if !ok || publicIDs[0] != candidate.String() || !requestcorrelation.SignatureIsCanonical(signatures[0]) {
		return requestcorrelation.ID{}, "", false
	}
	return candidate, signatures[0], true
}

type correlationResponseWriter struct {
	http.ResponseWriter
	requestID string
}

func (w *correlationResponseWriter) WriteHeader(status int) {
	w.Header().Set(RequestIDHeader, w.requestID)
	w.Header().Del(requestcorrelation.InternalIDHeader)
	w.Header().Del(requestcorrelation.InternalSignatureHeader)
	w.ResponseWriter.WriteHeader(status)
}
func (w *correlationResponseWriter) Write(p []byte) (int, error) {
	w.Header().Set(RequestIDHeader, w.requestID)
	w.Header().Del(requestcorrelation.InternalIDHeader)
	w.Header().Del(requestcorrelation.InternalSignatureHeader)
	return w.ResponseWriter.Write(p)
}
func (w *correlationResponseWriter) Flush() {
	w.Header().Set(RequestIDHeader, w.requestID)
	w.Header().Del(requestcorrelation.InternalIDHeader)
	w.Header().Del(requestcorrelation.InternalSignatureHeader)
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
func (w *correlationResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func encodeAuditCorrelation(id audit.CorrelationID) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(id)*2)
	for i, b := range id {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&15]
	}
	return string(out)
}
