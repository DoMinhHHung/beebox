package httpapi

import (
	"context"
	"net/http"

	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/requestcorrelation"
)

func correlationForRequest(r *http.Request) (audit.CorrelationID, error) {
	if r != nil {
		if correlationID, ok := correlationFromContext(r.Context()); ok {
			return correlationID, nil
		}
	}
	return audit.NewCorrelationID()
}

func WithTrustedRequestCorrelation(base http.Handler, key requestcorrelation.Key) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID, err := trustedOrFreshCorrelation(r, key)
		if err != nil {
			w.Header().Set(RequestIDHeader, "request_unavailable")
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Authentication is temporarily unavailable.", "request_unavailable")
			return
		}
		requestID := encodeAuditCorrelation(correlationID)
		r.Header.Del(RequestIDHeader)
		r.Header.Del(requestcorrelation.InternalIDHeader)
		r.Header.Del(requestcorrelation.InternalSignatureHeader)
		r.Header.Set(RequestIDHeader, requestID)
		ctx := context.WithValue(r.Context(), correlationContextKey{}, correlationID)
		base.ServeHTTP(&correlationResponseWriter{ResponseWriter: w, requestID: requestID}, r.WithContext(ctx))
	})
}

func trustedOrFreshCorrelation(r *http.Request, key requestcorrelation.Key) (audit.CorrelationID, error) {
	if r != nil && key != (requestcorrelation.Key{}) {
		ids := r.Header.Values(requestcorrelation.InternalIDHeader)
		sigs := r.Header.Values(requestcorrelation.InternalSignatureHeader)
		if len(ids) == 1 && len(sigs) == 1 {
			if trusted, ok := requestcorrelation.Verify(key, ids[0], sigs[0]); ok {
				return audit.CorrelationID(trusted), nil
			}
		}
	}
	return audit.NewCorrelationID()
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
