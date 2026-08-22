package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/requestcorrelation"
)

const requestIDHeader = requestcorrelation.PublicHeader

type statusResponse struct {
	Status string `json:"status"`
}

type gatewayPublicError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type gatewayErrorEnvelope struct {
	Error gatewayPublicError `json:"error"`
}

type handler struct {
	cfg             Config
	logger          *slog.Logger
	proxy           *httputil.ReverseProxy
	readinessClient *http.Client
	readinessURL    string
}

func NewHandler(cfg Config, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	transport := newTransport(cfg)
	h := &handler{
		cfg:             cfg,
		logger:          logger,
		readinessClient: &http.Client{Transport: transport, Timeout: cfg.ReadinessTimeout},
		readinessURL:    cfg.IdentityBaseURL.ResolveReference(mustRelativeURL("/health/ready")).String(),
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.IdentityBaseURL)
			pr.Out.Host = pr.In.Host
			stripForwardingHeaders(pr.Out.Header)
			stripCorrelationHeaders(pr.Out.Header)
			setTrustedForwardingHeaders(pr)
			if id, ok := correlationIDFromContext(pr.In.Context()); ok {
				pr.Out.Header.Set(requestcorrelation.PublicHeader, id.String())
				pr.Out.Header.Set(requestcorrelation.InternalIDHeader, id.String())
				pr.Out.Header.Set(requestcorrelation.InternalSignatureHeader, requestcorrelation.Sign(cfg.CorrelationKey, id))
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del(requestcorrelation.InternalIDHeader)
			resp.Header.Del(requestcorrelation.InternalSignatureHeader)
			if id, ok := correlationIDFromContext(resp.Request.Context()); ok {
				resp.Header.Set(requestcorrelation.PublicHeader, id.String())
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.writeProxyError(w, r, err)
		},
	}
	h.proxy = proxy
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", h.live)
	mux.HandleFunc("/health/ready", h.ready)
	mux.Handle("/", http.HandlerFunc(h.proxyRequest))
	return h.withRequestID(h.withAccessLog(mux))
}

func newTransport(cfg Config) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: cfg.ConnectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.ConnectTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
	}
}

func (h *handler) live(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, gatewayErrorEnvelope{Error: gatewayPublicError{Code: "method_not_allowed", Message: "The HTTP method is not allowed.", RequestID: requestIDFromContext(r.Context())}})
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (h *handler) ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, gatewayErrorEnvelope{Error: gatewayPublicError{Code: "method_not_allowed", Message: "The HTTP method is not allowed.", RequestID: requestIDFromContext(r.Context())}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.ReadinessTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.readinessURL, nil)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "not_ready"})
		return
	}
	resp, err := h.readinessClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "not_ready"})
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ready"})
}

func (h *handler) proxyRequest(w http.ResponseWriter, r *http.Request) {
	if h.cfg.MaxBodyBytes > 0 && r.ContentLength > h.cfg.MaxBodyBytes {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		h.writeGatewayError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "The request body is too large.")
		return
	}
	if r.Body != nil {
		body, err := readBoundedRequestBody(r.Context(), r.Body, h.cfg.MaxBodyBytes)
		if err != nil {
			var tooLarge *bodyTooLargeError
			if errors.As(err, &tooLarge) {
				h.writeGatewayError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "The request body is too large.")
				return
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			h.writeGatewayError(w, r, http.StatusBadRequest, "invalid_request", "The request body could not be read.")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.TransferEncoding = nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.RequestTimeout)
	defer cancel()
	h.proxy.ServeHTTP(w, r.WithContext(ctx))
}

type bodyTooLargeError struct{}

func (*bodyTooLargeError) Error() string { return "request body too large" }

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
	}
	n, err := r.r.Read(p)
	if err == nil {
		select {
		case <-r.ctx.Done():
			return n, r.ctx.Err()
		default:
		}
	}
	return n, err
}

func readBoundedRequestBody(ctx context.Context, body io.ReadCloser, limit int64) ([]byte, error) {
	defer body.Close()
	if limit <= 0 {
		return nil, &bodyTooLargeError{}
	}
	payload, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, r: body}, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, &bodyTooLargeError{}
	}
	return payload, nil
}

func (h *handler) writeProxyError(w http.ResponseWriter, r *http.Request, err error) {
	var maxBytesErr *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytesErr):
		h.writeGatewayError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "The request body is too large.")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(r.Context().Err(), context.DeadlineExceeded):
		h.writeGatewayError(w, r, http.StatusGatewayTimeout, "upstream_timeout", "A response was not available before the request timeout.")
	default:
		h.writeGatewayError(w, r, http.StatusBadGateway, "upstream_unavailable", "BeeBox is temporarily unavailable.")
	}
}

func (h *handler) writeGatewayError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, gatewayErrorEnvelope{Error: gatewayPublicError{Code: code, Message: message, RequestID: requestIDFromContext(r.Context())}})
}

func stripForwardingHeaders(header http.Header) {
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Proto", "X-Real-IP"} {
		header.Del(name)
	}
}

func stripCorrelationHeaders(header http.Header) {
	header.Del(requestcorrelation.PublicHeader)
	header.Del(requestcorrelation.InternalIDHeader)
	header.Del(requestcorrelation.InternalSignatureHeader)
}

func setTrustedForwardingHeaders(pr *httputil.ProxyRequest) {
	if host := pr.In.Host; host != "" {
		pr.Out.Header.Set("X-Forwarded-Host", host)
	}
	proto := "http"
	if pr.In.TLS != nil {
		proto = "https"
	}
	pr.Out.Header.Set("X-Forwarded-Proto", proto)
	peer := pr.In.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	peer = strings.TrimSpace(peer)
	if peer != "" {
		pr.Out.Header.Set("X-Forwarded-For", peer)
	}
}

type requestIDContextKey struct{}

func (h *handler) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripCorrelationHeaders(r.Header)
		id, err := requestcorrelation.NewID()
		if err != nil {
			w.Header().Set(requestIDHeader, "request_unavailable")
			writeJSON(w, http.StatusServiceUnavailable, gatewayErrorEnvelope{Error: gatewayPublicError{Code: "service_unavailable", Message: "BeeBox is temporarily unavailable.", RequestID: "request_unavailable"}})
			return
		}
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, id)
		r = r.WithContext(ctx)
		r.Header.Set(requestIDHeader, id.String())
		next.ServeHTTP(&requestIDResponseWriter{ResponseWriter: w, requestID: id.String()}, r)
	})
}

type requestIDResponseWriter struct {
	http.ResponseWriter
	requestID string
}

func (w *requestIDResponseWriter) WriteHeader(status int) {
	w.Header().Set(requestIDHeader, w.requestID)
	w.Header().Del(requestcorrelation.InternalIDHeader)
	w.Header().Del(requestcorrelation.InternalSignatureHeader)
	w.ResponseWriter.WriteHeader(status)
}
func (w *requestIDResponseWriter) Write(p []byte) (int, error) {
	w.Header().Set(requestIDHeader, w.requestID)
	w.Header().Del(requestcorrelation.InternalIDHeader)
	w.Header().Del(requestcorrelation.InternalSignatureHeader)
	return w.ResponseWriter.Write(p)
}
func (w *requestIDResponseWriter) Flush() {
	w.Header().Set(requestIDHeader, w.requestID)
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
func (w *requestIDResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (h *handler) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		h.logger.Info("gateway request", "request_id", requestIDFromContext(r.Context()), "method", r.Method, "path", r.URL.Path, "status", recorder.status, "bytes", recorder.bytes, "duration_ms", time.Since(started).Milliseconds())
	})
}

func correlationIDFromContext(ctx context.Context) (requestcorrelation.ID, bool) {
	id, ok := ctx.Value(requestIDContextKey{}).(requestcorrelation.ID)
	return id, ok && id != (requestcorrelation.ID{})
}
func requestIDFromContext(ctx context.Context) string {
	id, ok := correlationIDFromContext(ctx)
	if !ok {
		return "request_unavailable"
	}
	return id.String()
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}
func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func mustRelativeURL(path string) *url.URL {
	parsed, err := url.Parse(path)
	if err != nil {
		panic(err)
	}
	return parsed
}
