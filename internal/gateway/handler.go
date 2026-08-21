package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const requestIDHeader = "X-Request-ID"

type statusResponse struct {
	Status string `json:"status"`
}

type gatewayErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
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
		cfg:    cfg,
		logger: logger,
		readinessClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.ReadinessTimeout,
		},
		readinessURL: cfg.IdentityBaseURL.ResolveReference(mustRelativeURL("/health/ready")).String(),
	}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.IdentityBaseURL)
			pr.Out.Host = pr.In.Host
			stripForwardingHeaders(pr.Out.Header)
			setTrustedForwardingHeaders(pr)
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
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   cfg.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
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
		writeJSON(w, http.StatusMethodNotAllowed, gatewayErrorResponse{Error: "method_not_allowed", RequestID: requestIDFromContext(r.Context())})
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (h *handler) ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, gatewayErrorResponse{Error: "method_not_allowed", RequestID: requestIDFromContext(r.Context())})
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
	if h.cfg.MaxBodyBytes > 0 {
		if r.ContentLength > h.cfg.MaxBodyBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, gatewayErrorResponse{Error: "request_too_large", RequestID: requestIDFromContext(r.Context())})
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxBodyBytes)
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.RequestTimeout)
	defer cancel()
	h.proxy.ServeHTTP(w, r.WithContext(ctx))
}

func (h *handler) writeProxyError(w http.ResponseWriter, r *http.Request, err error) {
	var maxBytesErr *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytesErr):
		writeJSON(w, http.StatusRequestEntityTooLarge, gatewayErrorResponse{Error: "request_too_large", RequestID: requestIDFromContext(r.Context())})
	case errors.Is(err, context.DeadlineExceeded), errors.Is(r.Context().Err(), context.DeadlineExceeded):
		writeJSON(w, http.StatusGatewayTimeout, gatewayErrorResponse{Error: "upstream_timeout", RequestID: requestIDFromContext(r.Context())})
	default:
		writeJSON(w, http.StatusBadGateway, gatewayErrorResponse{Error: "upstream_unavailable", RequestID: requestIDFromContext(r.Context())})
	}
}

func stripForwardingHeaders(header http.Header) {
	for _, name := range []string{
		"Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Port",
		"X-Forwarded-Proto",
		"X-Real-IP",
	} {
		header.Del(name)
	}
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
		requestID := r.Header.Get(requestIDHeader)
		if !validRequestID(requestID) {
			requestID = newRequestID()
		}
		r.Header.Set(requestIDHeader, requestID)
		w.Header().Set(requestIDHeader, requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *handler) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		h.logger.Info(
			"gateway request",
			"request_id", requestIDFromContext(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"bytes", recorder.bytes,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func requestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

func validRequestID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func newRequestID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return fmt.Sprintf("fallback-%x", time.Now().UnixNano())
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

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

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
