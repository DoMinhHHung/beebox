package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-apperror"
)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type RateLimiter struct {
	rps    float64
	burst  float64
	now    func() time.Time
	mu     sync.Mutex
	bucket map[string]*tokenBucket
}

func NewRateLimiter(rps float64, burst int) *RateLimiter {
	if rps <= 0 {
		rps = 20
	}
	if burst <= 0 {
		burst = 40
	}
	return &RateLimiter{
		rps:    rps,
		burst:  float64(burst),
		now:    time.Now,
		bucket: map[string]*tokenBucket{},
	}
}

func (l *RateLimiter) Allow(key string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.bucket[key]
	if !ok {
		l.bucket[key] = &tokenBucket{tokens: l.burst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rps
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isHealth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if !l.Allow(limitKey(r)) {
			apperror.WriteJSON(w, apperror.New(apperror.CodeTooManyRequests, "too many requests"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isHealth(path string) bool {
	return strings.HasPrefix(path, "/health/")
}

func limitKey(r *http.Request) string {
	ip := clientIP(r)
	project := strings.TrimSpace(r.Header.Get("X-BeeBox-Publishable-Key"))
	if project == "" {
		project = strings.TrimSpace(r.Header.Get("X-BeeBox-Project-Slug"))
	}
	if project == "" {
		project = r.Host
	}
	return ip + "|" + project + "|" + pathGroup(r.URL.Path)
}

func pathGroup(path string) string {
	switch {
	case strings.HasPrefix(path, "/v1/plans"):
		return "plans"
	case strings.HasPrefix(path, "/v1/projects"), strings.HasPrefix(path, "/v1/accounts"):
		return "control"
	case strings.HasPrefix(path, "/v1/client/config"):
		return "config"
	default:
		return "other"
	}
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if p := strings.TrimSpace(parts[0]); p != "" {
			return p
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
