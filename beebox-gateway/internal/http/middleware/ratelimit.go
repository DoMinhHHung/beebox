package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

const maxBuckets = 8192

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
		l.evictLocked(now)
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

func (l *RateLimiter) evictLocked(now time.Time) {
	for k, b := range l.bucket {
		if now.Sub(b.last) > 2*time.Minute {
			delete(l.bucket, k)
		}
	}
	for len(l.bucket) >= maxBuckets {
		var victim string
		var oldest time.Time
		first := true
		for k, b := range l.bucket {
			if first || b.last.Before(oldest) {
				victim = k
				oldest = b.last
				first = false
			}
		}
		if victim == "" {
			return
		}
		delete(l.bucket, victim)
	}
}

func limitKey(r *http.Request) string {
	project := ""
	if p, ok := ProjectFrom(r); ok {
		project = p.ProjectID
	}
	return clientIP(r) + "|" + project + "|" + pathGroup(r.URL.Path)
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
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
