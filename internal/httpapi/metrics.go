package httpapi

import (
	"net/http"

	beeboxmetrics "github.com/DoMinhHHung/beebox/internal/metrics"
)

type metricsHTTP struct {
	base     http.Handler
	recorder *beeboxmetrics.Recorder
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func WithMetrics(base http.Handler, recorder *beeboxmetrics.Recorder) http.Handler {
	return &metricsHTTP{base: base, recorder: recorder}
}

func (h *metricsHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/metrics" {
		h.recorder.ServeHTTP(w, r)
		return
	}
	operation := metricOperation(r.URL.Path)
	if operation == "" || h.recorder == nil {
		h.base.ServeHTTP(w, r)
		return
	}
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.base.ServeHTTP(recorder, r)
	outcome := "success"
	if recorder.status >= 400 {
		outcome = "failure"
	}
	if recorder.status == http.StatusTooManyRequests {
		outcome = "rate_limited"
	}
	h.recorder.Observe(operation, outcome)
}

func metricOperation(path string) string {
	switch path {
	case "/v1/sign-ups":
		return "signup"
	case "/v1/email-verifications":
		return "verification_issue"
	case "/v1/email-verifications/confirm":
		return "verification_confirm"
	case "/v1/sign-ins":
		return "signin"
	case "/v1/sessions/refresh":
		return "refresh"
	case "/v1/sessions/current":
		return "session_current"
	case "/v1/sessions/sign-out":
		return "signout"
	case "/v1/password-resets":
		return "password_reset_issue"
	case "/v1/password-resets/confirm":
		return "password_reset_confirm"
	default:
		return ""
	}
}
