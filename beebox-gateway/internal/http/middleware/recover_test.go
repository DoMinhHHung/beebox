package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecoverDoesNotCrash(t *testing.T) {
	h := Recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("secret-panic-value")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
	raw := rec.Body.String()
	if strings.Contains(raw, "secret-panic-value") {
		t.Fatalf("must not leak panic string: %s", raw)
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body.Error.Code != "internal" {
		t.Fatalf("code=%q", body.Error.Code)
	}
	if body.Error.Message != "internal error" {
		t.Fatalf("message=%q", body.Error.Message)
	}
}

func TestRecoverDiscardsPartialResponse(t *testing.T) {
	h := Recover(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Partial", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("partial-body"))
		panic("after-write")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
	if rec.Header().Get("X-Partial") != "" {
		t.Fatalf("partial header leaked")
	}
	raw := rec.Body.String()
	if strings.Contains(raw, "partial-body") {
		t.Fatalf("partial body leaked: %s", raw)
	}
	if strings.Contains(raw, "after-write") {
		t.Fatalf("panic string leaked: %s", raw)
	}
}

func TestRecoverFlushesSuccess(t *testing.T) {
	h := Recover(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-OK", "1")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d", rec.Code)
	}
	if rec.Header().Get("X-OK") != "1" {
		t.Fatalf("missing header")
	}
	if rec.Body.String() != `{"status":"ok"}` {
		t.Fatalf("body=%q", rec.Body.String())
	}
}
