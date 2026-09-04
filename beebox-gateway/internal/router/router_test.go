package router

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/config"
)

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func testHandler() http.Handler {
	return New(config.Config{RequestTimeout: 2 * time.Second})
}

func TestHealthLiveReady(t *testing.T) {
	h := testHandler()
	for _, path := range []string{"/health/live", "/health/ready"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, rec.Code)
		}
	}
}

func TestUnknownPath(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/no/such/route", nil)
	testHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
	body := decodeError(t, rec.Body)
	if body.Error.Code != "not_found" {
		t.Fatalf("code=%q", body.Error.Code)
	}
}

func TestClientConfigNotImplemented(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/client/config", nil)
	testHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status=%d", rec.Code)
	}
	body := decodeError(t, rec.Body)
	if body.Error.Code != "not_implemented" {
		t.Fatalf("code=%q", body.Error.Code)
	}
}

func decodeError(t *testing.T, r io.Reader) errorBody {
	t.Helper()
	var body errorBody
	if err := json.NewDecoder(r).Decode(&body); err != nil {
		t.Fatalf("json: %v", err)
	}
	return body
}

func TestRequestIDHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	testHandler().ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatalf("missing X-Request-ID")
	}
}

func TestUnknownPathJSONOnly(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	testHandler().ServeHTTP(rec, req)
	raw := rec.Body.String()
	if strings.Contains(strings.ToLower(raw), "stack") {
		t.Fatalf("must not leak stack")
	}
}
