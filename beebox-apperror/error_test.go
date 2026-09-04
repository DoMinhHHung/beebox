package apperror

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusForCode(t *testing.T) {
	cases := map[Code]int{
		CodeInternal:        http.StatusInternalServerError,
		CodeInvalidInput:    http.StatusBadRequest,
		CodeUnauthorized:    http.StatusUnauthorized,
		CodeForbidden:       http.StatusForbidden,
		CodeNotFound:        http.StatusNotFound,
		CodeConflict:        http.StatusConflict,
		CodeTooManyRequests: http.StatusTooManyRequests,
		CodeNotImplemented:  http.StatusNotImplemented,
		CodeModuleDisabled:  http.StatusForbidden,
		CodePlanLimitFields: http.StatusForbidden,
	}
	for code, want := range cases {
		if got := Status(code); got != want {
			t.Fatalf("Status(%q)=%d want %d", code, got, want)
		}
		got := New(code, "m")
		if got.HTTPStatus != want {
			t.Fatalf("New(%q).HTTPStatus=%d want %d", code, got.HTTPStatus, want)
		}
	}
	if Status(Code("unknown")) != http.StatusInternalServerError {
		t.Fatalf("unknown code should map to 500")
	}
}

func TestWrapUnwrap(t *testing.T) {
	root := errors.New("root")
	wrapped := Wrap(root, CodeNotFound, "missing")
	if !errors.Is(wrapped, root) {
		t.Fatalf("Wrap should unwrap to root")
	}
	if wrapped.Unwrap() != root {
		t.Fatalf("Unwrap mismatch")
	}
	if wrapped.Error() != "missing" {
		t.Fatalf("Error()=%q", wrapped.Error())
	}
	if wrapped.Code != CodeNotFound {
		t.Fatalf("Code=%q", wrapped.Code)
	}
}

func TestWriteJSONShape(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, New(CodeNotFound, "nope"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type=%q", ct)
	}
	var body jsonBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body.Error.Code != string(CodeNotFound) || body.Error.Message != "nope" {
		t.Fatalf("body=%+v", body)
	}
}

func TestWriteJSONPlainError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, errors.New("secret-db-dsn"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
	raw, _ := io.ReadAll(rec.Body)
	var body jsonBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body.Error.Code != string(CodeInternal) {
		t.Fatalf("code=%q", body.Error.Code)
	}
	if body.Error.Message == "secret-db-dsn" {
		t.Fatalf("must not leak wrapped string")
	}
}
