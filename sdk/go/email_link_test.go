package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestRequestEmailLink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sign-ins/email-link" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-BeeBox-Publishable-Key") != "pk_test" {
			t.Fatal("publishable key missing")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["email"] != "user@example.com" || body["completion_url"] != "https://app.example/complete" {
			t.Fatalf("body = %#v", body)
		}
		_ = json.NewEncoder(w).Encode(StatusResponse{Status: "accepted"})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.RequestEmailLink(context.Background(), "user@example.com", "https://app.example/complete")
	if err != nil || result.Status != "accepted" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestConfirmEmailLinkUsesOnePOSTWithoutAutomaticRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sign-ins/email-link/confirm" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-BeeBox-Publishable-Key") != "pk_test" {
			t.Fatal("publishable key missing")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["challenge_id"] != "eln_123e4567-e89b-42d3-a456-426614174301" || body["secret"] != "opaque-secret" {
			t.Fatalf("body = %#v", body)
		}
		http.Error(w, "ambiguous upstream response", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ConfirmEmailLink(context.Background(), "eln_123e4567-e89b-42d3-a456-426614174301", "opaque-secret"); err == nil {
		t.Fatal("expected service error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("confirm calls = %d, want 1", got)
	}
}
