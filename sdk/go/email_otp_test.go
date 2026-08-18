package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestEmailOTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sign-ins/email-otp" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-BeeBox-Publishable-Key") != "pk_test" {
			t.Fatalf("publishable key missing")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["email"] != "user@example.com" {
			t.Fatalf("body = %v, err = %v", body, err)
		}
		_ = json.NewEncoder(w).Encode(StatusResponse{Status: "accepted"})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.RequestEmailOTP(context.Background(), "user@example.com")
	if err != nil || result.Status != "accepted" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestConfirmEmailOTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sign-ins/email-otp/confirm" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["email"] != "user@example.com" || body["code"] != "123456" {
			t.Fatalf("body = %v, err = %v", body, err)
		}
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access", TokenType: "Bearer", ExpiresIn: 300, SessionID: "ses_test", RefreshToken: "refresh"})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ConfirmEmailOTP(context.Background(), "user@example.com", "123456")
	if err != nil || result.AccessToken != "access" || result.RefreshToken != "refresh" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}
