package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientSignUpSendsPublishableAndIdempotencyHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sign-ups" || r.Header.Get("X-BeeBox-Publishable-Key") != "bb_pk_test" || r.Header.Get("Idempotency-Key") != "idem-1" {
			t.Fatalf("unexpected request: path=%s publishable=%q idem=%q", r.URL.Path, r.Header.Get("X-BeeBox-Publishable-Key"), r.Header.Get("Idempotency-Key"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(StatusResponse{Status: "verification_pending"})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "bb_pk_test")
	if err != nil {
		t.Fatal(err)
	}
	out, err := client.SignUp(context.Background(), "alice@example.test", "a sufficiently long password", "idem-1")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "verification_pending" {
		t.Fatalf("status = %q", out.Status)
	}
}

func TestClientBackendUsesSecretBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bb_sk_test.secret" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(Session{ID: "ses_test", UserID: "usr_test"})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "bb_pk_test", WithSecretKey("bb_sk_test.secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetSession(context.Background(), "ses_test"); err != nil {
		t.Fatal(err)
	}
}

func TestClientReturnsTypedSafeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"invalid_credentials","message":"invalid","request_id":"req"}}`))
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "bb_pk_test")
	_, err := client.SignIn(context.Background(), "alice@example.test", "secret")
	beeErr, ok := err.(*Error)
	if !ok || beeErr.Code != "invalid_credentials" {
		t.Fatalf("error = %#v", err)
	}
	if strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "secret") {
		t.Fatal("credential leaked through SDK error string")
	}
}
