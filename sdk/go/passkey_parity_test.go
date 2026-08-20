package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestPasskeySDKHTTPParityAndOneShotRequests(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.EscapedPath()
		mu.Lock()
		calls[key]++
		mu.Unlock()
		if r.Header.Get("X-BeeBox-Publishable-Key") != "pk_test" || r.Header.Get("Origin") != "https://app.example" {
			t.Fatalf("security headers=%v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		switch key {
		case "POST /v1/passkeys/registration/attempts", "POST /v1/passkeys/authentication/attempts":
			if key == "POST /v1/passkeys/registration/attempts" && r.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("registration authorization=%q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"attempt_id":"pka_123e4567-e89b-42d3-a456-426614174000","public_key":{"opaque":"browser-value"},"expires_in":300}`))
		case "POST /v1/passkeys/registration/complete":
			assertPasskeySDKBody(t, r, "registration")
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("registration complete authorization=%q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"id":"pky_123e4567-e89b-42d3-a456-426614174001","name":"Laptop","created_at":"2026-08-20T00:00:00Z"}`))
		case "POST /v1/passkeys/authentication/complete":
			assertPasskeySDKBody(t, r, "authentication")
			_, _ = w.Write([]byte(`{"access_token":"new-access","token_type":"Bearer","expires_in":300,"session_id":"ses_123e4567-e89b-42d3-a456-426614174002","refresh_token":"refresh"}`))
		case "GET /v1/passkeys":
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("list authorization=%q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"items":[{"id":"pky_123e4567-e89b-42d3-a456-426614174001","name":"Laptop","created_at":"2026-08-20T00:00:00Z"}]}`))
		case "DELETE /v1/passkeys/pky_123e4567-e89b-42d3-a456-426614174001":
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("remove authorization=%q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.BeginPasskeyRegistration(ctx, "access", "https://app.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CompletePasskeyRegistration(ctx, "access", "https://app.example", PasskeyRegistrationCompleteRequest{AttemptID: "pka_123e4567-e89b-42d3-a456-426614174000", Name: "Laptop", Credential: json.RawMessage(`{"id":"opaque-registration"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.BeginPasskeyAuthentication(ctx, "https://app.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CompletePasskeyAuthentication(ctx, "https://app.example", PasskeyAuthenticationCompleteRequest{AttemptID: "pka_123e4567-e89b-42d3-a456-426614174000", Credential: json.RawMessage(`{"id":"opaque-authentication"}`)}); err != nil {
		t.Fatal(err)
	}
	list, err := client.ListPasskeys(ctx, "access", "https://app.example")
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	if err := client.RemovePasskey(ctx, "access", "https://app.example", "pky_123e4567-e89b-42d3-a456-426614174001"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for route, count := range calls {
		if count != 1 {
			t.Fatalf("route %q calls=%d want exactly one", route, count)
		}
	}
	if len(calls) != 6 {
		t.Fatalf("distinct routes=%d calls=%v", len(calls), calls)
	}
}

func assertPasskeySDKBody(t *testing.T, r *http.Request, kind string) {
	t.Helper()
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body["credential"]) == 0 || string(body["credential"]) == "null" {
		t.Fatalf("%s credential was not preserved: %s", kind, body["credential"])
	}
	if len(body["attempt_id"]) == 0 {
		t.Fatalf("%s attempt_id missing", kind)
	}
}
