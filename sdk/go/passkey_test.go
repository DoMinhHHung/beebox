package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPasskeySDKTransportsOpaqueWebAuthnJSONAndSecurityContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-BeeBox-Publishable-Key") != "pk_test" || r.Header.Get("Origin") != "https://app.example" {
			t.Fatalf("headers=%v", r.Header)
		}
		switch r.URL.Path {
		case "/v1/passkeys/registration/attempts":
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"attempt_id":"pka_123e4567-e89b-42d3-a456-426614174000","public_key":{"challenge":"opaque"},"expires_in":300}`))
		case "/v1/passkeys/authentication/complete":
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if string(body["credential"]) != `{"id":"opaque-browser-value"}` {
				t.Fatalf("credential=%s", body["credential"])
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access-new","token_type":"Bearer","expires_in":300,"session_id":"ses_123e4567-e89b-42d3-a456-426614174001","refresh_token":"refresh"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := client.BeginPasskeyRegistration(context.Background(), "access", "https://app.example")
	if err != nil || attempt.ExpiresIn != 300 || string(attempt.PublicKey) != `{"challenge":"opaque"}` {
		t.Fatalf("attempt=%+v err=%v", attempt, err)
	}
	pair, err := client.CompletePasskeyAuthentication(context.Background(), "https://app.example", PasskeyAuthenticationCompleteRequest{
		AttemptID:  "pka_123e4567-e89b-42d3-a456-426614174000",
		Credential: json.RawMessage(`{"id":"opaque-browser-value"}`),
	})
	if err != nil || pair.AccessToken != "access-new" || pair.RefreshToken != "refresh" {
		t.Fatalf("pair=%+v err=%v", pair, err)
	}
}
