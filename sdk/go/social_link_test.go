package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCreateSocialLinkAttemptSendsExistingSessionAuthorityAndDoesNotRetry(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/social-links/attempts" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-BeeBox-Publishable-Key"); got != "pk_test" {
			t.Fatalf("publishable key = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer existing-access-token" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("Origin"); got != "https://app.example.test" {
			t.Fatalf("origin = %q", got)
		}
		var input SocialLinkAttemptRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if input.Provider != SocialProviderGitHub || input.RedirectURL != "https://app.example.test/account/link-complete" {
			t.Fatalf("request body = %#v", input)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"authorization_url":"https://provider.example/authorize?state=lnk_fake","expires_in":420}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := client.CreateSocialLinkAttempt(context.Background(), "existing-access-token", "https://app.example.test", SocialLinkAttemptRequest{
		Provider:    SocialProviderGitHub,
		RedirectURL: "https://app.example.test/account/link-complete",
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempt.AuthorizationURL == "" || attempt.ExpiresIn != 420 {
		t.Fatalf("response = %#v", attempt)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestCreateSocialLinkAttemptDoesNotRetryAmbiguousFailure(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "temporary", http.StatusBadGateway)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateSocialLinkAttempt(context.Background(), "access-token", "https://app.example.test", SocialLinkAttemptRequest{Provider: SocialProviderGoogle, RedirectURL: "https://app.example.test/link"})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls.Load() != 1 {
		t.Fatalf("request retried: calls = %d", calls.Load())
	}
}
