package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSocialAuthSDKEncodesAttemptAndExchange(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("X-BeeBox-Publishable-Key"); got != "pk_test" {
			t.Fatalf("publishable key = %q", got)
		}
		if got := r.Header.Get("Origin"); got != "https://app.example.test" {
			t.Fatalf("origin = %q", got)
		}
		switch r.URL.Path {
		case "/v1/social-auth/attempts":
			var input SocialAuthAttemptRequest
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Fatalf("decode attempt: %v", err)
			}
			if input.Provider != SocialProviderGitHub || input.RedirectURL != "https://app.example.test/auth/callback" || input.CodeChallenge != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || input.CodeChallengeMethod != "S256" {
				t.Fatalf("unexpected attempt: %#v", input)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"authorization_url":"https://github.com/login/oauth/authorize?state=fake","expires_in":600}`))
		case "/v1/social-auth/exchange":
			var input socialAuthExchangeRequest
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Fatalf("decode exchange: %v", err)
			}
			if input.Code != "fake-completion-code" || input.CodeVerifier != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
				t.Fatalf("unexpected exchange: %#v", input)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"fake-access","token_type":"Bearer","expires_in":300,"session_id":"sess_fake","refresh_token":"fake-refresh"}`))
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := client.CreateSocialAuthAttempt(context.Background(), "https://app.example.test", SocialAuthAttemptRequest{
		Provider:            SocialProviderGitHub,
		RedirectURL:         "https://app.example.test/auth/callback",
		CodeChallenge:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempt.ExpiresIn != 600 || attempt.AuthorizationURL == "" {
		t.Fatalf("unexpected attempt response: %#v", attempt)
	}
	pair, err := client.ExchangeSocialAuthCode(context.Background(), "https://app.example.test", "fake-completion-code", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if pair.SessionID != "sess_fake" || pair.RefreshToken != "fake-refresh" {
		t.Fatalf("unexpected token response: %#v", pair)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestExchangeSocialAuthCodeDoesNotRetry(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "temporary", http.StatusBadGateway)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ExchangeSocialAuthCode(context.Background(), "https://app.example.test", "fake-code", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err == nil {
		t.Fatal("expected error")
	}
	if calls.Load() != 1 {
		t.Fatalf("exchange retried: calls = %d", calls.Load())
	}
}
