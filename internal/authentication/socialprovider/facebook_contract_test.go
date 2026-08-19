package socialprovider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/authentication"
)

func TestFacebookAuthorizationContract(t *testing.T) {
	t.Parallel()
	const redirectURL = "https://auth.example.test/v1/social-auth/callback/facebook"
	a, err := newAdapter(adapterConfig{
		provider:     authentication.ProviderFacebook,
		clientID:     "fake-client",
		clientSecret: "fake-secret",
		redirectURL:  redirectURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.UsesPKCE() || a.UsesNonce() {
		t.Fatalf("Facebook PKCE=%v nonce=%v", a.UsesPKCE(), a.UsesNonce())
	}
	raw, err := a.AuthorizationURL("fake-state", "", "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "www.facebook.com" || u.Path != "/v25.0/dialog/oauth" {
		t.Fatalf("Facebook authorization endpoint = %s", u.String())
	}
	want := url.Values{
		"client_id":     {"fake-client"},
		"redirect_uri":  {redirectURL},
		"response_type": {"code"},
		"state":         {"fake-state"},
	}
	if !reflect.DeepEqual(u.Query(), want) {
		t.Fatalf("Facebook authorization query = %v, want %v", u.Query(), want)
	}
	for _, forbidden := range []string{"scope", "nonce", "code_challenge", "code_challenge_method"} {
		if u.Query().Get(forbidden) != "" {
			t.Fatalf("Facebook authorization sent forbidden parameter %q", forbidden)
		}
	}
}

func TestFacebookTokenExchangeContract(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v25.0/oauth/access_token" {
			t.Fatalf("Facebook token request = %s %s", r.Method, r.URL.Path)
		}
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if len(body) != 0 {
				t.Fatalf("Facebook token body = %q", body)
			}
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("Facebook token Authorization = %q", r.Header.Get("Authorization"))
		}
		want := url.Values{
			"client_id":     {"fake-client"},
			"client_secret": {"fake-secret"},
			"code":          {"fake-code"},
			"redirect_uri":  {server.URL + "/callback"},
		}
		if !reflect.DeepEqual(r.URL.Query(), want) {
			t.Fatalf("Facebook token query = %v, want %v", r.URL.Query(), want)
		}
		if r.URL.Query().Get("code_verifier") != "" || r.URL.Query().Get("grant_type") != "" {
			t.Fatalf("Facebook token request added extension parameters: %v", r.URL.Query())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fake-facebook-token","token_type":"bearer","expires_in":12345}`))
	}))
	defer server.Close()

	a := &adapter{
		provider:      authentication.ProviderFacebook,
		clientID:      "fake-client",
		clientSecret:  "fake-secret",
		redirectURL:   server.URL + "/callback",
		tokenURL:      server.URL + "/v25.0/oauth/access_token",
		tokenExchange: tokenExchangeFacebookGETQuery,
		httpClient:    noRedirectClient(server.Client()),
	}
	token, err := a.exchangeFacebook(context.Background(), "fake-code")
	if err != nil || token != "fake-facebook-token" {
		t.Fatalf("Facebook token=%q err=%v", token, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("Facebook token request calls = %d", calls.Load())
	}
}

func TestFacebookExchangeIdentityUsesDedicatedTokenAndGraphRequests(t *testing.T) {
	t.Parallel()
	var tokenCalls, graphCalls atomic.Int32
	var server *httptest.Server
	mux := http.NewServeMux()
	server = httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/v25.0/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		if r.Method != http.MethodGet {
			t.Fatalf("Facebook production token method = %s", r.Method)
		}
		want := url.Values{
			"client_id":     {"fake-client"},
			"client_secret": {"fake-secret"},
			"code":          {"fake-code"},
			"redirect_uri":  {server.URL + "/callback"},
		}
		if !reflect.DeepEqual(r.URL.Query(), want) {
			t.Fatalf("Facebook production token query = %v", r.URL.Query())
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("Facebook production token Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fake-facebook-token","token_type":"bearer","expires_in":12345}`))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		graphCalls.Add(1)
		want := url.Values{
			"fields":       {"id"},
			"access_token": {"fake-facebook-token"},
		}
		if r.Method != http.MethodGet || !reflect.DeepEqual(r.URL.Query(), want) {
			t.Fatalf("Facebook production Graph request = %s %v", r.Method, r.URL.Query())
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("Facebook production Graph Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1234567890123456"}`))
	})

	a := &adapter{
		provider:      authentication.ProviderFacebook,
		clientID:      "fake-client",
		clientSecret:  "fake-secret",
		redirectURL:   server.URL + "/callback",
		tokenURL:      server.URL + "/v25.0/oauth/access_token",
		userInfoURL:   server.URL + "/me?fields=id",
		mode:          subjectTopLevelStringID,
		tokenExchange: tokenExchangeFacebookGETQuery,
		httpClient:    noRedirectClient(server.Client()),
	}
	proof, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if proof.Provider != authentication.ProviderFacebook || proof.Subject != "1234567890123456" {
		t.Fatalf("Facebook proof = %#v", proof)
	}
	if tokenCalls.Load() != 1 || graphCalls.Load() != 1 {
		t.Fatalf("Facebook production calls token=%d graph=%d", tokenCalls.Load(), graphCalls.Load())
	}
}

func TestFacebookTokenFailuresAreSafeAndDoNotRetry(t *testing.T) {
	t.Parallel()
	const secret = "fake-secret-must-not-leak"
	const code = "fake-code-must-not-leak"
	const providerMessage = "synthetic provider error"
	const trace = "TEST_TRACE"

	tests := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "provider shaped error",
			status: http.StatusOK,
			body:   `{"error":{"message":"synthetic provider error","type":"OAuthException","code":190,"error_subcode":463,"fbtrace_id":"TEST_TRACE"}}`,
		},
		{name: "non-2xx", status: http.StatusBadRequest, body: `{"error":{"message":"synthetic provider error"}}`},
		{name: "malformed JSON", status: http.StatusOK, body: `{not-json`},
		{name: "empty token", status: http.StatusOK, body: `{"access_token":"","token_type":"bearer","expires_in":12345}`},
		{name: "oversized body", status: http.StatusOK, body: strings.Repeat("x", providerBodyLimit+1)},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			a := &adapter{
				provider:      authentication.ProviderFacebook,
				clientID:      "fake-client",
				clientSecret:  secret,
				redirectURL:   server.URL + "/callback",
				tokenURL:      server.URL + "/v25.0/oauth/access_token",
				tokenExchange: tokenExchangeFacebookGETQuery,
				httpClient:    noRedirectClient(server.Client()),
			}
			_, err := a.exchangeFacebook(context.Background(), code)
			assertSafeFacebookError(t, err, secret, code, providerMessage, trace)
			if calls.Load() != 1 {
				t.Fatalf("Facebook token failure calls = %d", calls.Load())
			}
		})
	}

	t.Run("redirect is not followed", func(t *testing.T) {
		var sourceCalls, targetCalls atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetCalls.Add(1)
			_, _ = w.Write([]byte(`{"access_token":"must-not-be-reached"}`))
		}))
		defer target.Close()
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sourceCalls.Add(1)
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
		defer source.Close()
		a := &adapter{
			provider:      authentication.ProviderFacebook,
			clientID:      "fake-client",
			clientSecret:  secret,
			redirectURL:   source.URL + "/callback",
			tokenURL:      source.URL + "/v25.0/oauth/access_token",
			tokenExchange: tokenExchangeFacebookGETQuery,
			httpClient:    noRedirectClient(source.Client()),
		}
		_, err := a.exchangeFacebook(context.Background(), code)
		assertSafeFacebookError(t, err, secret, code)
		if sourceCalls.Load() != 1 || targetCalls.Load() != 0 {
			t.Fatalf("Facebook redirect calls source=%d target=%d", sourceCalls.Load(), targetCalls.Load())
		}
	})

	t.Run("transport error", func(t *testing.T) {
		var calls atomic.Int32
		client := &http.Client{
			Timeout: time.Second,
			Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New("synthetic transport failure with " + secret + " " + code)
			}),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		a := &adapter{
			provider:      authentication.ProviderFacebook,
			clientID:      "fake-client",
			clientSecret:  secret,
			redirectURL:   "https://auth.example.test/callback",
			tokenURL:      "https://graph.facebook.com/v25.0/oauth/access_token",
			tokenExchange: tokenExchangeFacebookGETQuery,
			httpClient:    client,
		}
		_, err := a.exchangeFacebook(context.Background(), code)
		assertSafeFacebookError(t, err, secret, code)
		if calls.Load() != 1 {
			t.Fatalf("Facebook transport calls = %d", calls.Load())
		}
	})

	t.Run("timeout", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			time.Sleep(50 * time.Millisecond)
		}))
		defer server.Close()
		client := noRedirectClient(server.Client())
		client.Timeout = 5 * time.Millisecond
		a := &adapter{
			provider:      authentication.ProviderFacebook,
			clientID:      "fake-client",
			clientSecret:  secret,
			redirectURL:   server.URL + "/callback",
			tokenURL:      server.URL + "/v25.0/oauth/access_token",
			tokenExchange: tokenExchangeFacebookGETQuery,
			httpClient:    client,
		}
		_, err := a.exchangeFacebook(context.Background(), code)
		assertSafeFacebookError(t, err, secret, code)
		if calls.Load() != 1 {
			t.Fatalf("Facebook timeout calls = %d", calls.Load())
		}
	})
}

func noRedirectClient(client *http.Client) *http.Client {
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

func assertSafeFacebookError(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err != authentication.ErrSocialProviderProof {
		t.Fatalf("Facebook error = %v", err)
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatalf("Facebook provider detail leaked in error: %v", err)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
