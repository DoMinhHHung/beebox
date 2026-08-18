package socialprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/authentication"
)

func TestTikTokTokenContract(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Accept") != "application/json" {
			t.Fatalf("TikTok token request method=%s content-type=%q accept=%q", r.Method, r.Header.Get("Content-Type"), r.Header.Get("Accept"))
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		want := url.Values{
			"client_key":    {"fake-client"},
			"client_secret": {"fake-secret"},
			"code":          {"fake-code"},
			"grant_type":    {"authorization_code"},
			"redirect_uri":  {server.URL + "/callback"},
		}
		if !reflect.DeepEqual(r.Form, want) {
			t.Fatalf("TikTok token form = %v, want %v", r.Form, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fake-tiktok-access","expires_in":86400,"open_id":"fake-open-id","refresh_expires_in":31536000,"refresh_token":"fake-refresh-discarded","scope":"user.info.basic","token_type":"Bearer"}`))
	}))
	defer server.Close()

	a := &adapter{provider: authentication.ProviderTikTok, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, mode: subjectTikTokOpenID, tikTok: true, httpClient: server.Client()}
	proof, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if proof.Provider != authentication.ProviderTikTok || proof.Subject != "fake-open-id" || calls.Load() != 1 {
		t.Fatalf("proof=%#v calls=%d", proof, calls.Load())
	}
}

func TestTikTokSubjectAndErrorContracts(t *testing.T) {
	t.Parallel()
	t.Run("missing open_id", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"fake-access","expires_in":86400,"scope":"user.info.basic","token_type":"Bearer","email":"fallback@example.test"}`))
		}))
		defer server.Close()
		a := &adapter{provider: authentication.ProviderTikTok, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, mode: subjectTikTokOpenID, tikTok: true, httpClient: server.Client()}
		if _, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{}); err == nil {
			t.Fatal("TikTok accepted missing open_id using another claim")
		}
	})
	t.Run("wrong open_id type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"fake-access","open_id":12345,"token_type":"Bearer"}`))
		}))
		defer server.Close()
		a := &adapter{provider: authentication.ProviderTikTok, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, mode: subjectTikTokOpenID, tikTok: true, httpClient: server.Client()}
		if _, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{}); err == nil {
			t.Fatal("TikTok accepted non-string open_id")
		}
	})
	t.Run("documented error", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"vendor-secret-description","log_id":"fake-log-id"}`))
		}))
		defer server.Close()
		a := &adapter{provider: authentication.ProviderTikTok, clientID: "fake-client", clientSecret: "fake-secret", redirectURL: server.URL + "/callback", tokenURL: server.URL, mode: subjectTikTokOpenID, tikTok: true, httpClient: server.Client()}
		_, err := a.ExchangeIdentity(context.Background(), "fake-code", "", [32]byte{})
		if err != authentication.ErrSocialProviderProof || strings.Contains(err.Error(), "vendor-secret-description") || strings.Contains(err.Error(), "fake-secret") || strings.Contains(err.Error(), "fake-code") {
			t.Fatalf("unsafe TikTok error = %v", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("TikTok token request retried: %d", calls.Load())
		}
	})
}
