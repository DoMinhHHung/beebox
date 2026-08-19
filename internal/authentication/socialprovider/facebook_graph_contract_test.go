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

func TestFacebookGraphSubjectUsesQueryTokenAndOnlyID(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/me" {
			t.Fatalf("Facebook Graph request = %s %s", r.Method, r.URL.Path)
		}
		want := url.Values{
			"fields":       {"id"},
			"access_token": {"fake-facebook-token"},
		}
		if !reflect.DeepEqual(r.URL.Query(), want) {
			t.Fatalf("Facebook Graph query = %v, want %v", r.URL.Query(), want)
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("Facebook Graph Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"34567"}`))
	}))
	defer server.Close()

	a := &adapter{
		provider:    authentication.ProviderFacebook,
		userInfoURL: server.URL + "/me?fields=id",
		mode:        subjectTopLevelStringID,
		httpClient:  noRedirectClient(server.Client()),
	}
	subject, err := a.subjectFromFacebook(context.Background(), "fake-facebook-token")
	if err != nil || subject != "34567" {
		t.Fatalf("Facebook subject=%q err=%v", subject, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("Facebook Graph calls = %d", calls.Load())
	}
}

func TestFacebookGraphSubjectRejectsInvalidIDWithoutFallback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "missing", body: `{}`},
		{name: "empty", body: `{"id":""}`},
		{name: "numeric JSON", body: `{"id":1234567890123456}`},
		{name: "null", body: `{"id":null}`},
		{name: "email only", body: `{"email":"fallback@example.test"}`},
		{name: "name only", body: `{"name":"Fallback"}`},
		{name: "profile only", body: `{"picture":{"data":{"url":"https://ignored.example.test/avatar"}}}`},
		{name: "oversized", body: `{"id":"` + strings.Repeat("f", 513) + `"}`},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			a := &adapter{
				provider:    authentication.ProviderFacebook,
				userInfoURL: server.URL + "/me?fields=id",
				mode:        subjectTopLevelStringID,
				httpClient:  noRedirectClient(server.Client()),
			}
			_, err := a.subjectFromFacebook(context.Background(), "fake-facebook-token")
			assertSafeFacebookError(t, err, "fake-facebook-token", "fallback@example.test", "Fallback")
			if calls.Load() != 1 {
				t.Fatalf("Facebook Graph invalid-subject calls = %d", calls.Load())
			}
		})
	}
}

func TestFacebookGraphErrorsAreSafeAndDoNotRetry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "provider shaped error",
			status: http.StatusOK,
			body:   `{"error":{"message":"synthetic graph error","type":"OAuthException","code":190,"error_subcode":463,"fbtrace_id":"TEST_TRACE"}}`,
		},
		{name: "non-2xx", status: http.StatusBadRequest, body: `{"error":{"message":"synthetic graph error"}}`},
		{name: "malformed JSON", status: http.StatusOK, body: `{not-json`},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			a := &adapter{
				provider:    authentication.ProviderFacebook,
				userInfoURL: server.URL + "/me?fields=id",
				mode:        subjectTopLevelStringID,
				httpClient:  noRedirectClient(server.Client()),
			}
			_, err := a.subjectFromFacebook(context.Background(), "fake-facebook-token")
			assertSafeFacebookError(t, err, "fake-facebook-token", "synthetic graph error", "TEST_TRACE")
			if calls.Load() != 1 {
				t.Fatalf("Facebook Graph failure calls = %d", calls.Load())
			}
		})
	}
}
