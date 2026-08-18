package socialprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/authentication"
)

// This test covers only the Graph stable-subject boundary that can be supported
// by current Meta-owned Graph evidence. It deliberately does not claim that the
// Facebook Login authorization/token endpoints in specFor are current-contract
// verified; PR #22 remains blocked until provider-owned Login docs are available.
func TestFacebookGraphSubjectUsesOnlyID(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("fields") != "id" {
			t.Fatalf("Facebook fields = %q", r.URL.Query().Get("fields"))
		}
		if r.Header.Get("Authorization") != "Bearer fake-facebook-token" {
			t.Fatalf("Facebook Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"34567","name":"Ignored","email":"ignored@example.test"}`))
	}))
	defer server.Close()
	a := &adapter{provider: authentication.ProviderFacebook, userInfoURL: server.URL + "?fields=id", mode: subjectTopLevelStringID, httpClient: server.Client()}
	subject, err := a.subjectFromUserInfo(context.Background(), "fake-facebook-token")
	if err != nil || subject != "34567" {
		t.Fatalf("Facebook subject=%q err=%v", subject, err)
	}
}

func TestFacebookGraphSubjectCannotFallBackToProfileClaims(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"name":"Fallback","email":"fallback@example.test"}`,
		`{"id":34567,"name":"Fallback"}`,
		`{"id":"","name":"Fallback"}`,
	} {
		body := body
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			a := &adapter{provider: authentication.ProviderFacebook, userInfoURL: server.URL, mode: subjectTopLevelStringID, httpClient: server.Client()}
			if _, err := a.subjectFromUserInfo(context.Background(), "fake-token"); err == nil {
				t.Fatal("Facebook Graph fallback/wrong-type subject accepted")
			}
		})
	}
}
