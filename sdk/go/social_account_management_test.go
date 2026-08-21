package beebox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestListSocialLinksSendsBoundedPaginationAndSessionContext(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/social-links" || r.URL.Query().Get("limit") != "25" || r.URL.Query().Get("cursor") != "opaque" {
			t.Fatalf("request=%s %s", r.Method, r.URL.String())
		}
		if r.Header.Get("X-BeeBox-Publishable-Key") != "pk_test" || r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("Origin") != "https://app.example.test" {
			t.Fatalf("headers=%v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"sli_123e4567-e89b-42d3-a456-426614174000","provider":"github","created_at":"2026-08-20T00:00:00Z"}],"next_cursor":"next"}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListSocialLinks(context.Background(), "access-token", "https://app.example.test", ListSocialLinksOptions{Limit: 25, Cursor: "opaque"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Provider != SocialProviderGitHub || page.NextCursor != "next" {
		t.Fatalf("page=%#v err=%v", page, err)
	}
}

func TestListSocialLinksEscapesReservedCursorCharactersAsQueryData(t *testing.T) {
	t.Parallel()
	const cursor = "opaque?next=a&other=/+%"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/social-links" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		if got := r.URL.Query().Get("cursor"); got != cursor {
			t.Fatalf("cursor=%q want=%q rawQuery=%q", got, cursor, r.URL.RawQuery)
		}
		if got := r.URL.Query().Get("limit"); got != "7" {
			t.Fatalf("limit=%q rawQuery=%q", got, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListSocialLinks(context.Background(), "access-token", "https://app.example.test", ListSocialLinksOptions{Limit: 7, Cursor: cursor}); err != nil {
		t.Fatal(err)
	}
}

func TestUnlinkSocialLinkSendsOneDeleteAndNoProviderMaterial(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	id := "sli_123e4567-e89b-42d3-a456-426614174000"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/social-links/"+id {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("Origin") != "https://app.example.test" || r.Header.Get(ReverificationHeader) != "reverify-unlink" {
			t.Fatalf("headers=%v", r.Header)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UnlinkSocialLink(context.Background(), "access-token", "https://app.example.test", "reverify-unlink", id); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d want=1", calls.Load())
	}
}
