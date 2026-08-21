package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionSelfServiceSDKParity(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("X-BeeBox-Publishable-Key") != "bb_pk_test" || r.Header.Get("Authorization") != "Bearer access" {
			t.Fatalf("authority headers publishable=%q authorization=%q", r.Header.Get("X-BeeBox-Publishable-Key"), r.Header.Get("Authorization"))
		}
		switch requests {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/v1/sessions" || r.URL.Query().Get("limit") != "20" || r.URL.Query().Get("cursor") != "next" {
				t.Fatalf("list request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(SessionPage{Items: []UserSession{{ID: "ses_test", Current: true}}, NextCursor: "later"})
		case 2:
			assertSessionReverificationSDKRequest(t, r, "/v1/sessions/ses_test/revoke")
			w.WriteHeader(http.StatusNoContent)
		case 3:
			assertSessionReverificationSDKRequest(t, r, "/v1/sessions/revoke-others")
			_ = json.NewEncoder(w).Encode(StatusResponse{Status: "other_sessions_revoked"})
		case 4:
			assertSessionReverificationSDKRequest(t, r, "/v1/sessions/sign-out-everywhere")
			_ = json.NewEncoder(w).Encode(StatusResponse{Status: "signed_out_everywhere"})
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "bb_pk_test")
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListSessions(context.Background(), "access", 20, "next")
	if err != nil || len(page.Items) != 1 || !page.Items[0].Current || page.NextCursor != "later" {
		t.Fatalf("ListSessions() page=%+v err=%v", page, err)
	}
	if err := client.RevokeOwnSession(context.Background(), "https://app.example", "access", "grant", "ses_test"); err != nil {
		t.Fatal(err)
	}
	if err := client.RevokeOtherSessions(context.Background(), "https://app.example", "access", "grant"); err != nil {
		t.Fatal(err)
	}
	if err := client.SignOutEverywhere(context.Background(), "https://app.example", "access", "grant"); err != nil {
		t.Fatal(err)
	}
}

func assertSessionReverificationSDKRequest(t *testing.T, r *http.Request, path string) {
	t.Helper()
	if r.Method != http.MethodPost || r.URL.Path != path {
		t.Fatalf("mutation request = %s %s want POST %s", r.Method, r.URL.Path, path)
	}
	if r.Header.Get("Origin") != "https://app.example" || r.Header.Get(ReverificationHeader) != "grant" {
		t.Fatalf("reverification headers origin=%q grant=%q", r.Header.Get("Origin"), r.Header.Get(ReverificationHeader))
	}
}
