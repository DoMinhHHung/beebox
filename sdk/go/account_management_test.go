package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccountManagementSDKParity(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("X-BeeBox-Publishable-Key") != "bb_pk_test" || r.Header.Get("Authorization") != "Bearer access" || r.Header.Get("Origin") != "https://app.example" {
			t.Fatalf("authority headers publishable=%q authorization=%q origin=%q", r.Header.Get("X-BeeBox-Publishable-Key"), r.Header.Get("Authorization"), r.Header.Get("Origin"))
		}
		sensitive := requests == 2 || requests == 5 || requests == 6 || requests == 8 || requests == 11 || requests == 12
		if sensitive && r.Header.Get(ReverificationHeader) != "grant" {
			t.Fatalf("request %d missing reverification header", requests)
		}
		if !sensitive && r.Header.Get(ReverificationHeader) != "" {
			t.Fatalf("request %d unexpectedly sent reverification header", requests)
		}
		switch requests {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/v1/identifiers/emails" || r.URL.Query().Get("limit") != "20" || r.URL.Query().Get("cursor") != "next" {
				t.Fatalf("email list request=%s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(EmailIdentifierPage{Items: []EmailIdentifier{{ID: "eml_test"}}, NextCursor: "later"})
		case 2:
			assertSDKRequest(t, r, http.MethodPost, "/v1/identifiers/emails")
			_ = json.NewEncoder(w).Encode(EmailIdentifier{ID: "eml_test"})
		case 3:
			assertSDKRequest(t, r, http.MethodPost, "/v1/identifiers/emails/eml_test/verification")
			w.WriteHeader(http.StatusAccepted)
		case 4:
			assertSDKRequest(t, r, http.MethodPost, "/v1/identifiers/emails/eml_test/verification/confirm")
			_ = json.NewEncoder(w).Encode(EmailIdentifier{ID: "eml_test", Verified: true, Primary: true})
		case 5:
			assertSDKRequest(t, r, http.MethodPost, "/v1/identifiers/emails/eml_test/primary")
			w.WriteHeader(http.StatusNoContent)
		case 6:
			assertSDKRequest(t, r, http.MethodDelete, "/v1/identifiers/emails/eml_test")
			w.WriteHeader(http.StatusNoContent)
		case 7:
			assertSDKRequest(t, r, http.MethodGet, "/v1/identifiers/phones")
			_ = json.NewEncoder(w).Encode(PhoneIdentifierPage{Items: []PhoneIdentifier{{ID: "phn_test"}}})
		case 8:
			assertSDKRequest(t, r, http.MethodPost, "/v1/identifiers/phones")
			_ = json.NewEncoder(w).Encode(PhoneIdentifier{ID: "phn_test"})
		case 9:
			assertSDKRequest(t, r, http.MethodPost, "/v1/identifiers/phones/phn_test/verification")
			w.WriteHeader(http.StatusAccepted)
		case 10:
			assertSDKRequest(t, r, http.MethodPost, "/v1/identifiers/phones/phn_test/verification/confirm")
			_ = json.NewEncoder(w).Encode(PhoneIdentifier{ID: "phn_test", Verified: true, Primary: true})
		case 11:
			assertSDKRequest(t, r, http.MethodPost, "/v1/identifiers/phones/phn_test/primary")
			w.WriteHeader(http.StatusNoContent)
		case 12:
			assertSDKRequest(t, r, http.MethodDelete, "/v1/identifiers/phones/phn_test")
			w.WriteHeader(http.StatusNoContent)
		case 13:
			assertSDKRequest(t, r, http.MethodGet, "/v1/profile")
			_ = json.NewEncoder(w).Encode(Profile{})
		case 14:
			assertSDKRequest(t, r, http.MethodPatch, "/v1/profile")
			_ = json.NewEncoder(w).Encode(Profile{})
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "bb_pk_test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	origin := "https://app.example"
	page, err := client.ListEmailIdentifiers(ctx, origin, "access", 20, "next")
	if err != nil || len(page.Items) != 1 || page.NextCursor != "later" {
		t.Fatalf("ListEmailIdentifiers() page=%+v err=%v", page, err)
	}
	if _, err := client.AddEmailIdentifier(ctx, origin, "access", "grant", "user@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := client.RequestEmailIdentifierVerification(ctx, origin, "access", "eml_test"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ConfirmEmailIdentifierVerification(ctx, origin, "access", "eml_test", "123456"); err != nil {
		t.Fatal(err)
	}
	if err := client.SetPrimaryEmailIdentifier(ctx, origin, "access", "grant", "eml_test"); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveEmailIdentifier(ctx, origin, "access", "grant", "eml_test"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListPhoneIdentifiers(ctx, origin, "access", 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AddPhoneIdentifier(ctx, origin, "access", "grant", "+15550001000"); err != nil {
		t.Fatal(err)
	}
	if err := client.RequestPhoneIdentifierVerification(ctx, origin, "access", "phn_test"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ConfirmPhoneIdentifierVerification(ctx, origin, "access", "phn_test", "123456"); err != nil {
		t.Fatal(err)
	}
	if err := client.SetPrimaryPhoneIdentifier(ctx, origin, "access", "grant", "phn_test"); err != nil {
		t.Fatal(err)
	}
	if err := client.RemovePhoneIdentifier(ctx, origin, "access", "grant", "phn_test"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetProfile(ctx, origin, "access"); err != nil {
		t.Fatal(err)
	}
	name := "Bee"
	namePtr := &name
	if _, err := client.PatchProfile(ctx, origin, "access", ProfilePatch{DisplayName: &namePtr}); err != nil {
		t.Fatal(err)
	}
}

func TestAccountManagementSDKRejectsInvalidPageLimit(t *testing.T) {
	client, err := NewClient("https://api.example", "bb_pk_test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListEmailIdentifiers(context.Background(), "https://app.example", "access", 101, ""); err != ErrInvalidClient {
		t.Fatalf("ListEmailIdentifiers() error=%v want ErrInvalidClient", err)
	}
}

func assertSDKRequest(t *testing.T, r *http.Request, method, path string) {
	t.Helper()
	if r.Method != method || r.URL.Path != path {
		t.Fatalf("request=%s %s want %s %s", r.Method, r.URL.Path, method, path)
	}
}
