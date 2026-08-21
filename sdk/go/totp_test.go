package beebox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTOTPSDKLifecycleUsesTrustedHeadersAndExactRoutes(t *testing.T) {
	var seen = map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-BeeBox-Publishable-Key") != "pk_test" || r.Header.Get("Origin") != "https://app.example" {
			t.Fatalf("headers=%v", r.Header)
		}
		seen[r.Method+" "+r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/mfa/totp/enrollments":
			if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get(ReverificationHeader) != "reverify" {
				t.Fatalf("headers=%v", r.Header)
			}
			_, _ = w.Write([]byte(`{"enrollment_id":"mfe_test","secret":"SETUPSECRET","otpauth_uri":"otpauth://totp/test","expires_in":600}`))
		case "POST /v1/mfa/totp/enrollments/confirm":
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["enrollment_id"] != "mfe_test" || body["code"] != "123456" {
				t.Fatalf("body=%v", body)
			}
			_, _ = w.Write([]byte(`{"id":"mfc_test","created_at":"2026-08-20T00:00:00Z","recovery_codes":["01234-56789-ABCDE-FGHJK-MNPQRS"]}`))
		case "GET /v1/mfa/totp":
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"enabled":true,"credential_id":"mfc_test"}`))
		case "POST /v1/mfa/totp/complete":
			if r.Header.Get("Authorization") != "" {
				t.Fatalf("pending completion must not use ordinary session authorization")
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["pending_mfa_token"] != "mfp.token" || body["code"] != "654321" {
				t.Fatalf("body=%v", body)
			}
			_, _ = w.Write([]byte(`{"status":"authenticated","session":{"id":"ses_test"},"access_token":"access-new","token_type":"Bearer","expires_in":300,"session_id":"ses_test","refresh_token":"refresh"}`))
		case "POST /v1/mfa/recovery-codes/complete":
			if r.Header.Get("Authorization") != "" {
				t.Fatalf("recovery completion must not use ordinary session authorization")
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["pending_mfa_token"] != "mfp.recovery" || body["code"] != "01234-56789-ABCDE-FGHJK-MNPQRS" {
				t.Fatalf("body=%v", body)
			}
			_, _ = w.Write([]byte(`{"status":"authenticated","session":{"id":"ses_recovery"},"access_token":"access-recovery","token_type":"Bearer","expires_in":300,"session_id":"ses_recovery","refresh_token":"refresh-recovery"}`))
		case "GET /v1/mfa/recovery-codes":
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"available":true,"remaining":8}`))
		case "POST /v1/mfa/recovery-codes/regenerate":
			if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get(ReverificationHeader) != "reverify" {
				t.Fatalf("headers=%v", r.Header)
			}
			_, _ = w.Write([]byte(`{"recovery_codes":["01234-56789-ABCDE-FGHJK-MNPQRS"]}`))
		case "POST /v1/mfa/totp/replacements":
			if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get(ReverificationHeader) != "reverify" {
				t.Fatalf("headers=%v", r.Header)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["recovery_code"] != "01234-56789-ABCDE-FGHJK-MNPQRS" {
				t.Fatalf("body=%v", body)
			}
			_, _ = w.Write([]byte(`{"enrollment_id":"mfe_replacement","secret":"REPLACEMENTSECRET","otpauth_uri":"otpauth://totp/replacement","expires_in":600}`))
		case "POST /v1/mfa/totp/replacements/confirm":
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["enrollment_id"] != "mfe_replacement" || body["code"] != "111111" {
				t.Fatalf("body=%v", body)
			}
			_, _ = w.Write([]byte(`{"id":"mfc_replacement","created_at":"2026-08-20T00:00:00Z","recovery_codes":["ABCDE-FGHJK-MNPQR-STVWXYZ-012345"]}`))
		case "DELETE /v1/mfa/totp":
			if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get(ReverificationHeader) != "reverify" {
				t.Fatalf("headers=%v", r.Header)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if enrollment, err := client.StartTOTPEnrollment(ctx, "https://app.example", "access", "reverify"); err != nil || enrollment.Secret != "SETUPSECRET" {
		t.Fatalf("enrollment=%+v err=%v", enrollment, err)
	}
	if credential, err := client.ConfirmTOTPEnrollment(ctx, "https://app.example", "access", "mfe_test", "123456"); err != nil || credential.ID != "mfc_test" || len(credential.RecoveryCodes) != 1 {
		t.Fatalf("credential=%+v err=%v", credential, err)
	}
	if state, err := client.TOTPState(ctx, "https://app.example", "access"); err != nil || !state.Enabled || state.CredentialID != "mfc_test" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	if pair, err := client.CompleteTOTPAuthentication(ctx, "https://app.example", "mfp.token", "654321"); err != nil || pair.AccessToken != "access-new" || pair.RefreshToken != "refresh" {
		t.Fatalf("pair=%+v err=%v", pair, err)
	}
	if pair, err := client.CompleteRecoveryCodeAuthentication(ctx, "https://app.example", "mfp.recovery", "01234-56789-ABCDE-FGHJK-MNPQRS"); err != nil || pair.AccessToken != "access-recovery" || pair.RefreshToken != "refresh-recovery" {
		t.Fatalf("recovery pair=%+v err=%v", pair, err)
	}
	if state, err := client.RecoveryCodeState(ctx, "https://app.example", "access"); err != nil || !state.Available || state.Remaining != 8 {
		t.Fatalf("recovery state=%+v err=%v", state, err)
	}
	if set, err := client.RegenerateRecoveryCodes(ctx, "https://app.example", "access", "reverify"); err != nil || len(set.RecoveryCodes) != 1 {
		t.Fatalf("recovery set=%+v err=%v", set, err)
	}
	if enrollment, err := client.StartTOTPReplacement(ctx, "https://app.example", "access", "reverify", "01234-56789-ABCDE-FGHJK-MNPQRS"); err != nil || enrollment.EnrollmentID != "mfe_replacement" || enrollment.Secret != "REPLACEMENTSECRET" {
		t.Fatalf("replacement enrollment=%+v err=%v", enrollment, err)
	}
	if credential, err := client.ConfirmTOTPReplacement(ctx, "https://app.example", "access", "mfe_replacement", "111111"); err != nil || credential.ID != "mfc_replacement" || len(credential.RecoveryCodes) != 1 {
		t.Fatalf("replacement credential=%+v err=%v", credential, err)
	}
	if err := client.RemoveTOTP(ctx, "https://app.example", "access", "reverify"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"POST /v1/mfa/totp/enrollments",
		"POST /v1/mfa/totp/enrollments/confirm",
		"GET /v1/mfa/totp",
		"POST /v1/mfa/totp/complete",
		"POST /v1/mfa/recovery-codes/complete",
		"GET /v1/mfa/recovery-codes",
		"POST /v1/mfa/recovery-codes/regenerate",
		"POST /v1/mfa/totp/replacements",
		"POST /v1/mfa/totp/replacements/confirm",
		"DELETE /v1/mfa/totp",
	} {
		if seen[key] != 1 {
			t.Fatalf("%s calls=%d", key, seen[key])
		}
	}
}

func TestSDKDecodesPendingMFAWithoutInventingSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"mfa_required","pending_mfa_token":"mfp.token","expires_at":"2026-08-20T00:05:00Z","available_methods":["totp","recovery_code"]}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pk_test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SignIn(context.Background(), "user@example.com", "password")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "mfa_required" || result.PendingMFAToken != "mfp.token" || result.ExpiresAt != "2026-08-20T00:05:00Z" || len(result.AvailableMethods) != 2 || result.AvailableMethods[0] != "totp" || result.AvailableMethods[1] != "recovery_code" {
		t.Fatalf("result=%+v", result)
	}
	if result.AccessToken != "" || result.RefreshToken != "" || result.SessionID != "" || result.Session != nil {
		t.Fatalf("pending MFA response invented ordinary session material: %+v", result)
	}
}
