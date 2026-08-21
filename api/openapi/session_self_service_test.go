package openapi

import (
	"os"
	"strings"
	"testing"
)

func TestSessionSelfServiceOpenAPIContract(t *testing.T) {
	content, err := os.ReadFile("v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, required := range []string{
		"  /v1/sessions:\n",
		"operationId: listSessions",
		"  /v1/sessions/{session_id}/revoke:\n",
		"operationId: revokeOwnSession",
		"  /v1/sessions/revoke-others:\n",
		"operationId: revokeOtherSessions",
		"  /v1/sessions/sign-out-everywhere:\n",
		"operationId: signOutEverywhere",
		"SessionListLimit:",
		"SessionListCursor:",
		"SelfServiceSession:",
		"SelfServiceSessionPage:",
		"required: [id, created_at, last_seen_at, idle_expires_at, expires_at, revoked, current]",
		"schema: {type: integer, minimum: 1, maximum: 100, default: 20}",
		"#/components/parameters/ReverificationGrantHeader",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("v1 spec missing P2.9 contract anchor %q", required)
		}
	}
	normalized := strings.Join(strings.Fields(strings.ToLower(text)), " ")
	for _, required := range []string{
		"current application and current authenticated user",
		"opaque cursor",
		"newest-first",
		"session_revoke",
		"session_revoke_others",
		"sign_out_everywhere",
		"selected session id is a locator",
		"current session remains active",
		"including the current session",
		"five-minute",
		"offline",
	} {
		if !strings.Contains(normalized, required) {
			t.Fatalf("v1 spec missing P2.9 semantic %q", required)
		}
	}
	for _, forbidden := range []string{
		"mfa_method",
		"refresh_verifier",
		"device_fingerprint",
		"raw_user_agent",
		"precise_location",
	} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("v1 P2.9 contract leaks forbidden session detail %q", forbidden)
		}
	}
}
