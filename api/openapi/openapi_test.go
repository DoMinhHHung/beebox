package openapi

import (
	"os"
	"strings"
	"testing"
)

func TestPhase1OpenAPIContract(t *testing.T) {
	content, err := os.ReadFile("v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.HasPrefix(text, "openapi: 3.1.0\n") {
		t.Fatal("v1 spec is not OpenAPI 3.1.0")
	}
	if strings.Contains(text, "\t") {
		t.Fatal("v1 spec contains tab indentation")
	}
	for _, required := range []string{
		"  /.well-known/jwks.json:",
		"  /v1/sign-ups:",
		"  /v1/email-verifications:",
		"  /v1/email-verifications/confirm:",
		"  /v1/sign-ins:",
		"  /v1/sessions/refresh:",
		"  /v1/sessions/current:",
		"  /v1/sessions/sign-out:",
		"  /v1/backend/sessions/{session_id}:",
		"  /v1/backend/sessions/{session_id}/revoke:",
		"  /v1/password-resets:",
		"  /v1/password-resets/confirm:",
		"    publishableKey:",
		"    bearerAuth:",
		"    secretKey:",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("v1 spec missing required contract anchor %q", required)
		}
	}
	for _, forbidden := range []string{"application_instance_id", "password_hash", "refresh_verifier", "BIGINT"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("v1 spec leaks internal contract term %q", forbidden)
		}
	}
}
