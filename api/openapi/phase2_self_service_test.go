package openapi

import (
	"os"
	"strings"
	"testing"
)

func TestPhase2SelfServiceAndEmailLinkContract(t *testing.T) {
	content, err := os.ReadFile("v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)

	for _, required := range []string{
		"  /v1/identifiers/emails:",
		"  /v1/identifiers/phones:",
		"  /v1/identifiers/emails/{identifier_id}:",
		"  /v1/identifiers/phones/{identifier_id}:",
		"  /v1/identifiers/emails/{identifier_id}/verification:",
		"  /v1/identifiers/emails/{identifier_id}/verification/confirm:",
		"  /v1/identifiers/phones/{identifier_id}/verification:",
		"  /v1/identifiers/phones/{identifier_id}/verification/confirm:",
		"  /v1/identifiers/emails/{identifier_id}/primary:",
		"  /v1/identifiers/phones/{identifier_id}/primary:",
		"  /v1/profile:",
		"  /v1/sign-ins/email-link:",
		"  /v1/sign-ins/email-link/confirm:",
		"operationId: listEmailIdentifiers",
		"operationId: addEmailIdentifier",
		"operationId: listPhoneIdentifiers",
		"operationId: addPhoneIdentifier",
		"operationId: removeEmailIdentifier",
		"operationId: removePhoneIdentifier",
		"operationId: requestManagedEmailVerification",
		"operationId: confirmManagedEmailVerification",
		"operationId: requestManagedPhoneVerification",
		"operationId: confirmManagedPhoneVerification",
		"operationId: setPrimaryEmailIdentifier",
		"operationId: setPrimaryPhoneIdentifier",
		"operationId: getCurrentProfile",
		"operationId: patchCurrentProfile",
		"operationId: requestEmailLinkSignIn",
		"operationId: confirmEmailLinkSignIn",
		"pattern: '^eml_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
		"pattern: '^phn_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
		"pattern: '^eln_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
		"maximum: 100, default: 20",
		"maxLength: 512",
		"display_name:",
		"given_name:",
		"family_name:",
		"locale:",
		"maxLength: 35",
		"challenge_id:",
		"writeOnly: true",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("P2.10/P2.11 contract missing %q", required)
		}
	}

	normalized := strings.Join(strings.Fields(strings.ToLower(text)), " ")
	for _, semantic := range []string{
		"public eml_ ids are locators only",
		"email equality is not account-linking authority",
		"phone equality is never account-linking authority",
		"only verified ownership is globally unique inside one application",
		"postgresql is the final arbiter for verified ownership under concurrency",
		"identifier_remove reverification",
		"identifier_primary reverification",
		"last usable authentication method",
		"only display_name, given_name, family_name and locale",
		"random 32-byte secret",
		"ten-minute expiry",
		"one-minute resend cooldown",
		"three issues per 15-minute window",
		"secret only in its fragment",
		"mail-scanner get does not transmit or consume authentication authority",
		"secret is accepted only in this post body",
		"active totp returns only the tagged mfa-required result",
		"no ordinary session/access/refresh authority before mfa completion",
		"must not be blindly retried",
	} {
		if !strings.Contains(normalized, semantic) {
			t.Fatalf("P2.10/P2.11 contract missing semantic %q", semantic)
		}
	}

	if got := strings.Count(text, "#/components/parameters/ReverificationGrantHeader"); got != 17 {
		t.Fatalf("protected reverification header references=%d want=17", got)
	}
	if strings.Contains(normalized, "identifier mutation purposes remain reserved") {
		t.Fatal("P2.10 identifier purposes are still described as reserved")
	}
}
