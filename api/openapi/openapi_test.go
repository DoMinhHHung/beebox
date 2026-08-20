package openapi

import (
	"os"
	"strings"
	"testing"
)

func TestPublicOpenAPIContract(t *testing.T) {
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
		"  /v1/sign-ups/phone:",
		"  /v1/sign-ups/phone/confirm:",
		"  /v1/email-verifications:",
		"  /v1/email-verifications/confirm:",
		"  /v1/sign-ins:",
		"  /v1/sign-ins/email-otp:",
		"  /v1/sign-ins/email-otp/confirm:",
		"  /v1/sign-ins/phone-otp:",
		"  /v1/sign-ins/phone-otp/confirm:",
		"operationId: requestEmailOTPSignIn",
		"operationId: confirmEmailOTPSignIn",
		"operationId: requestPhoneSignUpOTP",
		"operationId: confirmPhoneSignUpOTP",
		"operationId: requestPhoneOTPSignIn",
		"operationId: confirmPhoneOTPSignIn",
		"pattern: '^\\+[1-9][0-9]{1,14}$'",
		"pattern: '^[0-9]{6}$'",
		"  /v1/social-auth/attempts:",
		"  /v1/social-links/attempts:",
		"  /v1/social-links:",
		"  /v1/social-links/{social_link_id}:",
		"  /v1/social-auth/callback/{provider}:",
		"  /v1/social-auth/exchange:",
		"operationId: createSocialAuthAttempt",
		"operationId: createSocialLinkAttempt",
		"operationId: listSocialLinks",
		"operationId: unlinkSocialLink",
		"operationId: completeSocialProviderCallback",
		"operationId: exchangeSocialAuthCode",
		"enum: [google, apple, microsoft, github, gitlab, facebook, slack, discord, linkedin, x, tiktok]",
		"code_challenge_method: {type: string, const: S256}",
		"required: [provider, redirect_url]",
		"maximum: 600",
		"SocialLinkUnauthorized:",
		"SocialLinkForbidden:",
		"SocialAccountForbidden:",
		"LastAuthenticationMethod:",
		"reverification_required",
		"last_authentication_method",
		"LinkedSocialAccount:",
		"LinkedSocialAccountPage:",
		"pattern: '^sli_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
		"schema: {type: integer, minimum: 1, maximum: 100, default: 20}",
		"maxItems: 100",
		"  /v1/passkeys/registration/attempts:",
		"  /v1/passkeys/registration/complete:",
		"  /v1/passkeys/authentication/attempts:",
		"  /v1/passkeys/authentication/complete:",
		"  /v1/passkeys:",
		"  /v1/passkeys/{passkey_id}:",
		"operationId: beginPasskeyRegistration",
		"operationId: completePasskeyRegistration",
		"operationId: beginPasskeyAuthentication",
		"operationId: completePasskeyAuthentication",
		"operationId: listPasskeys",
		"operationId: removePasskey",
		"PasskeyAttempt:",
		"PasskeyRegistrationCompleteRequest:",
		"PasskeyAuthenticationCompleteRequest:",
		"Passkey:",
		"PasskeyList:",
		"pattern: '^pka_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
		"pattern: '^pky_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
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
	normalizedText := strings.Join(strings.Fields(strings.ToLower(text)), " ")
	for _, requiredSemantics := range []string{
		"response is intentionally generic",
		"one-time and replay-safe",
		"primary authentication method",
		"strict international e.164",
		"no default region",
		"no user is created before successful possession proof",
		"must not be blindly retried",
		"invalid_credentials",
		"exact application-scoped allowlisted redirect",
		"provider email is not account-link authority",
		"provider access, refresh, and id tokens are never",
		"original rfc 7636 verifier",
		"does not implement mfa",
		"account linking",
		"exact current application, user, and session",
		"does not reset this freshness evidence",
		"callback-time browser session",
		"never merges accounts",
		"beebox_link=success",
		"beebox_error=social_link_failed",
		"listing does not require recent authentication",
		"only the beebox-owned social-link id, provider key, and creation time are returned",
		"refreshing an access token for that same older session does not renew freshness",
		"same idempotent 204 response without revealing ownership",
		"at least one currently usable authentication method must remain",
		"existing ordinary beebox sessions remain active",
		"invalidate pending unexchanged social completion state",
		"does not call provider-side oauth consent or token revocation apis",
		"passkey is a primary authentication method",
		"does not bypass configured mfa",
		"recent authentication is required for passkey registration and removal",
		"private key remains authenticator-owned",
		"webAuthn request and response payloads are opaque json",
		"one-time ceremony",
	} {
		if !strings.Contains(normalizedText, strings.ToLower(requiredSemantics)) {
			t.Fatalf("v1 spec missing authentication semantic %q", requiredSemantics)
		}
	}
	for _, forbidden := range []string{
		"application_instance_id", "password_hash", "refresh_verifier", "challenge_id", "BIGINT",
		"phone_identifier_id", "twilio_sid", "message_sid", "provider_subject", "client_secret",
		"webauthn.Credential", "webauthn.SessionData", "credential_json", "challenge_hash",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("v1 spec leaks internal/provider contract term %q", forbidden)
		}
	}
}
