package passkeywebauthn

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func protocolTestUser() authentication.PasskeyProtocolUser {
	return authentication.PasskeyProtocolUser{
		UserID:   1,
		PublicID: identity.PublicID("usr_123e4567-e89b-42d3-a456-426614174001"),
	}
}

func TestBeginPasskeyProtocolRequiresResidentCredentialAndUserVerification(t *testing.T) {
	p := New()
	registration, regSession, regChallenge, err := p.BeginRegistration(protocolTestUser(), "app.example", "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	if regChallenge == "" || len(regSession) == 0 {
		t.Fatal("registration ceremony did not return server state")
	}
	var creation map[string]any
	if err := json.Unmarshal(registration, &creation); err != nil {
		t.Fatal(err)
	}
	selection, ok := creation["authenticatorSelection"].(map[string]any)
	if !ok || selection["residentKey"] != "required" || selection["userVerification"] != "required" {
		t.Fatalf("authenticatorSelection=%v", creation["authenticatorSelection"])
	}

	authenticationOptions, authSession, authChallenge, err := p.BeginAuthentication("app.example", "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	if authChallenge == "" || len(authSession) == 0 {
		t.Fatal("authentication ceremony did not return server state")
	}
	var assertion map[string]any
	if err := json.Unmarshal(authenticationOptions, &assertion); err != nil {
		t.Fatal(err)
	}
	if assertion["rpId"] != "app.example" || assertion["userVerification"] != "required" {
		t.Fatalf("assertion options=%v", assertion)
	}
}

func TestPasskeyProtocolRejectsWrongRPAndMalformedRegistrationResponse(t *testing.T) {
	p := New()
	_, sessionJSON, _, err := p.BeginRegistration(protocolTestUser(), "app.example", "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		t.Fatal(err)
	}
	sessionData.RelyingPartyID = "evil.example"
	wrongRP, err := json.Marshal(sessionData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.FinishRegistration(protocolTestUser(), "app.example", "https://app.example", wrongRP, json.RawMessage(`{}`)); !errors.Is(err, authentication.ErrPasskeyProof) {
		t.Fatalf("wrong RP error=%v", err)
	}
	if _, err := p.FinishRegistration(protocolTestUser(), "app.example", "https://app.example", sessionJSON, json.RawMessage(`{"id":`)); !errors.Is(err, authentication.ErrPasskeyProof) {
		t.Fatalf("malformed response error=%v", err)
	}
}

func TestPasskeyProtocolRejectsWrongRPAndMalformedAuthenticationWithoutLoadingCredential(t *testing.T) {
	p := New()
	_, sessionJSON, _, err := p.BeginAuthentication("app.example", "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	loaderCalls := 0
	loader := func(context.Context, []byte, []byte) (authentication.PasskeyProtocolUser, error) {
		loaderCalls++
		return protocolTestUser(), nil
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		t.Fatal(err)
	}
	sessionData.RelyingPartyID = "evil.example"
	wrongRP, err := json.Marshal(sessionData)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.FinishAuthentication(context.Background(), "app.example", "https://app.example", wrongRP, json.RawMessage(`{}`), loader); !errors.Is(err, authentication.ErrPasskeyProof) {
		t.Fatalf("wrong RP error=%v", err)
	}
	if loaderCalls != 0 {
		t.Fatalf("loader called for wrong RP: %d", loaderCalls)
	}
	if _, _, err := p.FinishAuthentication(context.Background(), "app.example", "https://app.example", sessionJSON, json.RawMessage(`{"rawId":`), loader); !errors.Is(err, authentication.ErrPasskeyProof) {
		t.Fatalf("malformed assertion error=%v", err)
	}
	if loaderCalls != 0 {
		t.Fatalf("loader called for malformed assertion: %d", loaderCalls)
	}
}

func TestPasskeyProtocolRejectsInvalidStoredCredentialAndUserHandle(t *testing.T) {
	p := New()
	badUser := protocolTestUser()
	badUser.Credentials = []authentication.PasskeyCredential{{CredentialJSON: json.RawMessage(`{"id":`), CredentialID: []byte("id")}}
	if _, _, _, err := p.BeginRegistration(badUser, "app.example", "https://app.example"); !errors.Is(err, authentication.ErrPasskeyProof) {
		t.Fatalf("invalid stored credential error=%v", err)
	}
	if _, err := makeUser(authentication.PasskeyProtocolUser{UserID: 1}); !errors.Is(err, authentication.ErrPasskeyProof) {
		t.Fatalf("invalid handle error=%v", err)
	}
}
