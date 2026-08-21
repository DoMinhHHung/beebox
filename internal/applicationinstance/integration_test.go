package applicationinstance

import (
	"context"
	"errors"
	"testing"
)

type integrationStub struct {
	material    CredentialMaterial
	kind        CredentialKind
	credential  Credential
	hash        []byte
	loadErr     error
	finalizeErr error
	origin      string
	correlation CorrelationID
	finalized   bool
	rotated     bool
}

func (s *integrationStub) CreateCredential(_ context.Context, _ InternalID, kind CredentialKind, material CredentialMaterial, correlation CorrelationID) (Credential, error) {
	s.kind = kind
	s.material = material
	s.correlation = correlation
	return Credential{PublicID: material.PublicID, Kind: kind, ApplicationInstanceID: 1}, nil
}

func (s *integrationStub) RotateCredential(_ context.Context, appID InternalID, _ CredentialPublicID, kind CredentialKind, material CredentialMaterial, _, _ CorrelationID) (Credential, error) {
	s.rotated = true
	s.kind = kind
	s.material = material
	return Credential{PublicID: material.PublicID, Kind: kind, ApplicationInstanceID: appID}, nil
}

func (s *integrationStub) RevokeCredential(_ context.Context, _ InternalID, _ CredentialPublicID, correlation CorrelationID) error {
	s.correlation = correlation
	return nil
}

func (*integrationStub) ResolvePublishable(context.Context, string) (Instance, error) {
	return Instance{InternalID: 1}, nil
}

func (s *integrationStub) LoadSecretCredential(context.Context, string) (Credential, []byte, error) {
	return s.credential, s.hash, s.loadErr
}

func (s *integrationStub) FinalizeSecretCredential(context.Context, string, []byte) (Credential, error) {
	s.finalized = true
	if s.finalizeErr != nil {
		return Credential{}, s.finalizeErr
	}
	return s.credential, nil
}

func (s *integrationStub) AddAllowedOrigin(_ context.Context, _ InternalID, origin string, correlation CorrelationID) (AllowedOrigin, error) {
	s.origin = origin
	s.correlation = correlation
	return AllowedOrigin{CanonicalOrigin: origin}, nil
}

func TestCredentialFormatsSecretVerificationAndRotation(t *testing.T) {
	stub := &integrationStub{}
	service := NewIntegrationService(stub)

	cred, publishable, err := service.CreateCredential(context.Background(), 1, CredentialKindPublishable)
	if err != nil {
		t.Fatal(err)
	}
	if !cred.PublicID.Valid() || !validPublishableKey(publishable) || stub.material.SecretHash != nil {
		t.Fatal("invalid publishable credential material")
	}
	if stub.correlation == (CorrelationID{}) {
		t.Fatal("credential creation omitted audit correlation")
	}

	secretCred, secret, err := service.CreateCredential(context.Background(), 1, CredentialKindSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !secretCred.PublicID.Valid() || len(stub.material.SecretHash) != 32 || secret == "" {
		t.Fatal("invalid secret credential material")
	}
	_, raw, ok := parseSecretKey(secret)
	if !ok || len(raw) != 32 {
		t.Fatal("secret key parse failed")
	}
	stub.credential = Credential{PublicID: secretCred.PublicID, ApplicationInstanceID: 1, Kind: CredentialKindSecret}
	stub.hash = append([]byte(nil), stub.material.SecretHash...)

	if _, err := service.AuthenticateSecret(context.Background(), secret); err != nil {
		t.Fatalf("AuthenticateSecret() = %v", err)
	}
	if !stub.finalized {
		t.Fatal("successful secret verification skipped current-state finalization")
	}

	stub.finalized = false
	replacement := "A"
	if secret[len(secret)-1] == 'A' {
		replacement = "Q"
	}
	bad := secret[:len(secret)-1] + replacement
	if bad == secret {
		t.Fatal("bad secret fixture did not change secret material")
	}
	if _, err := service.AuthenticateSecret(context.Background(), bad); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("bad secret err = %v", err)
	}
	if stub.finalized {
		t.Fatal("wrong secret reached state finalization")
	}

	rotated, rotatedRaw, err := service.RotateCredential(context.Background(), 1, secretCred.PublicID, CredentialKindSecret)
	if err != nil {
		t.Fatalf("RotateCredential() = %v", err)
	}
	if !stub.rotated || rotated.PublicID == secretCred.PublicID || rotatedRaw == "" {
		t.Fatal("credential rotation did not create distinct secret material")
	}
}

func TestCanonicalizeOrigin(t *testing.T) {
	got, err := CanonicalizeOrigin("HTTPS://Example.COM:8443/")
	if err != nil || got != "https://example.com:8443" {
		t.Fatalf("origin = %q err = %v", got, err)
	}
	for _, raw := range []string{
		"https://example.com/path",
		"https://example.com?q=1",
		"https://example.com/#x",
		"ftp://example.com",
		" https://example.com",
	} {
		if _, err := CanonicalizeOrigin(raw); !errors.Is(err, ErrInvalidOrigin) {
			t.Fatalf("%q accepted", raw)
		}
	}
}
