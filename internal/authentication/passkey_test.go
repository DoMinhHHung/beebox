package authentication

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	testPasskeyAppPublic  = applicationinstance.PublicID("app_123e4567-e89b-42d3-a456-426614174000")
	testPasskeyUserPublic = identity.PublicID("usr_123e4567-e89b-42d3-a456-426614174001")
)

type passkeyPersistenceStub struct {
	credentials []PasskeyCredential
	attemptWrite PasskeyAttemptWrite
	attempt      PasskeyAttempt
	createdID    string
	loadUser     PasskeyProtocolUser
	removeErr    error
}

func (p *passkeyPersistenceStub) ListPasskeyCredentials(context.Context, applicationinstance.InternalID, identity.InternalID) ([]PasskeyCredential, error) {
	return append([]PasskeyCredential(nil), p.credentials...), nil
}
func (p *passkeyPersistenceStub) CreatePasskeyAttempt(_ context.Context, write PasskeyAttemptWrite) (string, error) {
	p.attemptWrite = write
	if p.createdID == "" {
		p.createdID = "pka_123e4567-e89b-42d3-a456-426614174002"
	}
	return p.createdID, nil
}
func (p *passkeyPersistenceStub) ConsumePasskeyAttempt(context.Context, applicationinstance.InternalID, string, string, string) (PasskeyAttempt, error) {
	return p.attempt, nil
}
func (p *passkeyPersistenceStub) CreatePasskeyCredential(_ context.Context, _ PasskeyAttempt, credential PasskeyCredential, _ audit.CorrelationID) (PasskeyCredential, error) {
	credential.PublicID = "pky_123e4567-e89b-42d3-a456-426614174003"
	credential.CreatedAt = time.Unix(100, 0).UTC()
	return credential, nil
}
func (p *passkeyPersistenceStub) LoadPasskeyUserByHandle(context.Context, applicationinstance.InternalID, string, []byte, []byte) (PasskeyProtocolUser, error) {
	return p.loadUser, nil
}
func (p *passkeyPersistenceStub) FinalizePasskeyAuthentication(context.Context, PasskeyAuthFinalize) (PasskeyAuthResult, error) {
	return PasskeyAuthResult{UserPublicID: testPasskeyUserPublic, ApplicationPublicID: testPasskeyAppPublic}, nil
}
func (p *passkeyPersistenceStub) RemovePasskeyCredential(context.Context, PasskeySession, string, audit.CorrelationID) error {
	return p.removeErr
}

type passkeyProtocolStub struct {
	challenge string
	finishErr error
}

func (p passkeyProtocolStub) BeginRegistration(PasskeyProtocolUser, string, string) (json.RawMessage, json.RawMessage, string, error) {
	return json.RawMessage(`{"rp":{"id":"app.example"}}`), json.RawMessage(`{"challenge":"stored"}`), p.challenge, nil
}
func (p passkeyProtocolStub) FinishRegistration(PasskeyProtocolUser, string, string, json.RawMessage, json.RawMessage) (PasskeyCredential, error) {
	if p.finishErr != nil {
		return PasskeyCredential{}, p.finishErr
	}
	return PasskeyCredential{RPID: "app.example", CredentialID: []byte("credential"), CredentialJSON: json.RawMessage(`{"id":"credential"}`)}, nil
}
func (p passkeyProtocolStub) BeginAuthentication(string, string) (json.RawMessage, json.RawMessage, string, error) {
	return json.RawMessage(`{"rpId":"app.example"}`), json.RawMessage(`{"challenge":"stored"}`), p.challenge, nil
}
func (p passkeyProtocolStub) FinishAuthentication(ctx context.Context, _ string, _ string, _ json.RawMessage, _ json.RawMessage, loader func(context.Context, []byte, []byte) (PasskeyProtocolUser, error)) (PasskeyProtocolUser, PasskeyCredential, error) {
	if p.finishErr != nil {
		return PasskeyProtocolUser{}, PasskeyCredential{}, p.finishErr
	}
	user, err := loader(ctx, []byte("credential"), []byte(testPasskeyUserPublic))
	if err != nil {
		return PasskeyProtocolUser{}, PasskeyCredential{}, err
	}
	return user, PasskeyCredential{RPID: "app.example", CredentialID: []byte("credential"), CredentialJSON: json.RawMessage(`{"id":"credential"}`)}, nil
}

func freshPasskeySession(now time.Time) PasskeySession {
	return PasskeySession{
		ApplicationInstanceID: 1,
		ApplicationPublicID:   testPasskeyAppPublic,
		UserID:                2,
		UserPublicID:          testPasskeyUserPublic,
		SessionPublicID:       "ses_123e4567-e89b-42d3-a456-426614174004",
		CreatedAt:             now.Add(-time.Minute),
		IdleExpiresAt:         now.Add(time.Hour),
		ExpiresAt:             now.Add(24 * time.Hour),
	}
}

func TestPasskeyBeginRegistrationBindsAndHashesChallenge(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	rawChallenge := []byte("0123456789abcdef0123456789abcdef")
	challenge := base64.RawURLEncoding.EncodeToString(rawChallenge)
	store := &passkeyPersistenceStub{}
	service := NewPasskeyService(store, passkeyProtocolStub{challenge: challenge})
	service.now = func() time.Time { return now }

	result, err := service.BeginRegistration(context.Background(), freshPasskeySession(now), "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	if result.AttemptID == "" || result.ExpiresIn <= 0 || result.ExpiresIn > int64(PasskeyAttemptTTL/time.Second) {
		t.Fatalf("unexpected result: %+v", result)
	}
	wantHash := sha256.Sum256(rawChallenge)
	if store.attemptWrite.ChallengeHash != wantHash {
		t.Fatal("challenge hash was not persisted")
	}
	if store.attemptWrite.ApplicationInstanceID != 1 || store.attemptWrite.UserID != 2 || store.attemptWrite.SessionPublicID == "" || store.attemptWrite.Origin != "https://app.example" || store.attemptWrite.RPID != "app.example" || store.attemptWrite.Purpose != "registration" {
		t.Fatalf("attempt binding mismatch: %+v", store.attemptWrite)
	}
}

func TestPasskeyRegistrationRequiresRecentAuthentication(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	rawChallenge := []byte("0123456789abcdef0123456789abcdef")
	store := &passkeyPersistenceStub{}
	service := NewPasskeyService(store, passkeyProtocolStub{challenge: base64.RawURLEncoding.EncodeToString(rawChallenge)})
	service.now = func() time.Time { return now }
	current := freshPasskeySession(now)
	current.CreatedAt = now.Add(-SocialLinkFreshness)

	_, err := service.BeginRegistration(context.Background(), current, "https://app.example")
	if !errors.Is(err, ErrPasskeyReverificationRequired) {
		t.Fatalf("got %v", err)
	}
	if store.attemptWrite.Purpose != "" {
		t.Fatal("stale session created an attempt")
	}
}

func TestPasskeyRejectsNonCanonicalOriginShape(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	service := NewPasskeyService(&passkeyPersistenceStub{}, passkeyProtocolStub{challenge: base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))})
	service.now = func() time.Time { return now }

	for _, origin := range []string{"https://app.example/path", "https://user@app.example", "app.example", "https://app.example?x=1"} {
		if _, err := service.BeginRegistration(context.Background(), freshPasskeySession(now), origin); !errors.Is(err, ErrPasskeyInvalidRequest) {
			t.Fatalf("origin %q: got %v", origin, err)
		}
	}
}

func TestPasskeyAuthenticationIsAttemptBoundAndProofFailureFailsClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	attempt := PasskeyAttempt{
		PublicID:              "pka_123e4567-e89b-42d3-a456-426614174002",
		ApplicationInstanceID: 1,
		ApplicationPublicID:   testPasskeyAppPublic,
		Purpose:               "authentication",
		Origin:                "https://app.example",
		RPID:                  "app.example",
		SessionData:           json.RawMessage(`{"challenge":"stored"}`),
		CreatedAt:             now,
		ExpiresAt:             now.Add(PasskeyAttemptTTL),
	}
	store := &passkeyPersistenceStub{attempt: attempt, loadUser: PasskeyProtocolUser{UserID: 2, PublicID: testPasskeyUserPublic}}
	service := NewPasskeyService(store, passkeyProtocolStub{finishErr: errors.New("bad proof")})
	app := applicationinstance.Instance{InternalID: 1, PublicID: testPasskeyAppPublic}

	_, _, _, err := service.VerifyAuthentication(context.Background(), app, attempt.Origin, attempt.PublicID, json.RawMessage(`{"id":"bad"}`))
	if !errors.Is(err, ErrPasskeyProof) {
		t.Fatalf("got %v", err)
	}
}

func TestPasskeyRemovePreservesLastMethodError(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := &passkeyPersistenceStub{removeErr: ErrLastAuthenticationMethod}
	service := NewPasskeyService(store, passkeyProtocolStub{})
	service.now = func() time.Time { return now }
	correlation := audit.CorrelationID{1}

	err := service.Remove(context.Background(), freshPasskeySession(now), "pky_123e4567-e89b-42d3-a456-426614174003", correlation)
	if !errors.Is(err, ErrLastAuthenticationMethod) {
		t.Fatalf("got %v", err)
	}
}
