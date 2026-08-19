package authentication

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func TestSocialLinkRequiresFreshExactSessionAndBindsStatePurpose(t *testing.T) {
	t.Parallel()
	appPublicID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	app := applicationinstance.Instance{InternalID: 9, PublicID: appPublicID}
	now := time.Unix(1_800_100_000, 0).UTC()
	store := &fakeSocialLinkStore{}
	provider := &fakeSocialProvider{provider: ProviderGitHub}
	service := NewSocialLinkService(store, fakeRedirectPolicy(true), fakeSocialLinkAdmission{}, fakeSocialRegistry{appID: appPublicID, provider: provider}, nil)
	service.now = func() time.Time { return now }
	current := SocialLinkSession{
		ApplicationInstanceID: app.InternalID,
		UserID:                identity.InternalID(44),
		PublicID:              "ses_11111111-1111-4111-8111-111111111111",
		CreatedAt:             now.Add(-5 * time.Minute),
		IdleExpiresAt:         now.Add(30 * time.Minute),
		ExpiresAt:             now.Add(time.Hour),
	}
	result, err := service.CreateLinkAttempt(context.Background(), app, current, ProviderGitHub, "https://app.example.test/link-complete")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.AuthorizationURL, "state="+SocialLinkStatePrefix) {
		t.Fatalf("authorization URL does not carry link-purpose state: %q", result.AuthorizationURL)
	}
	if result.ExpiresIn != 300 {
		t.Fatalf("expires_in = %d, want 300 from initiating-session freshness deadline", result.ExpiresIn)
	}
	if store.write.UserID != current.UserID || store.write.SessionPublicID != current.PublicID || !store.write.RecentAuthAt.Equal(current.CreatedAt) {
		t.Fatalf("attempt did not bind exact initiating principal/session: %#v", store.write)
	}

	stale := current
	stale.CreatedAt = now.Add(-SocialLinkFreshness)
	_, err = service.CreateLinkAttempt(context.Background(), app, stale, ProviderGitHub, "https://app.example.test/link-complete")
	if !errors.Is(err, ErrSocialLinkReverificationRequired) {
		t.Fatalf("stale session error = %v", err)
	}

	otherApp := current
	otherApp.ApplicationInstanceID = 10
	_, err = service.CreateLinkAttempt(context.Background(), app, otherApp, ProviderGitHub, "https://app.example.test/link-complete")
	if !errors.Is(err, ErrSocialLinkInvalidSession) {
		t.Fatalf("cross-app session error = %v", err)
	}
}

func TestSocialLinkCallbackConsumesBeforeProofAndCannotCrossPurpose(t *testing.T) {
	t.Parallel()
	appPublicID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	secret, hash, err := newSocialSecret()
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeSocialLinkStore{snapshot: SocialLinkAttemptSnapshot{
		AttemptID:             77,
		ApplicationInstanceID: 4,
		ApplicationPublicID:   appPublicID,
		UserID:                51,
		Provider:              ProviderGitHub,
		CanonicalRedirectURL:  "https://app.example.test/link-complete",
		StateHash:             hash,
	}}
	provider := &fakeSocialProvider{provider: ProviderGitHub, assertConsumed: func() bool { return store.consumed }}
	service := NewSocialLinkService(store, fakeRedirectPolicy(true), fakeSocialLinkAdmission{}, fakeSocialRegistry{appID: appPublicID, provider: provider}, nil)
	correlation, _ := audit.NewCorrelationID()
	result, err := service.CompleteLinkCallback(context.Background(), ProviderGitHub, SocialLinkStatePrefix+secret, "provider-code", false, correlation)
	if err != nil {
		t.Fatal(err)
	}
	if result.Failed || !store.consumed || !provider.exchanged || store.final.AttemptID != 77 || store.final.ProviderSubject != "stable-subject" {
		t.Fatalf("callback=%#v consumed=%v exchanged=%v final=%#v", result, store.consumed, provider.exchanged, store.final)
	}

	if _, err := service.CompleteLinkCallback(context.Background(), ProviderGitHub, secret, "provider-code", false, correlation); !errors.Is(err, ErrSocialLinkInvalidState) {
		t.Fatalf("normal social state accepted as link state: %v", err)
	}
	p23 := NewSocialService(&fakeSocialStore{}, fakeRedirectPolicy(true), fakeSocialAdmission{}, fakeSocialRegistry{appID: appPublicID, provider: provider}, nil)
	if _, err := p23.CompleteCallback(context.Background(), ProviderGitHub, SocialLinkStatePrefix+secret, "provider-code", false, correlation); !errors.Is(err, ErrSocialInvalidState) {
		t.Fatalf("link state accepted as P2.3 state: %v", err)
	}
}

func TestSocialLinkProviderDenialIsGenericAndAuditable(t *testing.T) {
	t.Parallel()
	appPublicID, _ := applicationinstance.NewPublicID()
	secret, hash, _ := newSocialSecret()
	store := &fakeSocialLinkStore{snapshot: SocialLinkAttemptSnapshot{
		AttemptID:             88,
		ApplicationInstanceID: 4,
		ApplicationPublicID:   appPublicID,
		UserID:                51,
		Provider:              ProviderGoogle,
		CanonicalRedirectURL:  "https://app.example.test/link-complete",
		StateHash:             hash,
	}}
	provider := &fakeSocialProvider{provider: ProviderGoogle}
	service := NewSocialLinkService(store, fakeRedirectPolicy(true), fakeSocialLinkAdmission{}, fakeSocialRegistry{appID: appPublicID, provider: provider}, nil)
	correlation, _ := audit.NewCorrelationID()
	result, err := service.CompleteLinkCallback(context.Background(), ProviderGoogle, SocialLinkStatePrefix+secret, "", true, correlation)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Failed || provider.exchanged || store.deniedAttemptID != 88 {
		t.Fatalf("result=%#v exchanged=%v denied=%d", result, provider.exchanged, store.deniedAttemptID)
	}
}

func TestSocialLinkProtectorSeparatesP2Point3CiphertextPurpose(t *testing.T) {
	t.Parallel()
	protector, err := NewSocialStateProtector(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	state := [32]byte{7, 8, 9}
	plaintext := []byte(strings.Repeat("v", 43))
	linkCiphertext, err := protector.SealLink(1, ProviderGoogle, state, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protector.Open(1, ProviderGoogle, state, linkCiphertext); err == nil {
		t.Fatal("link-purpose PKCE ciphertext opened with P2.3 AAD")
	}
	authCiphertext, err := protector.Seal(1, ProviderGoogle, state, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protector.OpenLink(1, ProviderGoogle, state, authCiphertext); err == nil {
		t.Fatal("P2.3 PKCE ciphertext opened with link-purpose AAD")
	}
}

type fakeSocialLinkAdmission struct{}

func (fakeSocialLinkAdmission) AllowSocialLinkAttempt(context.Context, applicationinstance.InternalID, identity.InternalID, Provider) error {
	return nil
}

type fakeSocialLinkStore struct {
	write           SocialLinkAttemptWrite
	snapshot        SocialLinkAttemptSnapshot
	final           SocialLinkFinalize
	consumed        bool
	deniedAttemptID int64
}

func (s *fakeSocialLinkStore) CreateSocialLinkAttempt(_ context.Context, write SocialLinkAttemptWrite) error {
	s.write = write
	return nil
}

func (s *fakeSocialLinkStore) ConsumeSocialLinkAttempt(_ context.Context, hash [32]byte, provider Provider) (SocialLinkAttemptSnapshot, error) {
	if s.consumed || hash != s.snapshot.StateHash || provider != s.snapshot.Provider {
		return SocialLinkAttemptSnapshot{}, ErrSocialLinkInvalidState
	}
	s.consumed = true
	return s.snapshot, nil
}

func (s *fakeSocialLinkStore) FinalizeSocialLink(_ context.Context, final SocialLinkFinalize) error {
	s.final = final
	return nil
}

func (s *fakeSocialLinkStore) DenySocialLink(_ context.Context, attemptID int64, _ audit.CorrelationID) error {
	s.deniedAttemptID = attemptID
	return nil
}
