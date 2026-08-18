package authentication

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
)

func TestSocialProviderVocabularyAndPKCE(t *testing.T) {
	t.Parallel()
	if len(Providers) != 10 {
		t.Fatalf("providers = %d", len(Providers))
	}
	seen := map[Provider]bool{}
	for _, provider := range Providers {
		if !provider.Valid() || seen[provider] {
			t.Fatalf("invalid or duplicate provider %q", provider)
		}
		seen[provider] = true
	}
	verifier := strings.Repeat("a", 43)
	challenge, ok := S256Challenge(verifier)
	if !ok || !ValidS256Challenge(challenge) || challenge == verifier {
		t.Fatalf("invalid S256 challenge %q", challenge)
	}
	for _, invalid := range []string{strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "+"} {
		if ValidPKCEVerifier(invalid) {
			t.Fatalf("accepted invalid verifier %q", invalid)
		}
	}
}

func TestSocialStateProtectorBindsApplicationProviderAndState(t *testing.T) {
	t.Parallel()
	protector, err := NewSocialStateProtector(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	state := [32]byte{1, 2, 3}
	ciphertext, err := protector.Seal(1, ProviderGoogle, state, []byte(strings.Repeat("v", 43)))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := protector.Open(1, ProviderGoogle, state, ciphertext)
	if err != nil || string(plain) != strings.Repeat("v", 43) {
		t.Fatalf("open = %q, %v", plain, err)
	}
	if _, err := protector.Open(2, ProviderGoogle, state, ciphertext); err == nil {
		t.Fatal("ciphertext crossed application binding")
	}
	if _, err := protector.Open(1, ProviderGitHub, state, ciphertext); err == nil {
		t.Fatal("ciphertext crossed provider binding")
	}
	otherState := state
	otherState[0]++
	if _, err := protector.Open(1, ProviderGoogle, otherState, ciphertext); err == nil {
		t.Fatal("ciphertext crossed attempt binding")
	}
}

func TestSocialAttemptAndCallbackUseTrustedStoredState(t *testing.T) {
	t.Parallel()
	appPublicID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	app := applicationinstance.Instance{InternalID: 7, PublicID: appPublicID}
	store := &fakeSocialStore{}
	provider := &fakeSocialProvider{provider: ProviderGitHub}
	service := NewSocialService(store, fakeRedirectPolicy(true), fakeSocialAdmission{}, fakeSocialRegistry{appID: appPublicID, provider: provider}, nil)
	service.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	challenge, _ := S256Challenge(strings.Repeat("c", 43))
	attempt, err := service.CreateAttempt(context.Background(), app, ProviderGitHub, "https://app.example.test/auth/callback", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	if attempt.ExpiresIn != 600 || attempt.AuthorizationURL == "" {
		t.Fatalf("attempt = %#v", attempt)
	}
	if store.write.StateHash == ([32]byte{}) || store.write.ClientCodeChallenge != challenge || store.write.CanonicalRedirectURL != "https://app.example.test/auth/callback" {
		t.Fatalf("stored attempt = %#v", store.write)
	}
	if strings.Contains(attempt.AuthorizationURL, store.rawState) && store.rawState != "" {
		t.Fatal("test store unexpectedly received raw state")
	}

	correlation, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	store.snapshot = SocialAttemptSnapshot{
		ApplicationInstanceID: app.InternalID,
		ApplicationPublicID: app.PublicID,
		Provider: ProviderGitHub,
		CanonicalRedirectURL: "https://app.example.test/auth/callback",
		StateHash: store.write.StateHash,
		ClientCodeChallenge: challenge,
		ExpiresAt: service.now().Add(SocialAttemptTTL),
	}
	provider.assertConsumed = func() bool { return store.consumed }
	callback, err := service.CompleteCallback(context.Background(), ProviderGitHub, store.stateFromAuthorizationURL(attempt.AuthorizationURL), "fake-provider-code", false, correlation)
	if err != nil {
		t.Fatal(err)
	}
	if !store.consumed || !provider.exchanged {
		t.Fatal("state was not consumed before provider proof")
	}
	if callback.RedirectURL != store.snapshot.CanonicalRedirectURL || callback.CompletionCode == "" || callback.Failed {
		t.Fatalf("callback = %#v", callback)
	}
	if store.final.ProviderSubject != "stable-subject" || store.final.Provider != ProviderGitHub || store.final.CompletionCodeHash == ([32]byte{}) {
		t.Fatalf("finalize = %#v", store.final)
	}
}

func TestSocialCallbackProviderDenialDoesNotCallBackchannel(t *testing.T) {
	t.Parallel()
	appPublicID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	state, hash, err := newSocialSecret()
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeSocialProvider{provider: ProviderGoogle}
	store := &fakeSocialStore{snapshot: SocialAttemptSnapshot{
		ApplicationInstanceID: 1,
		ApplicationPublicID: appPublicID,
		Provider: ProviderGoogle,
		CanonicalRedirectURL: "https://app.example.test/callback",
		StateHash: hash,
		ExpiresAt: time.Now().Add(time.Minute),
	}}
	service := NewSocialService(store, fakeRedirectPolicy(true), fakeSocialAdmission{}, fakeSocialRegistry{appID: appPublicID, provider: provider}, nil)
	correlation, _ := audit.NewCorrelationID()
	result, err := service.CompleteCallback(context.Background(), ProviderGoogle, state, "", true, correlation)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Failed || result.RedirectURL != "https://app.example.test/callback" || provider.exchanged {
		t.Fatalf("result = %#v exchanged=%v", result, provider.exchanged)
	}
}

type fakeRedirectPolicy bool

func (p fakeRedirectPolicy) IsAllowedRedirectURL(context.Context, applicationinstance.InternalID, string) (bool, error) {
	return bool(p), nil
}

type fakeSocialAdmission struct{}

func (fakeSocialAdmission) AllowSocialAttempt(context.Context, applicationinstance.InternalID, Provider) error {
	return nil
}
func (fakeSocialAdmission) AllowSocialExchange(context.Context, applicationinstance.InternalID) error {
	return nil
}

type fakeSocialRegistry struct {
	appID    applicationinstance.PublicID
	provider *fakeSocialProvider
}

func (r fakeSocialRegistry) Resolve(appID applicationinstance.PublicID, provider Provider) (SocialProvider, bool) {
	if appID != r.appID || r.provider == nil || provider != r.provider.provider {
		return nil, false
	}
	return r.provider, true
}

type fakeSocialProvider struct {
	provider       Provider
	exchanged      bool
	assertConsumed func() bool
}

func (p *fakeSocialProvider) Provider() Provider { return p.provider }
func (*fakeSocialProvider) UsesPKCE() bool        { return false }
func (*fakeSocialProvider) UsesNonce() bool       { return false }
func (p *fakeSocialProvider) AuthorizationURL(state, _, _ string) (string, error) {
	if state == "" {
		return "", errors.New("state missing")
	}
	return "https://provider.example.test/authorize?state=" + state, nil
}
func (p *fakeSocialProvider) ExchangeIdentity(context.Context, string, string, [32]byte) (ExternalIdentityProof, error) {
	if p.assertConsumed != nil && !p.assertConsumed() {
		return ExternalIdentityProof{}, errors.New("state not consumed")
	}
	p.exchanged = true
	return ExternalIdentityProof{Provider: p.provider, Subject: "stable-subject"}, nil
}

type fakeSocialStore struct {
	write     SocialAttemptWrite
	snapshot  SocialAttemptSnapshot
	final     SocialProofFinalize
	consumed  bool
	rawState  string
}

func (s *fakeSocialStore) CreateSocialAttempt(_ context.Context, write SocialAttemptWrite) error {
	s.write = write
	return nil
}
func (s *fakeSocialStore) ConsumeSocialAttempt(_ context.Context, hash [32]byte, provider Provider) (SocialAttemptSnapshot, error) {
	if s.consumed || provider != s.snapshot.Provider || hash != s.snapshot.StateHash {
		return SocialAttemptSnapshot{}, ErrSocialInvalidState
	}
	s.consumed = true
	return s.snapshot, nil
}
func (s *fakeSocialStore) FinalizeSocialProof(_ context.Context, final SocialProofFinalize) error {
	s.final = final
	return nil
}
func (s *fakeSocialStore) stateFromAuthorizationURL(rawURL string) string {
	const marker = "?state="
	idx := strings.Index(rawURL, marker)
	if idx < 0 {
		return ""
	}
	return rawURL[idx+len(marker):]
}
