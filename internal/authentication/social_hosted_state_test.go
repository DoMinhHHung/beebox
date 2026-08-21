package authentication

import (
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

func TestHostedSocialContextRoundTripAndTamperResistance(t *testing.T) {
	protector, err := NewSocialStateProtector([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	appPublicID := applicationinstance.PublicID("app_123e4567-e89b-42d3-a456-426614174301")
	now := time.Date(2026, time.August, 22, 0, 0, 0, 0, time.UTC)
	verifier, err := NewSocialPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	want := HostedSocialContext{
		ApplicationInstanceID: 7,
		ApplicationPublicID:   appPublicID,
		PKCEVerifier:          verifier,
		CompletionURL:         "https://app.example/complete",
		IssuedAt:              now,
		ExpiresAt:             now.Add(SocialAttemptTTL),
	}
	sealed, err := protector.SealHostedContext(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protector.OpenHostedContext(sealed, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got.ApplicationInstanceID != want.ApplicationInstanceID || got.ApplicationPublicID != want.ApplicationPublicID || got.PKCEVerifier != want.PKCEVerifier || got.CompletionURL != want.CompletionURL || !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("round trip=%#v want=%#v", got, want)
	}

	tampered := []byte(sealed)
	if tampered[len(tampered)-1] == 'A' {
		tampered[len(tampered)-1] = 'B'
	} else {
		tampered[len(tampered)-1] = 'A'
	}
	if _, err := protector.OpenHostedContext(string(tampered), now.Add(time.Minute)); err != ErrSocialInvalidState {
		t.Fatalf("tampered state error=%v", err)
	}
	if _, err := protector.OpenHostedContext(sealed, now.Add(SocialAttemptTTL)); err != ErrSocialInvalidState {
		t.Fatalf("expired state error=%v", err)
	}
}

func TestHostedSocialContextRejectsUnsafeDestinationAndOverlongLifetime(t *testing.T) {
	protector, err := NewSocialStateProtector([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewSocialPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	base := HostedSocialContext{
		ApplicationInstanceID: 1,
		ApplicationPublicID:   applicationinstance.PublicID("app_123e4567-e89b-42d3-a456-426614174302"),
		PKCEVerifier:          verifier,
		CompletionURL:         "https://app.example/complete",
		IssuedAt:              now,
		ExpiresAt:             now.Add(SocialAttemptTTL),
	}
	unsafe := base
	unsafe.CompletionURL = "https://user:pass@app.example/complete"
	if _, err := protector.SealHostedContext(unsafe); err != ErrSocialStateKey {
		t.Fatalf("userinfo destination error=%v", err)
	}
	tooLong := base
	tooLong.ExpiresAt = now.Add(SocialAttemptTTL + time.Second)
	if _, err := protector.SealHostedContext(tooLong); err != ErrSocialStateKey {
		t.Fatalf("overlong lifetime error=%v", err)
	}
}
