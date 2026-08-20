package authentication

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

type fakeSocialAccountPersistence struct {
	rows          []LinkedSocialAccount
	listLimit     int
	listCursor    *SocialAccountCursor
	unlinkCalls   int
	unlinkPublic  string
	unlinkCurrent SocialAccountSession
	unlinkErr     error
}

func (f *fakeSocialAccountPersistence) ListSocialAccounts(_ context.Context, _ applicationinstance.InternalID, _ identity.InternalID, limit int, cursor *SocialAccountCursor) ([]LinkedSocialAccount, error) {
	f.listLimit = limit
	f.listCursor = cursor
	return f.rows, nil
}

func (f *fakeSocialAccountPersistence) UnlinkSocialAccount(_ context.Context, current SocialAccountSession, publicID string, _ SocialMethodAvailability, _ audit.CorrelationID) error {
	f.unlinkCalls++
	f.unlinkPublic = publicID
	f.unlinkCurrent = current
	return f.unlinkErr
}

func TestSocialAccountCursorRoundTripAndValidation(t *testing.T) {
	created := time.Date(2026, 8, 20, 1, 2, 3, 456000000, time.UTC)
	id := "sli_123e4567-e89b-42d3-a456-426614174000"
	raw, err := EncodeSocialAccountCursor(SocialAccountCursor{CreatedAt: created, PublicID: id})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSocialAccountCursor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.CreatedAt.Equal(created) || decoded.PublicID != id {
		t.Fatalf("cursor=%#v", decoded)
	}
	for _, invalid := range []string{"%%%", "e30", raw + "garbage"} {
		if _, err := DecodeSocialAccountCursor(invalid); !errors.Is(err, ErrSocialAccountInvalidRequest) {
			t.Fatalf("cursor %q error=%v", invalid, err)
		}
	}
}

func TestSocialLinkPublicIDValidation(t *testing.T) {
	valid := "sli_123e4567-e89b-42d3-a456-426614174000"
	if !ValidSocialLinkPublicID(valid) {
		t.Fatal("valid UUID-v4 social link ID rejected")
	}
	for _, invalid := range []string{
		"123e4567-e89b-42d3-a456-426614174000",
		"sli_123e4567-e89b-12d3-a456-426614174000",
		"sli_123e4567-e89b-42d3-7456-426614174000",
		"sli_123E4567-e89b-42d3-a456-426614174000",
	} {
		if ValidSocialLinkPublicID(invalid) {
			t.Fatalf("invalid ID accepted: %q", invalid)
		}
	}
}

func TestSocialAccountListIsBoundedAndProducesCursor(t *testing.T) {
	p := &fakeSocialAccountPersistence{rows: []LinkedSocialAccount{
		{PublicID: "sli_123e4567-e89b-42d3-a456-426614174000", Provider: ProviderGitHub, CreatedAt: time.Unix(10, 0).UTC()},
		{PublicID: "sli_223e4567-e89b-42d3-a456-426614174000", Provider: ProviderGoogle, CreatedAt: time.Unix(20, 0).UTC()},
		{PublicID: "sli_323e4567-e89b-42d3-a456-426614174000", Provider: ProviderDiscord, CreatedAt: time.Unix(30, 0).UTC()},
	}}
	service := NewSocialAccountService(p, SocialMethodAvailability{})
	page, err := service.List(context.Background(), validSocialAccountTestSession(time.Now().UTC()), 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.listLimit != 3 || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("limit=%d items=%d cursor=%q", p.listLimit, len(page.Items), page.NextCursor)
	}
	cursor, err := DecodeSocialAccountCursor(page.NextCursor)
	if err != nil || cursor.PublicID != page.Items[1].PublicID {
		t.Fatalf("cursor=%#v err=%v", cursor, err)
	}
}

func TestSocialAccountUnlinkRequiresScopedReverification(t *testing.T) {
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	p := &fakeSocialAccountPersistence{}
	service := NewSocialAccountService(p, SocialMethodAvailability{})
	service.now = func() time.Time { return now }
	correlation, _ := audit.NewCorrelationID()
	id := "sli_123e4567-e89b-42d3-a456-426614174000"

	current := validSocialAccountTestSession(now)
	current.CreatedAt = now.Add(-24 * time.Hour)
	ctx := testReverificationContext(current.ApplicationInstanceID, current.UserID, current.SessionPublicID, ReverificationPurposeSocialUnlink)
	if err := service.Unlink(ctx, current, id, correlation); err != nil {
		t.Fatalf("old active session with trusted reverification error=%v", err)
	}
	if p.unlinkCalls != 1 {
		t.Fatalf("unlink calls=%d", p.unlinkCalls)
	}

	if err := service.Unlink(context.Background(), current, id, correlation); !errors.Is(err, ErrSocialAccountReverification) {
		t.Fatalf("missing reverification error=%v", err)
	}
	if p.unlinkCalls != 1 {
		t.Fatalf("unauthorized request reached persistence: calls=%d", p.unlinkCalls)
	}
}

func validSocialAccountTestSession(now time.Time) SocialAccountSession {
	return SocialAccountSession{
		ApplicationInstanceID: 1,
		ApplicationPublicID:   applicationinstance.PublicID("app_123e4567-e89b-42d3-a456-426614174000"),
		UserID:                2,
		SessionPublicID:       "ses_123e4567-e89b-42d3-a456-426614174000",
		CreatedAt:             now.Add(-time.Minute),
		IdleExpiresAt:         now.Add(time.Hour),
		ExpiresAt:             now.Add(2 * time.Hour),
	}
}
