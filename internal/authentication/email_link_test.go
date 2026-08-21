package authentication

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
)

type emailLinkTestStore struct {
	issueResult EmailLinkIssueResult
	issue       EmailLinkIssue
}

func (s *emailLinkTestStore) AllowEmailLinkIssue(context.Context, applicationinstance.InternalID, [32]byte) error {
	return nil
}
func (s *emailLinkTestStore) AllowEmailLinkConfirm(context.Context, applicationinstance.InternalID, [32]byte) error {
	return nil
}
func (s *emailLinkTestStore) IssueEmailLink(_ context.Context, issue EmailLinkIssue) (EmailLinkIssueResult, error) {
	s.issue = issue
	return s.issueResult, nil
}
func (*emailLinkTestStore) LoadEmailLink(context.Context, applicationinstance.InternalID, string) (EmailLinkChallengeSnapshot, error) {
	return EmailLinkChallengeSnapshot{}, ErrEmailLinkInvalid
}
func (*emailLinkTestStore) FinalizeEmailLink(context.Context, EmailLinkFinalize) (EmailLinkFinalizeResult, error) {
	return EmailLinkFinalizeResult{}, ErrEmailLinkInvalid
}

type emailLinkTestRedirects struct{ allowed bool }

func (r emailLinkTestRedirects) IsAllowedRedirectURL(context.Context, applicationinstance.InternalID, string) (bool, error) {
	return r.allowed, nil
}

type emailLinkTestDelivery struct {
	called bool
	link   string
}

func (d *emailLinkTestDelivery) DeliverSignInLink(_ context.Context, _, link string, _ time.Time) error {
	d.called = true
	d.link = link
	return nil
}

func TestEmailLinkSecretHashBindsScopeAndDestination(t *testing.T) {
	secret, err := newEmailLinkSecret()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := url.QueryUnescape(secret); err != nil || got != secret {
		t.Fatalf("secret is not URL-safe: %q err=%v", secret, err)
	}
	challengeA := "eln_123e4567-e89b-42d3-a456-426614174001"
	challengeB := "eln_123e4567-e89b-42d3-a456-426614174002"
	a, err := EmailLinkSecretHash(1, challengeA, "https://app.example/return", secret)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		app         applicationinstance.InternalID
		challenge   string
		destination string
	}{
		{2, challengeA, "https://app.example/return"},
		{1, challengeB, "https://app.example/return"},
		{1, challengeA, "https://app.example/other"},
	}
	for _, tt := range cases {
		got, err := EmailLinkSecretHash(tt.app, tt.challenge, tt.destination, secret)
		if err != nil {
			t.Fatal(err)
		}
		if got == a {
			t.Fatalf("hash did not change for scope %#v", tt)
		}
	}
	if _, err := EmailLinkSecretHash(1, challengeA, "https://app.example/return", "short"); err == nil {
		t.Fatal("short secret unexpectedly accepted")
	}
}

func TestBuildHostedEmailLinkKeepsSecretOutOfQuery(t *testing.T) {
	secret, err := newEmailLinkSecret()
	if err != nil {
		t.Fatal(err)
	}
	link, err := buildHostedEmailLink("https://auth.example", "pk_test", "eln_123e4567-e89b-42d3-a456-426614174003", secret)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.RawQuery, secret) || u.Query().Get("secret") != "" {
		t.Fatalf("secret leaked into query: %q", u.RawQuery)
	}
	fragment, err := url.ParseQuery(u.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	if fragment.Get("secret") != secret {
		t.Fatal("secret missing from URL fragment")
	}
	if u.Query().Get("challenge") == "" || u.Query().Get("pk") != "pk_test" {
		t.Fatalf("locator metadata missing: %q", u.RawQuery)
	}
}

func TestEmailLinkRequestIsGenericWhenNoEligibleAccount(t *testing.T) {
	appPublicID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	store := &emailLinkTestStore{issueResult: EmailLinkIssueResult{ShouldSend: false}}
	delivery := &emailLinkTestDelivery{}
	service := NewEmailLinkService(store, emailLinkTestRedirects{allowed: true}, delivery, "https://auth.example")
	correlation, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	err = service.RequestWithCorrelation(context.Background(), applicationinstance.Instance{InternalID: 1, PublicID: appPublicID}, "pk_test", "nobody@example.test", "https://app.example/return", correlation)
	if err != nil {
		t.Fatalf("generic request returned error: %v", err)
	}
	if delivery.called {
		t.Fatal("generic no-account request attempted delivery")
	}
	if store.issue.SecretHash == ([32]byte{}) || !ValidEmailLinkChallengeID(store.issue.ChallengePublicID) {
		t.Fatal("eligible request material was not generated before generic persistence decision")
	}
}

func TestEmailLinkRequestRejectsUnallowlistedCompletionURLBeforeIssuance(t *testing.T) {
	appPublicID, err := applicationinstance.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	store := &emailLinkTestStore{}
	service := NewEmailLinkService(store, emailLinkTestRedirects{allowed: false}, &emailLinkTestDelivery{}, "https://auth.example")
	correlation, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	err = service.RequestWithCorrelation(context.Background(), applicationinstance.Instance{InternalID: 1, PublicID: appPublicID}, "pk_test", "user@example.test", "https://evil.example/", correlation)
	if err != ErrEmailLinkInvalidDestination {
		t.Fatalf("error=%v, want invalid destination", err)
	}
	if store.issue.ApplicationInstanceID.Valid() {
		t.Fatal("unallowlisted destination reached persistence")
	}
}
