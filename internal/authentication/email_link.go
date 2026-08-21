package authentication

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

const (
	EmailLinkTTL            = 10 * time.Minute
	EmailLinkIssueWindow    = 15 * time.Minute
	EmailLinkResendCooldown = time.Minute
	EmailLinkMaxIssues      = 3
	EmailLinkMaxAttempts    = 5
)

var (
	ErrEmailLinkInvalidDestination = errors.New("invalid email link completion destination")
	ErrEmailLinkInvalid            = errors.New("invalid email link credentials")
	ErrEmailLinkRateLimited        = errors.New("email link rate limited")
	ErrEmailLinkDelivery           = errors.New("email link delivery failure")
	ErrEmailLinkPersistence        = errors.New("email link persistence failure")
	ErrEmailLinkStale              = errors.New("stale email link challenge")
)

type EmailLinkDelivery interface {
	DeliverSignInLink(context.Context, string, string, time.Time) error
}

type EmailLinkRedirectPolicy interface {
	IsAllowedRedirectURL(context.Context, applicationinstance.InternalID, string) (bool, error)
}

type EmailLinkIssue struct {
	ApplicationInstanceID applicationinstance.InternalID
	NormalizedEmail       string
	ChallengePublicID     string
	SecretHash            [32]byte
	CompletionURL         string
	CorrelationID         audit.CorrelationID
}

type EmailLinkIssueResult struct {
	ShouldSend  bool
	Destination string
	ExpiresAt   time.Time
}

type EmailLinkChallengeSnapshot struct {
	UserID              identity.InternalID
	EmailIdentifierID   identity.EmailIdentifierInternalID
	ChallengePublicID   string
	ChallengeGeneration int64
	SecretHash          [32]byte
	CompletionURL       string
	ExpiresAt           time.Time
	FailedAttempts      int
}

type EmailLinkFinalize struct {
	ApplicationInstanceID applicationinstance.InternalID
	EmailIdentifierID     identity.EmailIdentifierInternalID
	UserID                identity.InternalID
	ChallengePublicID     string
	ChallengeGeneration   int64
	CompletionURL         string
	Matched               bool
	SessionPublicID       string
	RefreshVerifier       [32]byte
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	PendingMFA            PendingMFAWrite
	CorrelationID         audit.CorrelationID
}

type EmailLinkFinalizeResult struct {
	UserPublicID          string
	ApplicationPublicID   string
	MFARequired           bool
	PendingMFAPublicID    string
	PendingMFAExpiresAt   time.Time
	RecoveryCodeAvailable bool
}

type EmailLinkPersistence interface {
	IssueEmailLink(context.Context, EmailLinkIssue) (EmailLinkIssueResult, error)
	LoadEmailLink(context.Context, applicationinstance.InternalID, string) (EmailLinkChallengeSnapshot, error)
	FinalizeEmailLink(context.Context, EmailLinkFinalize) (EmailLinkFinalizeResult, error)
}

type EmailLinkService struct {
	persistence  EmailLinkPersistence
	redirects    EmailLinkRedirectPolicy
	delivery     EmailLinkDelivery
	hostedOrigin string
}

func NewEmailLinkService(persistence EmailLinkPersistence, redirects EmailLinkRedirectPolicy, delivery EmailLinkDelivery, hostedOrigin string) *EmailLinkService {
	return &EmailLinkService{persistence: persistence, redirects: redirects, delivery: delivery, hostedOrigin: hostedOrigin}
}

func (s *EmailLinkService) RequestWithCorrelation(
	ctx context.Context,
	app applicationinstance.Instance,
	publishableKey string,
	rawEmail string,
	rawCompletionURL string,
	correlationID audit.CorrelationID,
) error {
	if s == nil || s.persistence == nil || s.redirects == nil || s.delivery == nil || !app.InternalID.Valid() || !app.PublicID.Valid() || publishableKey == "" || correlationID == (audit.CorrelationID{}) {
		return ErrEmailLinkPersistence
	}
	admission, ok := s.persistence.(EmailLinkAdmission)
	if !ok {
		return ErrEmailLinkPersistence
	}
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return identity.ErrInvalidEmail
	}
	completionURL, err := applicationinstance.CanonicalizeRedirectURL(rawCompletionURL)
	if err != nil {
		return ErrEmailLinkInvalidDestination
	}
	allowed, err := s.redirects.IsAllowedRedirectURL(ctx, app.InternalID, completionURL)
	if err != nil {
		return ErrEmailLinkPersistence
	}
	if !allowed {
		return ErrEmailLinkInvalidDestination
	}
	hostedOrigin, err := applicationinstance.CanonicalizeOrigin(s.hostedOrigin)
	if err != nil {
		return ErrEmailLinkPersistence
	}
	fingerprint := sha256.Sum256([]byte("email-link-issue-email\x00" + email.ComparisonKey))
	if err := admission.AllowEmailLinkIssue(ctx, app.InternalID, fingerprint); err != nil {
		if errors.Is(err, ErrPublicRateLimited) || errors.Is(err, ErrEmailLinkRateLimited) {
			return nil
		}
		return err
	}
	challengeID, err := publicid.NewUUIDv4("eln")
	if err != nil {
		return ErrEmailLinkPersistence
	}
	secret, err := newEmailLinkSecret()
	if err != nil {
		return ErrEmailLinkPersistence
	}
	secretHash, err := EmailLinkSecretHash(app.InternalID, challengeID, completionURL, secret)
	if err != nil {
		return ErrEmailLinkPersistence
	}
	result, err := s.persistence.IssueEmailLink(ctx, EmailLinkIssue{
		ApplicationInstanceID: app.InternalID,
		NormalizedEmail:       email.ComparisonKey,
		ChallengePublicID:     challengeID,
		SecretHash:            secretHash,
		CompletionURL:         completionURL,
		CorrelationID:         correlationID,
	})
	if err != nil {
		if errors.Is(err, ErrEmailLinkRateLimited) || errors.Is(err, ErrEmailLinkInvalid) {
			return nil
		}
		return err
	}
	if !result.ShouldSend {
		return nil
	}
	link, err := buildHostedEmailLink(hostedOrigin, publishableKey, challengeID, secret)
	if err != nil {
		return ErrEmailLinkPersistence
	}
	if err := s.delivery.DeliverSignInLink(ctx, result.Destination, link, result.ExpiresAt); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrEmailLinkDelivery
	}
	return nil
}

func ValidEmailLinkChallengeID(value string) bool {
	return publicid.IsUUIDv4(value, "eln")
}

func EmailLinkSecretHash(appID applicationinstance.InternalID, challengeID, completionURL, secret string) ([32]byte, error) {
	var zero [32]byte
	if !appID.Valid() || !ValidEmailLinkChallengeID(challengeID) || completionURL == "" {
		return zero, ErrEmailLinkInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(raw) != 32 {
		return zero, ErrEmailLinkInvalid
	}
	material := "beebox.email-link.sign-in.v1\x00" + strconv.FormatInt(int64(appID), 10) + "\x00" + challengeID + "\x00" + completionURL + "\x00" + secret
	return sha256.Sum256([]byte(material)), nil
}

func newEmailLinkSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func buildHostedEmailLink(hostedOrigin, publishableKey, challengeID, secret string) (string, error) {
	u, err := url.Parse(hostedOrigin)
	if err != nil || u.Scheme == "" || u.Host == "" || publishableKey == "" || !ValidEmailLinkChallengeID(challengeID) {
		return "", ErrEmailLinkPersistence
	}
	u.Path = "/auth/email-link"
	u.RawQuery = url.Values{"challenge": {challengeID}, "pk": {publishableKey}}.Encode()
	u.Fragment = url.Values{"secret": {secret}}.Encode()
	return u.String(), nil
}
