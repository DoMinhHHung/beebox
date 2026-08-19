package authentication

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const (
	SocialLinkStatePrefix = "lnk_"
	SocialLinkFreshness   = 10 * time.Minute
	SocialLinkAttemptTTL  = 10 * time.Minute

	SocialLinkAttemptGlobalLimit       = 120
	SocialLinkAttemptUserProviderLimit = 10
)

var (
	ErrSocialLinkInvalidRequest         = errors.New("invalid social link request")
	ErrSocialLinkInvalidRedirect        = errors.New("invalid social link redirect")
	ErrSocialLinkInvalidSession         = errors.New("invalid social link session")
	ErrSocialLinkReverificationRequired = errors.New("social link reverification required")
	ErrSocialLinkInvalidState           = errors.New("invalid social link state")
	ErrSocialLinkRateLimited            = errors.New("social link rate limited")
	ErrSocialLinkDenied                 = errors.New("social link denied")
	ErrSocialLinkPersistence            = errors.New("social link persistence failure")
	ErrSocialLinkUnavailable            = errors.New("social link unavailable")
)

type SocialLinkSession struct {
	ApplicationInstanceID applicationinstance.InternalID
	UserID                identity.InternalID
	PublicID              string
	CreatedAt             time.Time
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	Revoked               bool
}

type SocialLinkAttemptWrite struct {
	ApplicationInstanceID  applicationinstance.InternalID
	UserID                 identity.InternalID
	SessionPublicID        string
	Provider               Provider
	CanonicalRedirectURL   string
	StateHash              [32]byte
	RecentAuthAt           time.Time
	OIDCNonceHash          *[32]byte
	ProviderPKCECiphertext []byte
	CreatedAt              time.Time
	ExpiresAt              time.Time
}

type SocialLinkAttemptSnapshot struct {
	AttemptID              int64
	ApplicationInstanceID  applicationinstance.InternalID
	ApplicationPublicID    applicationinstance.PublicID
	UserID                 identity.InternalID
	Provider               Provider
	CanonicalRedirectURL   string
	StateHash              [32]byte
	OIDCNonceHash          *[32]byte
	ProviderPKCECiphertext []byte
}

type SocialLinkFinalize struct {
	AttemptID       int64
	ProviderSubject string
	Now             time.Time
	CorrelationID   audit.CorrelationID
}

type SocialLinkPersistence interface {
	CreateSocialLinkAttempt(context.Context, SocialLinkAttemptWrite) error
	ConsumeSocialLinkAttempt(context.Context, [32]byte, Provider) (SocialLinkAttemptSnapshot, error)
	FinalizeSocialLink(context.Context, SocialLinkFinalize) error
	DenySocialLink(context.Context, int64, audit.CorrelationID) error
}

type SocialLinkAdmission interface {
	AllowSocialLinkAttempt(context.Context, applicationinstance.InternalID, identity.InternalID, Provider) error
}

type SocialLinkResult struct {
	AuthorizationURL string
	ExpiresIn        int64
}

type SocialLinkCallbackResult struct {
	RedirectURL string
	Failed      bool
}

type SocialLinkService struct {
	persistence SocialLinkPersistence
	redirects   SocialRedirectPolicy
	admission   SocialLinkAdmission
	providers   SocialProviderRegistry
	protector   *SocialStateProtector
	now         func() time.Time
}

func NewSocialLinkService(persistence SocialLinkPersistence, redirects SocialRedirectPolicy, admission SocialLinkAdmission, providers SocialProviderRegistry, protector *SocialStateProtector) *SocialLinkService {
	return &SocialLinkService{
		persistence: persistence,
		redirects:   redirects,
		admission:   admission,
		providers:   providers,
		protector:   protector,
		now:         time.Now,
	}
}

func (s *SocialLinkService) CreateLinkAttempt(ctx context.Context, app applicationinstance.Instance, current SocialLinkSession, provider Provider, redirectURL string) (SocialLinkResult, error) {
	if s == nil || s.persistence == nil || s.redirects == nil || s.admission == nil || s.providers == nil || s.now == nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
		return SocialLinkResult{}, ErrSocialLinkUnavailable
	}
	if !provider.Valid() {
		return SocialLinkResult{}, ErrSocialUnsupportedProvider
	}
	if current.ApplicationInstanceID != app.InternalID || !current.UserID.Valid() || current.PublicID == "" || len(current.PublicID) > 128 {
		return SocialLinkResult{}, ErrSocialLinkInvalidSession
	}
	now := s.now().UTC()
	createdAt := current.CreatedAt.UTC()
	if current.Revoked || !current.ExpiresAt.UTC().After(now) || !current.IdleExpiresAt.UTC().After(now) {
		return SocialLinkResult{}, ErrSocialLinkInvalidSession
	}
	authDeadline := createdAt.Add(SocialLinkFreshness)
	if !now.Before(authDeadline) {
		return SocialLinkResult{}, ErrSocialLinkReverificationRequired
	}
	canonicalRedirect, err := applicationinstance.CanonicalizeRedirectURL(redirectURL)
	if err != nil || canonicalRedirect != redirectURL {
		return SocialLinkResult{}, ErrSocialLinkInvalidRedirect
	}
	allowed, err := s.redirects.IsAllowedRedirectURL(ctx, app.InternalID, canonicalRedirect)
	if err != nil {
		return SocialLinkResult{}, ErrSocialLinkUnavailable
	}
	if !allowed {
		return SocialLinkResult{}, ErrSocialLinkInvalidRedirect
	}
	adapter, ok := s.providers.Resolve(app.PublicID, provider)
	if !ok || adapter == nil {
		return SocialLinkResult{}, ErrSocialUnsupportedProvider
	}
	if err := s.admission.AllowSocialLinkAttempt(ctx, app.InternalID, current.UserID, provider); err != nil {
		if errors.Is(err, ErrSocialLinkRateLimited) || errors.Is(err, ErrPublicRateLimited) {
			return SocialLinkResult{}, ErrSocialLinkRateLimited
		}
		return SocialLinkResult{}, ErrSocialLinkUnavailable
	}

	stateSecret, stateHash, err := newSocialSecret()
	if err != nil {
		return SocialLinkResult{}, ErrSocialLinkUnavailable
	}
	state := SocialLinkStatePrefix + stateSecret
	var nonce string
	var nonceHash *[32]byte
	if adapter.UsesNonce() {
		var hash [32]byte
		nonce, hash, err = newSocialSecret()
		if err != nil {
			return SocialLinkResult{}, ErrSocialLinkUnavailable
		}
		nonceHash = &hash
	}
	var providerVerifier, providerChallenge string
	var providerCiphertext []byte
	if adapter.UsesPKCE() {
		providerVerifier, err = generatePKCEVerifier()
		if err != nil || s.protector == nil {
			return SocialLinkResult{}, ErrSocialLinkUnavailable
		}
		providerChallenge, _ = S256Challenge(providerVerifier)
		providerCiphertext, err = s.protector.SealLink(app.InternalID, provider, stateHash, []byte(providerVerifier))
		if err != nil {
			return SocialLinkResult{}, ErrSocialLinkUnavailable
		}
	}
	authorizationURL, err := adapter.AuthorizationURL(state, nonce, providerChallenge)
	if err != nil {
		return SocialLinkResult{}, ErrSocialLinkUnavailable
	}
	expiresAt := earliestTime(now.Add(SocialLinkAttemptTTL), authDeadline, current.ExpiresAt.UTC(), current.IdleExpiresAt.UTC())
	remaining := expiresAt.Sub(now)
	if remaining < time.Second {
		return SocialLinkResult{}, ErrSocialLinkInvalidSession
	}
	if err := s.persistence.CreateSocialLinkAttempt(ctx, SocialLinkAttemptWrite{
		ApplicationInstanceID:  app.InternalID,
		UserID:                 current.UserID,
		SessionPublicID:        current.PublicID,
		Provider:               provider,
		CanonicalRedirectURL:   canonicalRedirect,
		StateHash:              stateHash,
		RecentAuthAt:           createdAt,
		OIDCNonceHash:          nonceHash,
		ProviderPKCECiphertext: providerCiphertext,
		CreatedAt:              now,
		ExpiresAt:              expiresAt,
	}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return SocialLinkResult{}, ctxErr
		}
		switch {
		case errors.Is(err, ErrSocialLinkInvalidSession):
			return SocialLinkResult{}, ErrSocialLinkInvalidSession
		case errors.Is(err, ErrSocialLinkReverificationRequired):
			return SocialLinkResult{}, ErrSocialLinkReverificationRequired
		default:
			return SocialLinkResult{}, ErrSocialLinkUnavailable
		}
	}
	return SocialLinkResult{AuthorizationURL: authorizationURL, ExpiresIn: int64(remaining / time.Second)}, nil
}

func (s *SocialLinkService) CompleteLinkCallback(ctx context.Context, callbackProvider Provider, rawState, providerCode string, providerDenied bool, correlationID audit.CorrelationID) (SocialLinkCallbackResult, error) {
	if s == nil || s.persistence == nil || s.providers == nil || s.now == nil || !callbackProvider.Valid() || correlationID == (audit.CorrelationID{}) || !strings.HasPrefix(rawState, SocialLinkStatePrefix) {
		return SocialLinkCallbackResult{}, ErrSocialLinkInvalidState
	}
	encoded := strings.TrimPrefix(rawState, SocialLinkStatePrefix)
	stateBytes, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(stateBytes) != 32 {
		return SocialLinkCallbackResult{}, ErrSocialLinkInvalidState
	}
	stateHash := sha256.Sum256(stateBytes)
	attempt, err := s.persistence.ConsumeSocialLinkAttempt(ctx, stateHash, callbackProvider)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return SocialLinkCallbackResult{}, ctxErr
		}
		return SocialLinkCallbackResult{}, ErrSocialLinkInvalidState
	}
	fail := func() (SocialLinkCallbackResult, error) {
		_ = s.persistence.DenySocialLink(ctx, attempt.AttemptID, correlationID)
		return SocialLinkCallbackResult{RedirectURL: attempt.CanonicalRedirectURL, Failed: true}, nil
	}
	if providerDenied || providerCode == "" {
		return fail()
	}
	adapter, ok := s.providers.Resolve(attempt.ApplicationPublicID, attempt.Provider)
	if !ok || adapter == nil {
		return fail()
	}
	var providerVerifier string
	if adapter.UsesPKCE() {
		if s.protector == nil || len(attempt.ProviderPKCECiphertext) == 0 {
			return fail()
		}
		plaintext, err := s.protector.OpenLink(attempt.ApplicationInstanceID, attempt.Provider, attempt.StateHash, attempt.ProviderPKCECiphertext)
		if err != nil || !ValidPKCEVerifier(string(plaintext)) {
			return fail()
		}
		providerVerifier = string(plaintext)
	}
	var expectedNonce [32]byte
	if adapter.UsesNonce() {
		if attempt.OIDCNonceHash == nil {
			return fail()
		}
		expectedNonce = *attempt.OIDCNonceHash
	}
	proof, err := adapter.ExchangeIdentity(ctx, providerCode, providerVerifier, expectedNonce)
	if err != nil || proof.Provider != attempt.Provider || !validProviderSubject(proof.Subject) {
		return fail()
	}
	if err := s.persistence.FinalizeSocialLink(ctx, SocialLinkFinalize{
		AttemptID:       attempt.AttemptID,
		ProviderSubject: proof.Subject,
		Now:             s.now().UTC(),
		CorrelationID:   correlationID,
	}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return SocialLinkCallbackResult{}, ctxErr
		}
		return SocialLinkCallbackResult{RedirectURL: attempt.CanonicalRedirectURL, Failed: true}, nil
	}
	return SocialLinkCallbackResult{RedirectURL: attempt.CanonicalRedirectURL}, nil
}

func SocialLinkRateLimitKey(userID identity.InternalID, provider Provider) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("beebox-social-link-v1\x00%d\x00%s", userID, provider)))
}

func (p *SocialStateProtector) SealLink(appID applicationinstance.InternalID, provider Provider, stateHash [32]byte, plaintext []byte) ([]byte, error) {
	if p == nil || p.aead == nil || !appID.Valid() || !provider.Valid() || len(plaintext) == 0 {
		return nil, ErrSocialStateKey
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrSocialStateKey
	}
	sealed := p.aead.Seal(nil, nonce, plaintext, socialLinkAAD(appID, provider, stateHash))
	return append(nonce, sealed...), nil
}

func (p *SocialStateProtector) OpenLink(appID applicationinstance.InternalID, provider Provider, stateHash [32]byte, ciphertext []byte) ([]byte, error) {
	if p == nil || p.aead == nil || !appID.Valid() || !provider.Valid() || len(ciphertext) <= p.aead.NonceSize() {
		return nil, ErrSocialStateKey
	}
	nonce := ciphertext[:p.aead.NonceSize()]
	body := ciphertext[p.aead.NonceSize():]
	plaintext, err := p.aead.Open(nil, nonce, body, socialLinkAAD(appID, provider, stateHash))
	if err != nil {
		return nil, ErrSocialStateKey
	}
	return plaintext, nil
}

func socialLinkAAD(appID applicationinstance.InternalID, provider Provider, stateHash [32]byte) []byte {
	return []byte(fmt.Sprintf("beebox-social-link-v1\x00%d\x00%s\x00%s", appID, provider, base64.RawURLEncoding.EncodeToString(stateHash[:])))
}

func earliestTime(values ...time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result
}
