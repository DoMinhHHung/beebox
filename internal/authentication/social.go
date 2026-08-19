package authentication

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
)

const (
	SocialAttemptTTL    = 10 * time.Minute
	SocialCompletionTTL = 5 * time.Minute

	SocialAttemptGlobalLimit       = 120
	SocialAttemptProviderLimit     = 30
	SocialExchangeGlobalLimit      = 120
	SocialExchangeApplicationLimit = 60
)

type Provider string

const (
	ProviderGoogle    Provider = "google"
	ProviderApple     Provider = "apple"
	ProviderMicrosoft Provider = "microsoft"
	ProviderGitHub    Provider = "github"
	ProviderGitLab    Provider = "gitlab"
	ProviderFacebook  Provider = "facebook"
	ProviderSlack     Provider = "slack"
	ProviderDiscord   Provider = "discord"
	ProviderLinkedIn  Provider = "linkedin"
	ProviderX         Provider = "x"
	ProviderTikTok    Provider = "tiktok"
)

var Providers = [...]Provider{
	ProviderGoogle,
	ProviderApple,
	ProviderMicrosoft,
	ProviderGitHub,
	ProviderGitLab,
	ProviderFacebook,
	ProviderSlack,
	ProviderDiscord,
	ProviderLinkedIn,
	ProviderX,
	ProviderTikTok,
}

var (
	ErrSocialInvalidRequest      = errors.New("invalid social authentication request")
	ErrSocialUnsupportedProvider = errors.New("unsupported social provider")
	ErrSocialUnavailable         = errors.New("social authentication unavailable")
	ErrSocialInvalidState        = errors.New("invalid social authentication state")
	ErrSocialProviderProof       = errors.New("social provider proof failed")
	ErrSocialCompletionInvalid   = errors.New("invalid social completion")
	ErrSocialRateLimited         = errors.New("social authentication rate limited")
	ErrSocialPersistence         = errors.New("social authentication persistence failure")
	ErrSocialStateKey            = errors.New("invalid social state encryption key")
)

var pkceVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
var pkceChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func (p Provider) Valid() bool {
	switch p {
	case ProviderGoogle, ProviderApple, ProviderMicrosoft, ProviderGitHub, ProviderGitLab, ProviderFacebook, ProviderSlack, ProviderDiscord, ProviderLinkedIn, ProviderX, ProviderTikTok:
		return true
	default:
		return false
	}
}

func ValidPKCEVerifier(value string) bool {
	return pkceVerifierPattern.MatchString(value)
}

func ValidS256Challenge(value string) bool {
	return pkceChallengePattern.MatchString(value)
}

func S256Challenge(verifier string) (string, bool) {
	if !ValidPKCEVerifier(verifier) {
		return "", false
	}
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:]), true
}

type ExternalIdentityProof struct {
	Provider Provider
	Subject  string
}

type SocialProvider interface {
	Provider() Provider
	UsesPKCE() bool
	UsesNonce() bool
	AuthorizationURL(state, nonce, providerCodeChallenge string) (string, error)
	ExchangeIdentity(context.Context, string, string, [32]byte) (ExternalIdentityProof, error)
}

type SocialProviderRegistry interface {
	Resolve(applicationinstance.PublicID, Provider) (SocialProvider, bool)
}

type SocialRedirectPolicy interface {
	IsAllowedRedirectURL(context.Context, applicationinstance.InternalID, string) (bool, error)
}

type SocialAdmission interface {
	AllowSocialAttempt(context.Context, applicationinstance.InternalID, Provider) error
	AllowSocialExchange(context.Context, applicationinstance.InternalID) error
}

type SocialAttemptWrite struct {
	ApplicationInstanceID  applicationinstance.InternalID
	Provider               Provider
	CanonicalRedirectURL   string
	StateHash              [32]byte
	ClientCodeChallenge    string
	OIDCNonceHash          *[32]byte
	ProviderPKCECiphertext []byte
	ExpiresAt              time.Time
}

type SocialAttemptSnapshot struct {
	ApplicationInstanceID  applicationinstance.InternalID
	ApplicationPublicID    applicationinstance.PublicID
	Provider               Provider
	CanonicalRedirectURL   string
	StateHash              [32]byte
	ClientCodeChallenge    string
	OIDCNonceHash          *[32]byte
	ProviderPKCECiphertext []byte
	ExpiresAt              time.Time
}

type SocialProofFinalize struct {
	ApplicationInstanceID applicationinstance.InternalID
	Provider              Provider
	ProviderSubject       string
	ClientCodeChallenge   string
	CompletionCodeHash    [32]byte
	CompletionExpiresAt   time.Time
	CorrelationID         audit.CorrelationID
}

type SocialPersistence interface {
	CreateSocialAttempt(context.Context, SocialAttemptWrite) error
	ConsumeSocialAttempt(context.Context, [32]byte, Provider) (SocialAttemptSnapshot, error)
	FinalizeSocialProof(context.Context, SocialProofFinalize) error
}

type SocialAttemptResult struct {
	AuthorizationURL string
	ExpiresIn        int64
}

type SocialCallbackResult struct {
	RedirectURL    string
	CompletionCode string
	Failed         bool
}

type SocialService struct {
	persistence SocialPersistence
	redirects   SocialRedirectPolicy
	admission   SocialAdmission
	providers   SocialProviderRegistry
	protector   *SocialStateProtector
	now         func() time.Time
}

func NewSocialService(persistence SocialPersistence, redirects SocialRedirectPolicy, admission SocialAdmission, providers SocialProviderRegistry, protector *SocialStateProtector) *SocialService {
	return &SocialService{
		persistence: persistence,
		redirects:   redirects,
		admission:   admission,
		providers:   providers,
		protector:   protector,
		now:         time.Now,
	}
}

func (s *SocialService) CreateAttempt(ctx context.Context, app applicationinstance.Instance, provider Provider, redirectURL, clientChallenge, challengeMethod string) (SocialAttemptResult, error) {
	if s == nil || s.persistence == nil || s.redirects == nil || s.admission == nil || s.providers == nil || s.now == nil || !app.InternalID.Valid() || !app.PublicID.Valid() {
		return SocialAttemptResult{}, ErrSocialUnavailable
	}
	if !provider.Valid() {
		return SocialAttemptResult{}, ErrSocialUnsupportedProvider
	}
	if challengeMethod != "S256" || !ValidS256Challenge(clientChallenge) {
		return SocialAttemptResult{}, ErrSocialInvalidRequest
	}
	canonicalRedirect, err := applicationinstance.CanonicalizeRedirectURL(redirectURL)
	if err != nil || canonicalRedirect != redirectURL {
		return SocialAttemptResult{}, ErrSocialInvalidRequest
	}
	allowed, err := s.redirects.IsAllowedRedirectURL(ctx, app.InternalID, canonicalRedirect)
	if err != nil {
		return SocialAttemptResult{}, ErrSocialUnavailable
	}
	if !allowed {
		return SocialAttemptResult{}, ErrSocialInvalidRequest
	}
	adapter, ok := s.providers.Resolve(app.PublicID, provider)
	if !ok || adapter == nil {
		return SocialAttemptResult{}, ErrSocialUnsupportedProvider
	}
	if err := s.admission.AllowSocialAttempt(ctx, app.InternalID, provider); err != nil {
		if errors.Is(err, ErrSocialRateLimited) || errors.Is(err, ErrPublicRateLimited) {
			return SocialAttemptResult{}, ErrSocialRateLimited
		}
		return SocialAttemptResult{}, ErrSocialUnavailable
	}

	state, stateHash, err := newSocialSecret()
	if err != nil {
		return SocialAttemptResult{}, ErrSocialUnavailable
	}
	var nonce string
	var nonceHash *[32]byte
	if adapter.UsesNonce() {
		var hash [32]byte
		nonce, hash, err = newSocialSecret()
		if err != nil {
			return SocialAttemptResult{}, ErrSocialUnavailable
		}
		nonceHash = &hash
	}
	var providerVerifier, providerChallenge string
	var providerCiphertext []byte
	if adapter.UsesPKCE() {
		providerVerifier, err = generatePKCEVerifier()
		if err != nil {
			return SocialAttemptResult{}, ErrSocialUnavailable
		}
		providerChallenge, _ = S256Challenge(providerVerifier)
		if s.protector == nil {
			return SocialAttemptResult{}, ErrSocialUnavailable
		}
		providerCiphertext, err = s.protector.Seal(app.InternalID, provider, stateHash, []byte(providerVerifier))
		if err != nil {
			return SocialAttemptResult{}, ErrSocialUnavailable
		}
	}
	authorizationURL, err := adapter.AuthorizationURL(state, nonce, providerChallenge)
	if err != nil {
		return SocialAttemptResult{}, ErrSocialUnavailable
	}
	now := s.now().UTC()
	if err := s.persistence.CreateSocialAttempt(ctx, SocialAttemptWrite{
		ApplicationInstanceID:  app.InternalID,
		Provider:               provider,
		CanonicalRedirectURL:   canonicalRedirect,
		StateHash:              stateHash,
		ClientCodeChallenge:    clientChallenge,
		OIDCNonceHash:          nonceHash,
		ProviderPKCECiphertext: providerCiphertext,
		ExpiresAt:              now.Add(SocialAttemptTTL),
	}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return SocialAttemptResult{}, ctxErr
		}
		return SocialAttemptResult{}, ErrSocialUnavailable
	}
	return SocialAttemptResult{AuthorizationURL: authorizationURL, ExpiresIn: int64(SocialAttemptTTL / time.Second)}, nil
}

func (s *SocialService) CompleteCallback(ctx context.Context, callbackProvider Provider, rawState, providerCode string, providerDenied bool, correlationID audit.CorrelationID) (SocialCallbackResult, error) {
	if s == nil || s.persistence == nil || s.providers == nil || s.now == nil || !callbackProvider.Valid() || correlationID == (audit.CorrelationID{}) || rawState == "" {
		return SocialCallbackResult{}, ErrSocialInvalidState
	}
	stateBytes, err := base64.RawURLEncoding.Strict().DecodeString(rawState)
	if err != nil || len(stateBytes) != 32 {
		return SocialCallbackResult{}, ErrSocialInvalidState
	}
	stateHash := sha256.Sum256(stateBytes)
	attempt, err := s.persistence.ConsumeSocialAttempt(ctx, stateHash, callbackProvider)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return SocialCallbackResult{}, ctxErr
		}
		return SocialCallbackResult{}, ErrSocialInvalidState
	}
	if providerDenied || providerCode == "" {
		return SocialCallbackResult{RedirectURL: attempt.CanonicalRedirectURL, Failed: true}, nil
	}
	adapter, ok := s.providers.Resolve(attempt.ApplicationPublicID, attempt.Provider)
	if !ok || adapter == nil {
		return SocialCallbackResult{RedirectURL: attempt.CanonicalRedirectURL, Failed: true}, nil
	}
	var providerVerifier string
	if adapter.UsesPKCE() {
		if s.protector == nil || len(attempt.ProviderPKCECiphertext) == 0 {
			return SocialCallbackResult{RedirectURL: attempt.CanonicalRedirectURL, Failed: true}, nil
		}
		plaintext, err := s.protector.Open(attempt.ApplicationInstanceID, attempt.Provider, attempt.StateHash, attempt.ProviderPKCECiphertext)
		if err != nil || !ValidPKCEVerifier(string(plaintext)) {
			return SocialCallbackResult{RedirectURL: attempt.CanonicalRedirectURL, Failed: true}, nil
		}
		providerVerifier = string(plaintext)
	}
	var expectedNonce [32]byte
	if adapter.UsesNonce() {
		if attempt.OIDCNonceHash == nil {
			return SocialCallbackResult{RedirectURL: attempt.CanonicalRedirectURL, Failed: true}, nil
		}
		expectedNonce = *attempt.OIDCNonceHash
	}
	proof, err := adapter.ExchangeIdentity(ctx, providerCode, providerVerifier, expectedNonce)
	if err != nil || proof.Provider != attempt.Provider || !validProviderSubject(proof.Subject) {
		return SocialCallbackResult{RedirectURL: attempt.CanonicalRedirectURL, Failed: true}, nil
	}
	completionCode, completionHash, err := newSocialSecret()
	if err != nil {
		return SocialCallbackResult{}, ErrSocialUnavailable
	}
	now := s.now().UTC()
	if err := s.persistence.FinalizeSocialProof(ctx, SocialProofFinalize{
		ApplicationInstanceID: attempt.ApplicationInstanceID,
		Provider:              attempt.Provider,
		ProviderSubject:       proof.Subject,
		ClientCodeChallenge:   attempt.ClientCodeChallenge,
		CompletionCodeHash:    completionHash,
		CompletionExpiresAt:   now.Add(SocialCompletionTTL),
		CorrelationID:         correlationID,
	}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return SocialCallbackResult{}, ctxErr
		}
		return SocialCallbackResult{}, ErrSocialUnavailable
	}
	return SocialCallbackResult{RedirectURL: attempt.CanonicalRedirectURL, CompletionCode: completionCode}, nil
}

func newSocialSecret() (string, [32]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [32]byte{}, err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), sha256.Sum256(raw[:]), nil
}

func generatePKCEVerifier() (string, error) {
	var raw [64]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(raw[:])
	if !ValidPKCEVerifier(value) {
		return "", ErrSocialUnavailable
	}
	return value, nil
}

func validProviderSubject(subject string) bool {
	return subject != "" && len(subject) <= 512
}

type SocialStateProtector struct {
	aead cipher.AEAD
}

func NewSocialStateProtector(key []byte) (*SocialStateProtector, error) {
	if len(key) != 32 {
		return nil, ErrSocialStateKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrSocialStateKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrSocialStateKey
	}
	return &SocialStateProtector{aead: aead}, nil
}

func (p *SocialStateProtector) Seal(appID applicationinstance.InternalID, provider Provider, stateHash [32]byte, plaintext []byte) ([]byte, error) {
	if p == nil || p.aead == nil || !appID.Valid() || !provider.Valid() || len(plaintext) == 0 {
		return nil, ErrSocialStateKey
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrSocialStateKey
	}
	aad := socialAAD(appID, provider, stateHash)
	sealed := p.aead.Seal(nil, nonce, plaintext, aad)
	return append(nonce, sealed...), nil
}

func (p *SocialStateProtector) Open(appID applicationinstance.InternalID, provider Provider, stateHash [32]byte, ciphertext []byte) ([]byte, error) {
	if p == nil || p.aead == nil || !appID.Valid() || !provider.Valid() || len(ciphertext) <= p.aead.NonceSize() {
		return nil, ErrSocialStateKey
	}
	nonce := ciphertext[:p.aead.NonceSize()]
	body := ciphertext[p.aead.NonceSize():]
	plaintext, err := p.aead.Open(nil, nonce, body, socialAAD(appID, provider, stateHash))
	if err != nil {
		return nil, ErrSocialStateKey
	}
	return plaintext, nil
}

func socialAAD(appID applicationinstance.InternalID, provider Provider, stateHash [32]byte) []byte {
	return []byte(fmt.Sprintf("beebox-social-v1\x00%d\x00%s\x00%s", appID, provider, base64.RawURLEncoding.EncodeToString(stateHash[:])))
}

func CompareNonceHash(expected [32]byte, nonce string) bool {
	if nonce == "" || expected == ([32]byte{}) {
		return false
	}
	actual := sha256.Sum256([]byte(nonce))
	return subtle.ConstantTimeCompare(expected[:], actual[:]) == 1
}
