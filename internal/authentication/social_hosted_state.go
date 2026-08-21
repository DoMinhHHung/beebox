package authentication

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
)

const hostedSocialStateAAD = "beebox-hosted-social-v1"

type HostedSocialContext struct {
	ApplicationInstanceID applicationinstance.InternalID `json:"application_instance_id"`
	ApplicationPublicID   applicationinstance.PublicID   `json:"application_public_id"`
	PKCEVerifier          string                         `json:"pkce_verifier"`
	CompletionURL         string                         `json:"completion_url"`
	IssuedAt              time.Time                      `json:"issued_at"`
	ExpiresAt             time.Time                      `json:"expires_at"`
}

func NewSocialPKCEVerifier() (string, error) {
	return generatePKCEVerifier()
}

func (c HostedSocialContext) valid() bool {
	if !c.ApplicationInstanceID.Valid() || !c.ApplicationPublicID.Valid() || !ValidPKCEVerifier(c.PKCEVerifier) || c.CompletionURL == "" {
		return false
	}
	canonical, err := applicationinstance.CanonicalizeRedirectURL(c.CompletionURL)
	if err != nil || canonical != c.CompletionURL {
		return false
	}
	issued := c.IssuedAt.UTC()
	expires := c.ExpiresAt.UTC()
	return !issued.IsZero() && issued.Before(expires) && !expires.After(issued.Add(SocialAttemptTTL))
}

func (p *SocialStateProtector) SealHostedContext(context HostedSocialContext) (string, error) {
	if p == nil || p.aead == nil || !context.valid() {
		return "", ErrSocialStateKey
	}
	plaintext, err := json.Marshal(context)
	if err != nil {
		return "", ErrSocialStateKey
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrSocialStateKey
	}
	sealed := p.aead.Seal(nil, nonce, plaintext, []byte(hostedSocialStateAAD))
	payload := append(nonce, sealed...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func (p *SocialStateProtector) OpenHostedContext(raw string, now time.Time) (HostedSocialContext, error) {
	if p == nil || p.aead == nil || raw == "" || now.IsZero() {
		return HostedSocialContext{}, ErrSocialInvalidState
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(payload) <= p.aead.NonceSize() {
		return HostedSocialContext{}, ErrSocialInvalidState
	}
	nonce := payload[:p.aead.NonceSize()]
	body := payload[p.aead.NonceSize():]
	plaintext, err := p.aead.Open(nil, nonce, body, []byte(hostedSocialStateAAD))
	if err != nil {
		return HostedSocialContext{}, ErrSocialInvalidState
	}
	var context HostedSocialContext
	if err := json.Unmarshal(plaintext, &context); err != nil || !context.valid() || !now.UTC().Before(context.ExpiresAt.UTC()) {
		return HostedSocialContext{}, ErrSocialInvalidState
	}
	return context, nil
}
