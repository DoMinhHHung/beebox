package beebox

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var ErrInvalidAccessToken = errors.New("invalid access token")

const verifierClockSkew = 30 * time.Second

var publicIDPattern = regexp.MustCompile(`^(app|usr|ses|tok)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	SessionID string `json:"sid"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
	TokenID   string `json:"jti"`
}

type Verifier struct {
	issuer     string
	audience   string
	jwksURL    string
	httpClient *http.Client
	cacheTTL   time.Duration
	now        func() time.Time

	mu        sync.RWMutex
	keys      map[string]ed25519.PublicKey
	fetchedAt time.Time
}

func NewVerifier(issuer, audience string, client *http.Client) (*Verifier, error) {
	if !strings.HasPrefix(issuer, "https://") || !validTypedPublicID(audience, "app") {
		return nil, ErrInvalidClient
	}
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	issuer = strings.TrimSuffix(issuer, "/")
	return &Verifier{
		issuer:     issuer,
		audience:   audience,
		jwksURL:    issuer + "/.well-known/jwks.json",
		httpClient: client,
		cacheTTL:   time.Minute,
		now:        time.Now,
		keys:       make(map[string]ed25519.PublicKey),
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if v == nil || len(parts) != 3 {
		return Claims{}, ErrInvalidAccessToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerBytes, &header) != nil || header.Alg != "EdDSA" || header.Kid == "" {
		return Claims{}, ErrInvalidAccessToken
	}
	key, ok := v.key(header.Kid)
	if !ok || v.cacheExpired() {
		if err := v.refresh(ctx); err != nil {
			return Claims{}, ErrInvalidAccessToken
		}
		key, ok = v.key(header.Kid)
	}
	if !ok {
		// Unknown kid gets at most one controlled refresh above.
		return Claims{}, ErrInvalidAccessToken
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, ErrInvalidAccessToken
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidAccessToken
	}
	var claims Claims
	if json.Unmarshal(payload, &claims) != nil {
		return Claims{}, ErrInvalidAccessToken
	}
	now := v.now().UTC()
	if claims.Issuer != v.issuer || claims.Audience != v.audience ||
		!validTypedPublicID(claims.Subject, "usr") ||
		!validTypedPublicID(claims.Audience, "app") ||
		!validTypedPublicID(claims.SessionID, "ses") ||
		!validTypedPublicID(claims.TokenID, "tok") ||
		claims.ExpiresAt == 0 || claims.NotBefore == 0 || claims.IssuedAt == 0 {
		return Claims{}, ErrInvalidAccessToken
	}
	if now.After(time.Unix(claims.ExpiresAt, 0).Add(verifierClockSkew)) || now.Add(verifierClockSkew).Before(time.Unix(claims.NotBefore, 0)) {
		return Claims{}, ErrInvalidAccessToken
	}
	return claims, nil
}

func (v *Verifier) key(kid string) (ed25519.PublicKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok := v.keys[kid]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), key...), true
}

func (v *Verifier) cacheExpired() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.fetchedAt.IsZero() || v.now().Sub(v.fetchedAt) >= v.cacheTTL
}

func (v *Verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	res, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ErrInvalidAccessToken
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			D   string `json:"d,omitempty"`
		} `json:"keys"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&set) != nil {
		return ErrInvalidAccessToken
	}
	keys := make(map[string]ed25519.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Use != "sig" || jwk.Alg != "EdDSA" || jwk.Kid == "" || jwk.D != "" {
			return ErrInvalidAccessToken
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(jwk.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return ErrInvalidAccessToken
		}
		if _, exists := keys[jwk.Kid]; exists {
			return ErrInvalidAccessToken
		}
		keys[jwk.Kid] = ed25519.PublicKey(append([]byte(nil), raw...))
	}
	if len(keys) == 0 {
		return ErrInvalidAccessToken
	}
	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = v.now().UTC()
	v.mu.Unlock()
	return nil
}

func validTypedPublicID(value, prefix string) bool {
	return strings.HasPrefix(value, prefix+"_") && publicIDPattern.MatchString(value)
}
