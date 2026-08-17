package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

const (
	AccessTokenLifetime = 5 * time.Minute
	ClockSkew           = 30 * time.Second
)

var (
	ErrTokenConfig  = errors.New("invalid access token configuration")
	ErrToken        = errors.New("invalid access token")
	ErrTokenSigning = errors.New("access token signing failure")
)

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

type KeyRing struct {
	issuer  string
	kid     string
	private ed25519.PrivateKey
	public  map[string]ed25519.PublicKey
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func NewKeyRing(issuer, activeKID string, privateKey ed25519.PrivateKey, verificationKeys map[string]ed25519.PublicKey) (*KeyRing, error) {
	if !strings.HasPrefix(issuer, "https://") || activeKID == "" || len(privateKey) != ed25519.PrivateKeySize || len(verificationKeys) == 0 {
		return nil, ErrTokenConfig
	}
	activePublic, ok := verificationKeys[activeKID]
	if !ok || len(activePublic) != ed25519.PublicKeySize || !privateKey.Public().(ed25519.PublicKey).Equal(activePublic) {
		return nil, ErrTokenConfig
	}
	copyKeys := make(map[string]ed25519.PublicKey, len(verificationKeys))
	for kid, key := range verificationKeys {
		if kid == "" || len(key) != ed25519.PublicKeySize {
			return nil, ErrTokenConfig
		}
		copyKeys[kid] = append(ed25519.PublicKey(nil), key...)
	}
	return &KeyRing{
		issuer:  strings.TrimSuffix(issuer, "/"),
		kid:     activeKID,
		private: append(ed25519.PrivateKey(nil), privateKey...),
		public:  copyKeys,
	}, nil
}

func (r *KeyRing) Sign(userPublicID, applicationPublicID, sessionPublicID string, now time.Time) (string, error) {
	if r == nil || !publicid.IsUUIDv4(userPublicID, "usr") || !publicid.IsUUIDv4(applicationPublicID, "app") || !publicid.IsUUIDv4(sessionPublicID, "ses") {
		return "", ErrToken
	}
	jti, err := publicid.NewUUIDv4("tok")
	if err != nil {
		return "", ErrTokenSigning
	}
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": r.kid, "typ": "JWT"})
	if err != nil {
		return "", ErrTokenSigning
	}
	claims, err := json.Marshal(Claims{
		Issuer:    r.issuer,
		Subject:   userPublicID,
		Audience:  applicationPublicID,
		SessionID: sessionPublicID,
		ExpiresAt: now.Add(AccessTokenLifetime).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		TokenID:   jti,
	})
	if err != nil {
		return "", ErrTokenSigning
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sig := ed25519.Sign(r.private, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (r *KeyRing) Verify(token, expectedAudience string, now time.Time) (Claims, error) {
	parts := strings.Split(token, ".")
	if r == nil || len(parts) != 3 {
		return Claims{}, ErrToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerBytes, &header) != nil || header.Alg != "EdDSA" || header.Kid == "" {
		return Claims{}, ErrToken
	}
	key, ok := r.public[header.Kid]
	if !ok {
		return Claims{}, ErrToken
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return Claims{}, ErrToken
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrToken
	}
	var claims Claims
	if json.Unmarshal(payload, &claims) != nil {
		return Claims{}, ErrToken
	}
	if claims.Issuer != r.issuer || claims.Audience != expectedAudience ||
		!publicid.IsUUIDv4(claims.Subject, "usr") || !publicid.IsUUIDv4(claims.Audience, "app") ||
		!publicid.IsUUIDv4(claims.SessionID, "ses") || !publicid.IsUUIDv4(claims.TokenID, "tok") {
		return Claims{}, ErrToken
	}
	if claims.ExpiresAt == 0 || claims.NotBefore == 0 || claims.IssuedAt == 0 ||
		now.After(time.Unix(claims.ExpiresAt, 0).Add(ClockSkew)) ||
		now.Add(ClockSkew).Before(time.Unix(claims.NotBefore, 0)) {
		return Claims{}, ErrToken
	}
	return claims, nil
}

func (r *KeyRing) JWKS() JWKS {
	if r == nil {
		return JWKS{}
	}
	kids := make([]string, 0, len(r.public))
	for kid := range r.public {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	keys := make([]JWK, 0, len(kids))
	for _, kid := range kids {
		keys = append(keys, JWK{
			Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid,
			X: base64.RawURLEncoding.EncodeToString(r.public[kid]),
		})
	}
	return JWKS{Keys: keys}
}

func GenerateRefreshSecret() (string, [32]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [32]byte{}, ErrTokenSigning
	}
	secret := base64.RawURLEncoding.EncodeToString(raw[:])
	return secret, HashRefreshSecret(secret), nil
}

func HashRefreshSecret(secret string) [32]byte {
	return sha256.Sum256([]byte("refresh-token\x00" + secret))
}
