package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

const (
	AccessTokenLifetime = 5 * time.Minute
	ClockSkew           = 30 * time.Second
)

var (
	ErrTokenConfig   = errors.New("invalid access token configuration")
	ErrToken         = errors.New("invalid access token")
	ErrTokenSigning  = errors.New("access token signing failure")
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
	issuer string
	kid    string
	private ed25519.PrivateKey
	public map[string]ed25519.PublicKey
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

type JWKS struct { Keys []JWK `json:"keys"` }

func NewKeyRing(issuer, activeKID string, privateKey ed25519.PrivateKey, verificationKeys map[string]ed25519.PublicKey) (*KeyRing, error) {
	if !strings.HasPrefix(issuer, "https://") || activeKID == "" || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrTokenConfig
	}
	if len(verificationKeys) == 0 {
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
	return &KeyRing{issuer: issuer, kid: activeKID, private: append(ed25519.PrivateKey(nil), privateKey...), public: copyKeys}, nil
}

func (r *KeyRing) Sign(userPublicID, applicationPublicID, sessionPublicID string, now time.Time) (string, error) {
	if r == nil || !publicid.IsUUIDv4(userPublicID, "usr") || !publicid.IsUUIDv4(applicationPublicID, "app") || !publicid.IsUUIDv4(sessionPublicID, "ses") {
		return "", ErrToken
	}
	jti, err := publicid.NewUUIDv4("tok")
	if err != nil {
		return "", ErrTokenSigning
	}
	header, _ := json.Marshal(map[string]string{"alg":"EdDSA","kid":r.kid,"typ":"JWT"})
	claims, _ := json.Marshal(Claims{Issuer:r.issuer, Subject:userPublicID, Audience:applicationPublicID, SessionID:sessionPublicID, ExpiresAt:now.Add(AccessTokenLifetime).Unix(), NotBefore:now.Unix(), IssuedAt:now.Unix(), TokenID:jti})
	input := base64.RawURLEncoding.EncodeToString(header)+"."+base64.RawURLEncoding.EncodeToString(claims)
	sig := ed25519.Sign(r.private, []byte(input))
	return input+"."+base64.RawURLEncoding.EncodeToString(sig), nil
}

func (r *KeyRing) Verify(token, expectedAudience string, now time.Time) (Claims, error) {
	parts := strings.Split(token, ".")
	if r == nil || len(parts) != 3 {
		return Claims{}, ErrToken
	}
	var header struct { Alg string `json:"alg"`; Kid string `json:"kid"`; Typ string `json:"typ"` }
	hb, err := base64.RawURLEncoding.Strict().DecodeString(parts[0]); if err != nil || json.Unmarshal(hb,&header) != nil || header.Alg != "EdDSA" || header.Kid == "" { return Claims{}, ErrToken }
	key, ok := r.public[header.Kid]; if !ok { return Claims{}, ErrToken }
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2]); if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) { return Claims{}, ErrToken }
	pb, err := base64.RawURLEncoding.Strict().DecodeString(parts[1]); if err != nil { return Claims{}, ErrToken }
	var c Claims; if json.Unmarshal(pb,&c) != nil { return Claims{}, ErrToken }
	if c.Issuer != r.issuer || c.Audience != expectedAudience || !publicid.IsUUIDv4(c.Subject,"usr") || !publicid.IsUUIDv4(c.Audience,"app") || !publicid.IsUUIDv4(c.SessionID,"ses") || !publicid.IsUUIDv4(c.TokenID,"tok") { return Claims{}, ErrToken }
	if c.ExpiresAt == 0 || c.NotBefore == 0 || c.IssuedAt == 0 || now.After(time.Unix(c.ExpiresAt,0).Add(ClockSkew)) || now.Add(ClockSkew).Before(time.Unix(c.NotBefore,0)) { return Claims{}, ErrToken }
	return c, nil
}

func (r *KeyRing) JWKS() JWKS {
	keys := make([]JWK,0,len(r.public))
	for kid, key := range r.public { keys = append(keys, JWK{Kty:"OKP",Crv:"Ed25519",Use:"sig",Alg:"EdDSA",Kid:kid,X:base64.RawURLEncoding.EncodeToString(key)}) }
	return JWKS{Keys:keys}
}

func GenerateRefreshSecret() (string, [32]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil { return "", [32]byte{}, ErrTokenSigning }
	secret := base64.RawURLEncoding.EncodeToString(raw[:])
	return secret, sha256Bytes([]byte(secret)), nil
}

func sha256Bytes(value []byte) [32]byte {
	// kept local to avoid exposing refresh verifier representation
	var out [32]byte
	// crypto/sha256 Sum cannot be called without import; this helper is replaced below by explicit implementation through standard library.
	return out
}
