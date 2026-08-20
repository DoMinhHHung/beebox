package secretencryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	KeysEnv        = "BEEBOX_SECRET_ENCRYPTION_KEYS"
	ActiveKeyIDEnv = "BEEBOX_SECRET_ENCRYPTION_ACTIVE_KEY_ID"
	MaxKeys        = 8
	Version1       = 1
	PurposeTOTP    = "totp"
	totpHKDFInfo   = "beebox:v1:secret-encryption:totp"
)

var (
	ErrConfig      = errors.New("invalid secret encryption configuration")
	ErrUnavailable = errors.New("secret encryption unavailable")
	ErrDecrypt     = errors.New("secret decryption failed")
	keyIDPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
)

type LookupEnv func(string) (string, bool)

type Keyring struct {
	keys   map[string][32]byte
	active string
}

type Envelope struct {
	Version    int
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

type Context struct {
	ApplicationID string
	UserID        string
	CredentialID  string
	Purpose       string
}

func Load(lookup LookupEnv) (*Keyring, error) {
	if lookup == nil {
		return nil, ErrConfig
	}
	raw, hasKeys := lookup(KeysEnv)
	active, hasActive := lookup(ActiveKeyIDEnv)
	if (!hasKeys || strings.TrimSpace(raw) == "") && (!hasActive || strings.TrimSpace(active) == "") {
		return nil, nil
	}
	if !hasKeys || !hasActive || raw == "" || active == "" || strings.TrimSpace(raw) != raw || strings.TrimSpace(active) != active || !keyIDPattern.MatchString(active) {
		return nil, ErrConfig
	}
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > MaxKeys {
		return nil, ErrConfig
	}
	keys := make(map[string][32]byte, len(parts))
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part || strings.Count(part, ":") != 1 {
			return nil, ErrConfig
		}
		id, encoded, ok := strings.Cut(part, ":")
		if !ok || !keyIDPattern.MatchString(id) || encoded == "" {
			return nil, ErrConfig
		}
		if _, duplicate := keys[id]; duplicate {
			return nil, ErrConfig
		}
		rawKey, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(rawKey) != 32 {
			return nil, ErrConfig
		}
		var key [32]byte
		copy(key[:], rawKey)
		keys[id] = key
	}
	if _, ok := keys[active]; !ok {
		return nil, ErrConfig
	}
	return &Keyring{keys: keys, active: active}, nil
}

func (k *Keyring) Enabled() bool { return k != nil && len(k.keys) > 0 && k.active != "" }

func (k *Keyring) ActiveKeyID() string {
	if k == nil {
		return ""
	}
	return k.active
}

func (k *Keyring) HasKey(id string) bool {
	if k == nil {
		return false
	}
	_, ok := k.keys[id]
	return ok
}

func (k *Keyring) EncryptTOTP(ctx Context, plaintext []byte) (Envelope, error) {
	if !k.Enabled() || len(plaintext) == 0 || !validContext(ctx, PurposeTOTP) {
		return Envelope{}, ErrUnavailable
	}
	root := k.keys[k.active]
	aead, err := totpAEAD(root)
	if err != nil {
		return Envelope{}, ErrUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, ErrUnavailable
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad(Version1, PurposeTOTP, ctx))
	return Envelope{Version: Version1, KeyID: k.active, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (k *Keyring) DecryptTOTP(ctx Context, env Envelope) ([]byte, error) {
	if k == nil || env.Version != Version1 || !keyIDPattern.MatchString(env.KeyID) || len(env.Nonce) != 12 || len(env.Ciphertext) == 0 || !validContext(ctx, PurposeTOTP) {
		return nil, ErrDecrypt
	}
	root, ok := k.keys[env.KeyID]
	if !ok {
		return nil, ErrDecrypt
	}
	aead, err := totpAEAD(root)
	if err != nil {
		return nil, ErrDecrypt
	}
	plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, aad(env.Version, PurposeTOTP, ctx))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

func totpAEAD(root [32]byte) (cipher.AEAD, error) {
	r := hkdf.New(sha256.New, root[:], nil, []byte(totpHKDFInfo))
	derived := make([]byte, 32)
	if _, err := io.ReadFull(r, derived); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func validContext(ctx Context, purpose string) bool {
	return ctx.Purpose == purpose && ctx.ApplicationID != "" && ctx.UserID != "" && ctx.CredentialID != "" &&
		!strings.ContainsRune(ctx.ApplicationID, '\x00') && !strings.ContainsRune(ctx.UserID, '\x00') && !strings.ContainsRune(ctx.CredentialID, '\x00')
}

func aad(version int, purpose string, ctx Context) []byte {
	return []byte(fmt.Sprintf("beebox-secret-encryption\x00v%d\x00%s\x00%s\x00%s\x00%s", version, purpose, ctx.ApplicationID, ctx.UserID, ctx.CredentialID))
}
