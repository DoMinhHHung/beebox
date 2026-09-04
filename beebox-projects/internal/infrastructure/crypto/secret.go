package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

type SecretBox struct {
	key []byte
}

func NewSecretBox(kekHex string) (SecretBox, error) {
	kekHex = strings.TrimSpace(kekHex)
	if kekHex == "" {
		return SecretBox{}, fmt.Errorf("empty kek")
	}
	key, err := hex.DecodeString(kekHex)
	if err != nil || len(key) != 32 {
		return SecretBox{}, fmt.Errorf("kek must be 32-byte hex")
	}
	return SecretBox{key: key}, nil
}

func (b SecretBox) Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return hex.EncodeToString(out), nil
}

func (b SecretBox) Decrypt(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := hex.DecodeString(enc)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext short")
	}
	nonce, sealed := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
