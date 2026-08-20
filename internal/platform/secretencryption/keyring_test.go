package secretencryption

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func testKey(seed byte) string {
	raw := bytes.Repeat([]byte{seed}, 32)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func lookup(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestLoadKeyring(t *testing.T) {
	valid := map[string]string{
		KeysEnv:        "k1:" + testKey(1) + ",k2:" + testKey(2),
		ActiveKeyIDEnv: "k2",
	}
	kr, err := Load(lookup(valid))
	if err != nil || !kr.Enabled() || kr.ActiveKeyID() != "k2" || !kr.HasKey("k1") {
		t.Fatalf("valid keyring rejected: kr=%v err=%v", kr, err)
	}

	cases := []map[string]string{
		{KeysEnv: "k1:***", ActiveKeyIDEnv: "k1"},
		{KeysEnv: "k1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)), ActiveKeyIDEnv: "k1"},
		{KeysEnv: "k1:" + testKey(1) + ",k1:" + testKey(2), ActiveKeyIDEnv: "k1"},
		{KeysEnv: "k1:" + testKey(1), ActiveKeyIDEnv: "missing"},
		{KeysEnv: "bad id:" + testKey(1), ActiveKeyIDEnv: "bad id"},
		{KeysEnv: "k1:" + testKey(1)},
	}
	tooMany := map[string]string{ActiveKeyIDEnv: "k0"}
	for i := 0; i <= MaxKeys; i++ {
		if i > 0 { tooMany[KeysEnv] += "," }
		tooMany[KeysEnv] += string(rune('a'+i)) + ":" + testKey(byte(i+1))
	}
	tooMany[ActiveKeyIDEnv] = "a"
	cases = append(cases, tooMany)
	for i, values := range cases {
		if _, err := Load(lookup(values)); !errors.Is(err, ErrConfig) {
			t.Fatalf("case %d expected ErrConfig, got %v", i, err)
		}
	}

	kr, err = Load(lookup(map[string]string{}))
	if err != nil || kr != nil {
		t.Fatalf("empty config must disable capability: kr=%v err=%v", kr, err)
	}
}

func TestTOTPRoundTripAADTamperAndRotation(t *testing.T) {
	oldConfig := map[string]string{KeysEnv: "old:" + testKey(3), ActiveKeyIDEnv: "old"}
	oldRing, err := Load(lookup(oldConfig))
	if err != nil { t.Fatal(err) }
	ctx := Context{ApplicationID: "app_1", UserID: "usr_1", CredentialID: "totp_1", Purpose: PurposeTOTP}
	secret := []byte("01234567890123456789")
	a, err := oldRing.EncryptTOTP(ctx, secret)
	if err != nil { t.Fatal(err) }
	b, err := oldRing.EncryptTOTP(ctx, secret)
	if err != nil { t.Fatal(err) }
	if bytes.Equal(a.Nonce, b.Nonce) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("same plaintext encryption must be randomized")
	}
	plain, err := oldRing.DecryptTOTP(ctx, a)
	if err != nil || !bytes.Equal(plain, secret) { t.Fatalf("round trip failed: %v", err) }

	tampered := a
	tampered.Ciphertext = append([]byte(nil), a.Ciphertext...)
	tampered.Ciphertext[0] ^= 1
	if _, err := oldRing.DecryptTOTP(ctx, tampered); !errors.Is(err, ErrDecrypt) { t.Fatalf("tampered ciphertext accepted: %v", err) }
	tampered = a
	tampered.Nonce = append([]byte(nil), a.Nonce...)
	tampered.Nonce[0] ^= 1
	if _, err := oldRing.DecryptTOTP(ctx, tampered); !errors.Is(err, ErrDecrypt) { t.Fatalf("tampered nonce accepted: %v", err) }
	for name, wrong := range map[string]Context{
		"app": {ApplicationID: "app_2", UserID: ctx.UserID, CredentialID: ctx.CredentialID, Purpose: PurposeTOTP},
		"user": {ApplicationID: ctx.ApplicationID, UserID: "usr_2", CredentialID: ctx.CredentialID, Purpose: PurposeTOTP},
		"credential": {ApplicationID: ctx.ApplicationID, UserID: ctx.UserID, CredentialID: "totp_2", Purpose: PurposeTOTP},
		"purpose": {ApplicationID: ctx.ApplicationID, UserID: ctx.UserID, CredentialID: ctx.CredentialID, Purpose: "other"},
	} {
		if _, err := oldRing.DecryptTOTP(wrong, a); !errors.Is(err, ErrDecrypt) { t.Fatalf("wrong %s AAD accepted: %v", name, err) }
	}
	badVersion := a
	badVersion.Version = 2
	if _, err := oldRing.DecryptTOTP(ctx, badVersion); !errors.Is(err, ErrDecrypt) { t.Fatalf("unknown version accepted: %v", err) }
	badKey := a
	badKey.KeyID = "missing"
	if _, err := oldRing.DecryptTOTP(ctx, badKey); !errors.Is(err, ErrDecrypt) { t.Fatalf("unknown key accepted: %v", err) }

	rotated, err := Load(lookup(map[string]string{
		KeysEnv:        "old:" + testKey(3) + ",new:" + testKey(4),
		ActiveKeyIDEnv: "new",
	}))
	if err != nil { t.Fatal(err) }
	if _, err := rotated.DecryptTOTP(ctx, a); err != nil { t.Fatalf("old key stopped decrypting after rotation: %v", err) }
	fresh, err := rotated.EncryptTOTP(ctx, secret)
	if err != nil { t.Fatal(err) }
	if fresh.KeyID != "new" { t.Fatalf("new encryption used key %q", fresh.KeyID) }
}

func TestErrorsDoNotContainSecretMaterial(t *testing.T) {
	secretValue := testKey(9)
	_, err := Load(lookup(map[string]string{KeysEnv: "k:" + secretValue, ActiveKeyIDEnv: "missing"}))
	if !errors.Is(err, ErrConfig) { t.Fatalf("expected config error, got %v", err) }
	if bytes.Contains([]byte(err.Error()), []byte(secretValue)) { t.Fatal("config error leaked key material") }
}
