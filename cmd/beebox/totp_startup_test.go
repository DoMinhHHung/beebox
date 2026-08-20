package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	authpostgres "github.com/DoMinhHHung/beebox/internal/authentication/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/secretencryption"
)

type totpReferenceStoreStub struct {
	refs []authpostgres.SecretEncryptionReference
	err  error
}

func (s totpReferenceStoreStub) TOTPSecretEncryptionReferences(context.Context) ([]authpostgres.SecretEncryptionReference, error) {
	return s.refs, s.err
}

func TestTOTPStartupAllowsUnconfiguredCapabilityWhenNoCiphertextExists(t *testing.T) {
	keyring, err := loadTOTPSecretEncryption(testLookup(nil), totpReferenceStoreStub{})
	if err != nil || keyring != nil {
		t.Fatalf("keyring=%v err=%v", keyring, err)
	}
}

func TestTOTPStartupFailsClosedForPersistedUnknownKeyOrVersion(t *testing.T) {
	values := map[string]string{
		secretencryption.KeysEnv:        "current:" + startupTestKey(1),
		secretencryption.ActiveKeyIDEnv: "current",
	}
	for name, refs := range map[string][]authpostgres.SecretEncryptionReference{
		"missing historical key": {{Version: secretencryption.Version1, KeyID: "old"}},
		"unsupported version":    {{Version: 2, KeyID: "current"}},
	} {
		t.Run(name, func(t *testing.T) {
			keyring, err := loadTOTPSecretEncryption(testLookup(values), totpReferenceStoreStub{refs: refs})
			if !errors.Is(err, errTOTPEncryptionReadiness) || keyring != nil {
				t.Fatalf("keyring=%v err=%v", keyring, err)
			}
		})
	}
}

func TestTOTPStartupSupportsAdditiveRotationWithHistoricalDecryptKey(t *testing.T) {
	values := map[string]string{
		secretencryption.KeysEnv:        "old:" + startupTestKey(1) + ",new:" + startupTestKey(2),
		secretencryption.ActiveKeyIDEnv: "new",
	}
	keyring, err := loadTOTPSecretEncryption(testLookup(values), totpReferenceStoreStub{refs: []authpostgres.SecretEncryptionReference{{Version: secretencryption.Version1, KeyID: "old"}}})
	if err != nil || keyring == nil || !keyring.Enabled() || keyring.ActiveKeyID() != "new" || !keyring.HasKey("old") {
		t.Fatalf("keyring=%v err=%v", keyring, err)
	}
}

func TestTOTPStartupRejectsMalformedConfiguredKeyringEvenWithoutPersistedData(t *testing.T) {
	values := map[string]string{
		secretencryption.KeysEnv:        "current:not-base64url",
		secretencryption.ActiveKeyIDEnv: "current",
	}
	keyring, err := loadTOTPSecretEncryption(testLookup(values), totpReferenceStoreStub{})
	if !errors.Is(err, errTOTPEncryptionReadiness) || keyring != nil {
		t.Fatalf("keyring=%v err=%v", keyring, err)
	}
}

func TestTOTPStartupCollapsesReferenceStoreFailureToSafeReadinessError(t *testing.T) {
	const secretMarker = "must-not-leak-secret"
	keyring, err := loadTOTPSecretEncryption(testLookup(nil), totpReferenceStoreStub{err: errors.New(secretMarker)})
	if !errors.Is(err, errTOTPEncryptionReadiness) || keyring != nil {
		t.Fatalf("keyring=%v err=%v", keyring, err)
	}
	if bytes.Contains([]byte(err.Error()), []byte(secretMarker)) {
		t.Fatalf("startup error leaked dependency detail: %q", err)
	}
}

func startupTestKey(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}
