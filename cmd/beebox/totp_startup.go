package main

import (
	"context"
	"errors"
	"time"

	authpostgres "github.com/DoMinhHHung/beebox/internal/authentication/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/config"
	"github.com/DoMinhHHung/beebox/internal/platform/secretencryption"
)

const totpEncryptionStartupTimeout = 5 * time.Second

var errTOTPEncryptionReadiness = errors.New("verify TOTP secret encryption readiness")

func loadTOTPSecretEncryption(lookup config.LookupEnv, store *authpostgres.Store) (*secretencryption.Keyring, error) {
	if lookup == nil || store == nil {
		return nil, errTOTPEncryptionReadiness
	}
	keyring, err := secretencryption.Load(secretencryption.LookupEnv(lookup))
	if err != nil {
		return nil, errTOTPEncryptionReadiness
	}
	ctx, cancel := context.WithTimeout(context.Background(), totpEncryptionStartupTimeout)
	defer cancel()
	refs, err := store.TOTPSecretEncryptionReferences(ctx)
	if err != nil {
		return nil, errTOTPEncryptionReadiness
	}
	if len(refs) == 0 {
		return keyring, nil
	}
	if keyring == nil || !keyring.Enabled() {
		return nil, errTOTPEncryptionReadiness
	}
	for _, ref := range refs {
		if ref.Version != secretencryption.Version1 || !keyring.HasKey(ref.KeyID) {
			return nil, errTOTPEncryptionReadiness
		}
	}
	return keyring, nil
}
