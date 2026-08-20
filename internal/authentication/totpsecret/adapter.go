package totpsecret

import (
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
	"github.com/DoMinhHHung/beebox/internal/platform/secretencryption"
)

type Adapter struct {
	keyring *secretencryption.Keyring
}

func New(keyring *secretencryption.Keyring) *Adapter { return &Adapter{keyring: keyring} }

func (a *Adapter) Enabled() bool { return a != nil && a.keyring != nil && a.keyring.Enabled() }

func (a *Adapter) EncryptTOTP(ctx authentication.TOTPSecretContext, plaintext []byte) (authentication.TOTPSecretEnvelope, error) {
	if !a.Enabled() {
		return authentication.TOTPSecretEnvelope{}, authentication.ErrTOTPUnavailable
	}
	env, err := a.keyring.EncryptTOTP(secretencryption.Context{
		ApplicationID: stringID(int64(ctx.ApplicationID)),
		UserID:        stringID(int64(ctx.UserID)),
		CredentialID:  ctx.CredentialID,
		Purpose:       secretencryption.PurposeTOTP,
	}, plaintext)
	if err != nil {
		return authentication.TOTPSecretEnvelope{}, authentication.ErrTOTPUnavailable
	}
	return authentication.TOTPSecretEnvelope{Version: env.Version, KeyID: env.KeyID, Nonce: env.Nonce, Ciphertext: env.Ciphertext}, nil
}

func (a *Adapter) DecryptTOTP(ctx authentication.TOTPSecretContext, env authentication.TOTPSecretEnvelope) ([]byte, error) {
	if !a.Enabled() {
		return nil, authentication.ErrTOTPUnavailable
	}
	plaintext, err := a.keyring.DecryptTOTP(secretencryption.Context{
		ApplicationID: stringID(int64(ctx.ApplicationID)),
		UserID:        stringID(int64(ctx.UserID)),
		CredentialID:  ctx.CredentialID,
		Purpose:       secretencryption.PurposeTOTP,
	}, secretencryption.Envelope{Version: env.Version, KeyID: env.KeyID, Nonce: env.Nonce, Ciphertext: env.Ciphertext})
	if err != nil {
		return nil, authentication.ErrTOTPUnavailable
	}
	return plaintext, nil
}

func (a *Adapter) NewEnrollmentID() (string, error) { return publicid.NewUUIDv4("mfe") }
func (a *Adapter) NewCredentialID() (string, error) { return publicid.NewUUIDv4("mfc") }

func stringID(id int64) string {
	if id <= 0 {
		return ""
	}
	// Decimal internal IDs are used only as authenticated AEAD context and never leave the process.
	return decimal(id)
}

func decimal(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
