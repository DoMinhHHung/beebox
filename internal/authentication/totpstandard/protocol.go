package totpstandard

import (
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/DoMinhHHung/beebox/internal/authentication"
)

const (
	PeriodSeconds = uint(30)
	SecretBytes   = uint(20)
)

var ErrProtocol = errors.New("TOTP protocol failure")

var rawBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type Protocol struct{}

func New() *Protocol { return &Protocol{} }

func (p *Protocol) Generate(applicationID, userID string) (authentication.TOTPProtocolEnrollment, error) {
	if p == nil || applicationID == "" || userID == "" {
		return authentication.TOTPProtocolEnrollment{}, ErrProtocol
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "BeeBox",
		AccountName: applicationID + ":" + userID,
		Period:      PeriodSeconds,
		SecretSize:  SecretBytes,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return authentication.TOTPProtocolEnrollment{}, ErrProtocol
	}
	encoded := key.Secret()
	raw, err := rawBase32.DecodeString(encoded)
	if err != nil || len(raw) != int(SecretBytes) {
		return authentication.TOTPProtocolEnrollment{}, ErrProtocol
	}
	return authentication.TOTPProtocolEnrollment{SecretRaw: raw, Secret: encoded, URI: key.URL()}, nil
}

func (p *Protocol) Verify(secretRaw []byte, code string, serverTime time.Time) (int64, bool, error) {
	if p == nil || len(secretRaw) == 0 || !validCode(code) || serverTime.Unix() < 0 {
		return 0, false, ErrProtocol
	}
	secret := rawBase32.EncodeToString(secretRaw)
	current := serverTime.UTC().Unix() / int64(PeriodSeconds)
	for _, timestep := range []int64{current, current - 1, current + 1} {
		if timestep < 0 {
			continue
		}
		at := time.Unix(timestep*int64(PeriodSeconds), 0).UTC()
		valid, err := totp.ValidateCustom(code, secret, at, totp.ValidateOpts{
			Period:    PeriodSeconds,
			Skew:      0,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false, ErrProtocol
		}
		if valid {
			return timestep, true, nil
		}
	}
	return 0, false, nil
}

func (p *Protocol) CodeForTest(secretRaw []byte, at time.Time) (string, error) {
	if p == nil || len(secretRaw) == 0 {
		return "", ErrProtocol
	}
	code, err := totp.GenerateCodeCustom(rawBase32.EncodeToString(secretRaw), at.UTC(), totp.ValidateOpts{
		Period:    PeriodSeconds,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", fmt.Errorf("%w", ErrProtocol)
	}
	return code, nil
}

func validCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}
