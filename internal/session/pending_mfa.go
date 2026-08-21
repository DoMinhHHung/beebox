package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

type PendingMFA struct {
	Token            string
	ExpiresAt        time.Time
	AvailableMethods []string
}

type PendingMFAContext struct {
	ApplicationInstanceID applicationinstance.InternalID
	PrimaryMethod         string
	PrimaryContext        string
}

type PendingMFAContextLoader interface {
	LoadPendingMFAContext(context.Context, string, [32]byte) (PendingMFAContext, error)
}

func ResolvePendingMFAContext(ctx context.Context, loader PendingMFAContextLoader, token string) (PendingMFAContext, error) {
	if loader == nil || token == "" {
		return PendingMFAContext{}, ErrInvalidCredentials
	}
	publicID, tokenHash, ok := parsePendingMFAToken(token)
	if !ok {
		return PendingMFAContext{}, ErrInvalidCredentials
	}
	out, err := loader.LoadPendingMFAContext(ctx, publicID, tokenHash)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return PendingMFAContext{}, ctxErr
		}
		return PendingMFAContext{}, ErrInvalidCredentials
	}
	if !out.ApplicationInstanceID.Valid() || out.PrimaryMethod == "" || out.PrimaryContext == "" {
		return PendingMFAContext{}, ErrInvalidCredentials
	}
	return out, nil
}

func pendingMFAMethods(recoveryCodeAvailable bool) []string {
	methods := []string{"totp"}
	if recoveryCodeAvailable {
		methods = append(methods, "recovery_code")
	}
	return methods
}

func preparePendingMFA(method, primaryContext string, now time.Time) (authentication.PendingMFAWrite, string, error) {
	publicID, err := publicid.NewUUIDv4("mfp")
	if err != nil {
		return authentication.PendingMFAWrite{}, "", ErrSessionUnavailable
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return authentication.PendingMFAWrite{}, "", ErrSessionUnavailable
	}
	hashInput := make([]byte, 0, len("beebox:v1:pending-mfa-token\x00")+len(secret))
	hashInput = append(hashInput, "beebox:v1:pending-mfa-token\x00"...)
	hashInput = append(hashInput, secret...)
	hash := sha256.Sum256(hashInput)
	raw := base64.RawURLEncoding.EncodeToString(secret)
	write := authentication.PendingMFAWrite{
		PublicID:       publicID,
		TokenHash:      hash,
		PrimaryMethod:  method,
		PrimaryContext: primaryContext,
		CreatedAt:      now.UTC(),
		ExpiresAt:      now.UTC().Add(authentication.PendingMFATTL),
	}
	if !write.Valid() {
		return authentication.PendingMFAWrite{}, "", ErrSessionUnavailable
	}
	return write, publicID + "." + raw, nil
}

func parsePendingMFAToken(token string) (string, [32]byte, bool) {
	var zero [32]byte
	publicID, raw, ok := strings.Cut(token, ".")
	if !ok || !publicid.IsUUIDv4(publicID, "mfp") || strings.Contains(raw, ".") {
		return "", zero, false
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(secret) != 32 {
		return "", zero, false
	}
	hashInput := make([]byte, 0, len("beebox:v1:pending-mfa-token\x00")+len(secret))
	hashInput = append(hashInput, "beebox:v1:pending-mfa-token\x00"...)
	hashInput = append(hashInput, secret...)
	return publicID, sha256.Sum256(hashInput), true
}
