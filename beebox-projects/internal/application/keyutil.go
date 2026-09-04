package application

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	beeboxid "github.com/DoMinhHHung/beebox/beebox-id"
	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

func keyPrefix(kind, env string) string {
	switch kind + ":" + env {
	case domain.KeyKindPublishable + ":" + domain.EnvTest:
		return "pk_test_"
	case domain.KeyKindPublishable + ":" + domain.EnvLive:
		return "pk_live_"
	case domain.KeyKindSecret + ":" + domain.EnvTest:
		return "sk_test_"
	case domain.KeyKindSecret + ":" + domain.EnvLive:
		return "sk_live_"
	default:
		return ""
	}
}

func hashSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func issueKey(projectID uuid.UUID, kind, env string) (domain.IssuedKey, error) {
	head := keyPrefix(kind, env)
	if head == "" {
		return domain.IssuedKey{}, domain.ErrInvalidInput
	}
	var rnd [24]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return domain.IssuedKey{}, err
	}
	secretPart := hex.EncodeToString(rnd[:])
	raw := head + secretPart
	id, err := beeboxid.New()
	if err != nil {
		return domain.IssuedKey{}, err
	}
	display := head
	if len(secretPart) >= 8 {
		display = head + secretPart[:8]
	}
	return domain.IssuedKey{
		Key: domain.APIKey{
			ID:         id,
			ProjectID:  projectID,
			Prefix:     display,
			SecretHash: hashSecret(raw),
			Kind:       kind,
			Env:        env,
		},
		Secret: raw,
	}, nil
}

func knownModule(name string) bool {
	for _, m := range domain.KnownModules {
		if m == name {
			return true
		}
	}
	return false
}

func moduleAllowed(planSlug, name string) bool {
	if !knownModule(name) {
		return false
	}
	if planSlug == "pro" {
		return true
	}
	return name == domain.ModuleAuthPassword || name == domain.ModuleUsersProfile
}
