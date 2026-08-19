package authentication

import (
	"context"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
)

type SocialCompletionFinalize struct {
	ApplicationInstanceID applicationinstance.InternalID
	CompletionCodeHash    [32]byte
	ClientCodeChallenge   string
	SessionPublicID       string
	RefreshVerifier       [32]byte
	IdleExpiresAt         time.Time
	ExpiresAt             time.Time
	CorrelationID         audit.CorrelationID
}

type SocialCompletionResult struct {
	UserPublicID        string
	ApplicationPublicID string
}

type SocialCompletionPersistence interface {
	ExchangeSocialCompletion(context.Context, SocialCompletionFinalize) (SocialCompletionResult, error)
}
