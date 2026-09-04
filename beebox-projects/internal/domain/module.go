package domain

import (
	"context"

	"github.com/google/uuid"
)

const (
	ModuleAuthPassword       = "auth.password"
	ModuleAuthOTP            = "auth.otp"
	ModuleAuthOAuthApple     = "auth.oauth.apple"
	ModuleAuthOAuthGitLab    = "auth.oauth.gitlab"
	ModuleAuthOAuthLinkedIn  = "auth.oauth.linkedin"
	ModuleAuthOAuthSlack     = "auth.oauth.slack"
	ModuleAuthOAuthTwitch    = "auth.oauth.twitch"
	ModuleAuthOAuthFacebook  = "auth.oauth.facebook"
	ModuleAuthOAuthGoogle    = "auth.oauth.google"
	ModuleAuthOAuthMicrosoft = "auth.oauth.microsoft"
	ModuleAuthOAuthGitHub    = "auth.oauth.github"
	ModuleAuthOAuthX         = "auth.oauth.x"
	ModuleAuthOAuthOIDC      = "auth.oauth.oidc"
	ModuleUsersProfile       = "users.profile"
	ModuleDataCollections    = "data.collections"
	ModuleFileStorage        = "file.storage"
	ModuleRealtimeCollection = "realtime.collection"
)

var KnownModules = []string{
	ModuleAuthPassword,
	ModuleAuthOTP,
	ModuleAuthOAuthApple,
	ModuleAuthOAuthGitLab,
	ModuleAuthOAuthLinkedIn,
	ModuleAuthOAuthSlack,
	ModuleAuthOAuthTwitch,
	ModuleAuthOAuthFacebook,
	ModuleAuthOAuthGoogle,
	ModuleAuthOAuthMicrosoft,
	ModuleAuthOAuthGitHub,
	ModuleAuthOAuthX,
	ModuleAuthOAuthOIDC,
	ModuleUsersProfile,
	ModuleDataCollections,
	ModuleFileStorage,
	ModuleRealtimeCollection,
}

var DefaultModules = []string{
	ModuleAuthPassword,
	ModuleUsersProfile,
}

type ModuleRepository interface {
	Replace(ctx context.Context, ownerID, projectID uuid.UUID, names []string) error
	ListByProject(ctx context.Context, ownerID, projectID uuid.UUID) ([]string, error)
	ListByProjectID(ctx context.Context, projectID uuid.UUID) ([]string, error)
}
