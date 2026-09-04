package domain

import (
	"context"

	"github.com/google/uuid"
)

const (
	ModuleAuthPassword       = "auth.password"
	ModuleAuthOTP            = "auth.otp"
	ModuleAuthOAuthGoogle    = "auth.oauth.google"
	ModuleUsersProfile       = "users.profile"
	ModuleDataCollections    = "data.collections"
	ModuleFileStorage        = "file.storage"
	ModuleRealtimeCollection = "realtime.collection"
)

var KnownModules = []string{
	ModuleAuthPassword,
	ModuleAuthOTP,
	ModuleAuthOAuthGoogle,
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
