package application

import (
	"context"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
	"github.com/google/uuid"
)

var oauthSlugs = map[string]struct{}{
	"apple": {}, "gitlab": {}, "linkedin": {}, "slack": {}, "twitch": {},
	"facebook": {}, "google": {}, "microsoft": {}, "github": {}, "x": {}, "oidc": {},
}

type SecretBox interface {
	Encrypt(plain string) (string, error)
	Decrypt(enc string) (string, error)
}

type PutOAuthProvider struct {
	Projects domain.ProjectRepository
	OAuth    domain.OAuthProviderRepository
	Catalog  domain.PlanCatalog
	Box      SecretBox
}

type PutOAuthInput struct {
	OwnerID      uuid.UUID
	ProjectID    uuid.UUID
	Slug         string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Enabled      bool
	Extra        map[string]string
}

func (u PutOAuthProvider) Execute(ctx context.Context, in PutOAuthInput) (domain.OAuthProvider, error) {
	slug := strings.ToLower(strings.TrimSpace(in.Slug))
	if _, ok := oauthSlugs[slug]; !ok {
		return domain.OAuthProvider{}, domain.ErrInvalidInput
	}
	project, err := u.Projects.FindByID(ctx, in.OwnerID, in.ProjectID)
	if err != nil {
		return domain.OAuthProvider{}, err
	}
	plan, err := u.Catalog.FindBySlug(ctx, project.PlanSlug)
	if err != nil {
		return domain.OAuthProvider{}, err
	}
	if !plan.Limits.OAuth {
		return domain.OAuthProvider{}, domain.ErrPlanLimit
	}
	if slug == "oidc" && strings.TrimSpace(in.Extra["issuer"]) == "" {
		return domain.OAuthProvider{}, domain.ErrInvalidInput
	}
	enc := ""
	if strings.TrimSpace(in.ClientSecret) != "" {
		if u.Box == nil {
			return domain.OAuthProvider{}, domain.ErrInvalidInput
		}
		enc, err = u.Box.Encrypt(in.ClientSecret)
		if err != nil {
			return domain.OAuthProvider{}, err
		}
	}
	newID, err := id.New()
	if err != nil {
		return domain.OAuthProvider{}, err
	}
	item := domain.OAuthProvider{
		ID:          newID,
		ProjectID:   in.ProjectID,
		Slug:        slug,
		ClientID:    strings.TrimSpace(in.ClientID),
		SecretEnc:   enc,
		Extra:       in.Extra,
		RedirectURI: strings.TrimSpace(in.RedirectURI),
		Enabled:     in.Enabled,
	}
	if item.Extra == nil {
		item.Extra = map[string]string{}
	}
	if err := u.OAuth.Upsert(ctx, in.OwnerID, item); err != nil {
		return domain.OAuthProvider{}, err
	}
	stored, err := u.OAuth.Find(ctx, in.OwnerID, in.ProjectID, slug)
	if err != nil {
		return item, nil
	}
	stored.ClientSecret = ""
	return stored, nil
}

type GetOAuthProvider struct {
	Projects domain.ProjectRepository
	OAuth    domain.OAuthProviderRepository
}

func (u GetOAuthProvider) Execute(ctx context.Context, ownerID, projectID uuid.UUID, slug string) (domain.OAuthProvider, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if _, ok := oauthSlugs[slug]; !ok {
		return domain.OAuthProvider{}, domain.ErrInvalidInput
	}
	if _, err := u.Projects.FindByID(ctx, ownerID, projectID); err != nil {
		return domain.OAuthProvider{}, err
	}
	item, err := u.OAuth.Find(ctx, ownerID, projectID, slug)
	if err != nil {
		return domain.OAuthProvider{}, err
	}
	item.ClientSecret = ""
	return item, nil
}

type InternalOAuthProvider struct {
	OAuth domain.OAuthProviderRepository
	Box   SecretBox
}

func (u InternalOAuthProvider) Execute(ctx context.Context, projectID uuid.UUID, slug string) (domain.OAuthProvider, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	item, err := u.OAuth.FindByProject(ctx, projectID, slug)
	if err != nil {
		return domain.OAuthProvider{}, err
	}
	if !item.Enabled {
		return domain.OAuthProvider{}, domain.ErrNotFound
	}
	if u.Box != nil && item.SecretEnc != "" {
		plain, err := u.Box.Decrypt(item.SecretEnc)
		if err != nil {
			return domain.OAuthProvider{}, err
		}
		item.ClientSecret = plain
	}
	return item, nil
}
