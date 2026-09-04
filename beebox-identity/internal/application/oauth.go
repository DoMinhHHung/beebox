package application

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/DoMinhHHung/beebox/beebox-identity/internal/infrastructure/oauth"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
	"github.com/google/uuid"
)

type OAuthCredentialStore interface {
	Get(ctx context.Context, projectID uuid.UUID, slug string) (oauth.Credentials, error)
}

type OAuthStart struct {
	States domain.OAuthStateRepository
	Creds  OAuthCredentialStore
	Now    func() time.Time
}

type OAuthStartResult struct {
	Location string
}

func (u OAuthStart) Execute(ctx context.Context, scope domain.Scope, slug string) (OAuthStartResult, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := requireOAuthModule(scope, slug); err != nil {
		return OAuthStartResult{}, err
	}
	provider, err := oauth.Lookup(slug)
	if err != nil {
		return OAuthStartResult{}, domain.ErrInvalidInput
	}
	creds, err := u.Creds.Get(ctx, scope.ProjectID, slug)
	if err != nil {
		return OAuthStartResult{}, err
	}
	if strings.TrimSpace(creds.RedirectURI) == "" || strings.TrimSpace(creds.ClientID) == "" {
		return OAuthStartResult{}, domain.ErrInvalidInput
	}
	verifier, _, err := oauth.NewPKCE()
	if err != nil {
		return OAuthStartResult{}, err
	}
	state, err := oauth.NewState()
	if err != nil {
		return OAuthStartResult{}, err
	}
	nonce, err := oauth.NewState()
	if err != nil {
		return OAuthStartResult{}, err
	}
	now := u.now()
	if err := u.States.Create(ctx, domain.OAuthState{
		StateHash: oauth.HashState(state),
		ProjectID: scope.ProjectID,
		Env:       scope.Env,
		Slug:      slug,
		Verifier:  verifier,
		Redirect:  creds.RedirectURI,
		Nonce:     nonce,
		ExpiresAt: now.Add(domain.OAuthStateTTL),
		CreatedAt: now,
	}); err != nil {
		return OAuthStartResult{}, err
	}
	location, _, err := provider.AuthURL(oauth.AuthRequest{
		ClientID:    creds.ClientID,
		RedirectURI: creds.RedirectURI,
		State:       state,
		Verifier:    verifier,
		Nonce:       nonce,
		Extra:       creds.Extra,
	})
	if err != nil {
		return OAuthStartResult{}, err
	}
	return OAuthStartResult{Location: location}, nil
}

func (u OAuthStart) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

type OAuthCallback struct {
	Users      domain.UserRepository
	Identities domain.IdentityRepository
	Sessions   domain.SessionRepository
	States     domain.OAuthStateRepository
	Creds      OAuthCredentialStore
	Tokens     domain.TokenSource
	Now        func() time.Time
	TTL        time.Duration
}

func (u OAuthCallback) Execute(ctx context.Context, slug, code, state, appleUser string) (AuthResult, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if strings.TrimSpace(state) == "" || strings.TrimSpace(code) == "" {
		return AuthResult{}, domain.ErrUnauthorized
	}
	saved, err := u.States.TakeByHash(ctx, oauth.HashState(state))
	if err != nil {
		return AuthResult{}, domain.ErrUnauthorized
	}
	now := u.now()
	if !saved.ExpiresAt.After(now) || saved.Slug != slug {
		return AuthResult{}, domain.ErrUnauthorized
	}
	provider, err := oauth.Lookup(slug)
	if err != nil {
		return AuthResult{}, domain.ErrUnauthorized
	}
	creds, err := u.Creds.Get(ctx, saved.ProjectID, slug)
	if err != nil {
		return AuthResult{}, domain.ErrUnauthorized
	}
	if creds.RedirectURI != saved.Redirect {
		return AuthResult{}, domain.ErrUnauthorized
	}
	if creds.Extra == nil {
		creds.Extra = map[string]string{}
	}
	if saved.Nonce != "" {
		creds.Extra["nonce"] = saved.Nonce
	}
	profile, err := provider.Exchange(ctx, code, saved.Verifier, saved.Redirect, creds)
	if err != nil {
		return AuthResult{}, domain.ErrUnauthorized
	}
	if appleUser != "" && slug == oauth.SlugApple {
		name, given, family := oauth.ParseAppleUser(appleUser)
		if profile.Name == "" {
			profile.Name = name
		}
		if profile.GivenName == "" {
			profile.GivenName = given
		}
		if profile.FamilyName == "" {
			profile.FamilyName = family
		}
	}
	user, err := u.linkOrCreate(ctx, saved, profile)
	if err != nil {
		return AuthResult{}, err
	}
	return issueSession(ctx, u.Sessions, u.Tokens, u.TTL, u.now, user)
}

func (u OAuthCallback) linkOrCreate(ctx context.Context, saved domain.OAuthState, profile oauth.Profile) (domain.User, error) {
	existing, err := u.Identities.FindBySubject(ctx, saved.ProjectID, saved.Env, saved.Slug, profile.Subject)
	if err == nil {
		return u.Users.FindByID(ctx, existing.UserID)
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return domain.User{}, err
	}
	email := strings.ToLower(strings.TrimSpace(profile.Email))
	needsEmail := profile.NeedsEmail || email == ""
	if email != "" && profile.EmailVerified {
		user, err := u.Users.FindByEmail(ctx, saved.ProjectID, saved.Env, email)
		if err == nil {
			if err := u.addIdentity(ctx, user.ID, saved, profile.Subject); err != nil && !errors.Is(err, domain.ErrConflict) {
				return domain.User{}, err
			}
			return user, nil
		}
		if !errors.Is(err, domain.ErrNotFound) {
			return domain.User{}, err
		}
	}
	if email == "" {
		email = saved.Slug + "+" + profile.Subject + "@" + domain.OAuthInvalidDomain
		needsEmail = true
	}
	userID, err := id.New()
	if err != nil {
		return domain.User{}, err
	}
	now := u.now()
	user := domain.User{
		ID:         userID,
		ProjectID:  saved.ProjectID,
		Env:        saved.Env,
		Email:      email,
		NeedsEmail: needsEmail,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := u.Users.Create(ctx, user); err != nil {
		return domain.User{}, err
	}
	if err := u.addIdentity(ctx, user.ID, saved, profile.Subject); err != nil {
		return domain.User{}, err
	}
	return user, nil
}

func (u OAuthCallback) addIdentity(ctx context.Context, userID uuid.UUID, saved domain.OAuthState, subject string) error {
	identID, err := id.New()
	if err != nil {
		return err
	}
	return u.Identities.Create(ctx, domain.Identity{
		ID:        identID,
		UserID:    userID,
		ProjectID: saved.ProjectID,
		Env:       saved.Env,
		Provider:  saved.Slug,
		Subject:   subject,
		CreatedAt: u.now(),
	})
}

func (u OAuthCallback) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

func requireOAuthModule(scope domain.Scope, slug string) error {
	if scope.Disabled {
		return domain.ErrProjectDisabled
	}
	if scope.ProjectID == uuid.Nil || !domain.ValidEnv(scope.Env) {
		return domain.ErrUnauthorized
	}
	if !oauth.ValidSlug(slug) {
		return domain.ErrInvalidInput
	}
	if !scope.HasModule(oauth.ModuleName(slug)) {
		return domain.ErrModuleDisabled
	}
	return nil
}
