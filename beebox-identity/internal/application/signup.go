package application

import (
	"context"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
)

type SignUp struct {
	Users    domain.UserRepository
	Sessions domain.SessionRepository
	Hasher   domain.PasswordHasher
	Tokens   domain.TokenSource
	Now      func() time.Time
	TTL      time.Duration
}

type AuthResult struct {
	User      domain.User
	Token     string
	ExpiresAt time.Time
}

func (u SignUp) Execute(ctx context.Context, scope domain.Scope, email, password string) (AuthResult, error) {
	if err := requireAuthModule(scope); err != nil {
		return AuthResult{}, err
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return AuthResult{}, err
	}
	if err := validatePassword(password); err != nil {
		return AuthResult{}, err
	}
	hash, err := u.Hasher.Hash(password)
	if err != nil {
		return AuthResult{}, err
	}
	userID, err := id.New()
	if err != nil {
		return AuthResult{}, err
	}
	now := u.now()
	user := domain.User{
		ID:           userID,
		ProjectID:    scope.ProjectID,
		Env:          scope.Env,
		Email:        email,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := u.Users.Create(ctx, user); err != nil {
		return AuthResult{}, err
	}
	return issueSession(ctx, u.Sessions, u.Tokens, u.TTL, u.now, user)
}

func (u SignUp) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}
