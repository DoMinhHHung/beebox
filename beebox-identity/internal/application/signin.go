package application

import (
	"context"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
)

type SignIn struct {
	Users    domain.UserRepository
	Sessions domain.SessionRepository
	Hasher   domain.PasswordHasher
	Tokens   domain.TokenSource
	Now      func() time.Time
	TTL      time.Duration
}

func (u SignIn) Execute(ctx context.Context, scope domain.Scope, email, password string) (AuthResult, error) {
	if err := requireAuthModule(scope); err != nil {
		return AuthResult{}, err
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return AuthResult{}, err
	}
	if password == "" {
		return AuthResult{}, domain.ErrUnauthorized
	}
	user, err := u.Users.FindByEmail(ctx, scope.ProjectID, scope.Env, email)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			u.Hasher.Verify(password, dummyHash)
			return AuthResult{}, domain.ErrUnauthorized
		}
		return AuthResult{}, err
	}
	if !u.Hasher.Verify(password, user.PasswordHash) {
		return AuthResult{}, domain.ErrUnauthorized
	}
	return issueSession(ctx, u.Sessions, u.Tokens, u.TTL, u.now, user)
}

func (u SignIn) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

const dummyHash = "$argon2id$v=19$m=65536,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
