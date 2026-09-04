package application

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-identity/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
	"github.com/google/uuid"
)

func issueSession(
	ctx context.Context,
	sessions domain.SessionRepository,
	tokens domain.TokenSource,
	ttl time.Duration,
	nowFn func() time.Time,
	user domain.User,
) (AuthResult, error) {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	raw, hash, err := tokens.New()
	if err != nil {
		return AuthResult{}, err
	}
	sessionID, err := id.New()
	if err != nil {
		return AuthResult{}, err
	}
	now := nowFn()
	session := domain.Session{
		ID:        sessionID,
		UserID:    user.ID,
		ProjectID: user.ProjectID,
		Env:       user.Env,
		TokenHash: hash,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if err := sessions.Create(ctx, session); err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: user, Token: raw, ExpiresAt: session.ExpiresAt}, nil
}

type Me struct {
	Users    domain.UserRepository
	Sessions domain.SessionRepository
	Tokens   domain.TokenSource
	Now      func() time.Time
}

func (u Me) Execute(ctx context.Context, scope domain.Scope, bearer string) (domain.User, error) {
	session, err := loadSession(ctx, u.Sessions, u.Tokens, u.now, bearer)
	if err != nil {
		return domain.User{}, err
	}
	if err := matchScope(scope, session.ProjectID, session.Env); err != nil {
		return domain.User{}, err
	}
	return u.Users.FindByID(ctx, session.UserID)
}

func (u Me) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

type SignOut struct {
	Sessions domain.SessionRepository
	Tokens   domain.TokenSource
	Now      func() time.Time
}

func (u SignOut) Execute(ctx context.Context, scope domain.Scope, bearer string) error {
	session, err := loadSession(ctx, u.Sessions, u.Tokens, u.now, bearer)
	if err != nil {
		return err
	}
	if err := matchScope(scope, session.ProjectID, session.Env); err != nil {
		return err
	}
	return u.Sessions.DeleteByTokenHash(ctx, session.TokenHash)
}

func (u SignOut) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

func loadSession(ctx context.Context, sessions domain.SessionRepository, tokens domain.TokenSource, nowFn func() time.Time, bearer string) (domain.Session, error) {
	raw := strings.TrimSpace(bearer)
	if !strings.HasPrefix(raw, domain.SessionTokenPrefix) || len(raw) <= len(domain.SessionTokenPrefix) {
		return domain.Session{}, domain.ErrUnauthorized
	}
	session, err := sessions.FindByTokenHash(ctx, tokens.Hash(raw))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.Session{}, domain.ErrUnauthorized
		}
		return domain.Session{}, err
	}
	now := nowFn()
	if !session.ExpiresAt.After(now) {
		_ = sessions.DeleteByTokenHash(ctx, session.TokenHash)
		return domain.Session{}, domain.ErrUnauthorized
	}
	return session, nil
}

func matchScope(scope domain.Scope, projectID uuid.UUID, env string) error {
	if scope.ProjectID != uuid.Nil && scope.ProjectID != projectID {
		return domain.ErrUnauthorized
	}
	if scope.Env != "" && scope.Env != env {
		return domain.ErrUnauthorized
	}
	return nil
}
