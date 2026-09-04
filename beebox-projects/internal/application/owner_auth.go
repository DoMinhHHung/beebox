package application

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/DoMinhHHung/beebox/libs/shared/id"
)

const dummyOwnerHash = "$argon2id$v=19$m=65536,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type OwnerAuthResult struct {
	Account   domain.Account
	Token     string
	ExpiresAt time.Time
}

type OwnerSignUp struct {
	Accounts domain.AccountRepository
	Sessions domain.OwnerSessionRepository
	Hasher   domain.PasswordHasher
	Tokens   domain.TokenSource
	Now      func() time.Time
	TTL      time.Duration
}

func (u OwnerSignUp) Execute(ctx context.Context, email, password string) (OwnerAuthResult, error) {
	email, err := normalizeOwnerEmail(email)
	if err != nil {
		return OwnerAuthResult{}, err
	}
	if err := validateOwnerPassword(password); err != nil {
		return OwnerAuthResult{}, err
	}
	hash, err := u.Hasher.Hash(password)
	if err != nil {
		return OwnerAuthResult{}, err
	}
	accountID, err := id.New()
	if err != nil {
		return OwnerAuthResult{}, err
	}
	account := domain.Account{ID: accountID, Email: email, PasswordHash: hash}
	if err := u.Accounts.Create(ctx, account); err != nil {
		return OwnerAuthResult{}, err
	}
	return issueOwnerSession(ctx, u.Sessions, u.Tokens, u.TTL, u.now, account)
}

func (u OwnerSignUp) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

type OwnerSignIn struct {
	Accounts domain.AccountRepository
	Sessions domain.OwnerSessionRepository
	Hasher   domain.PasswordHasher
	Tokens   domain.TokenSource
	Now      func() time.Time
	TTL      time.Duration
}

func (u OwnerSignIn) Execute(ctx context.Context, email, password string) (OwnerAuthResult, error) {
	email, err := normalizeOwnerEmail(email)
	if err != nil {
		return OwnerAuthResult{}, err
	}
	if password == "" {
		return OwnerAuthResult{}, domain.ErrUnauthorized
	}
	account, err := u.Accounts.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			u.Hasher.Verify(password, dummyOwnerHash)
			return OwnerAuthResult{}, domain.ErrUnauthorized
		}
		return OwnerAuthResult{}, err
	}
	if account.PasswordHash == "" || !u.Hasher.Verify(password, account.PasswordHash) {
		return OwnerAuthResult{}, domain.ErrUnauthorized
	}
	return issueOwnerSession(ctx, u.Sessions, u.Tokens, u.TTL, u.now, account)
}

func (u OwnerSignIn) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

type OwnerMe struct {
	Accounts domain.AccountRepository
	Sessions domain.OwnerSessionRepository
	Tokens   domain.TokenSource
	Now      func() time.Time
}

func (u OwnerMe) Execute(ctx context.Context, bearer string) (domain.Account, error) {
	session, err := loadOwnerSession(ctx, u.Sessions, u.Tokens, u.now, bearer)
	if err != nil {
		return domain.Account{}, err
	}
	return u.Accounts.FindByID(ctx, session.AccountID)
}

func (u OwnerMe) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

type OwnerSignOut struct {
	Sessions domain.OwnerSessionRepository
	Tokens   domain.TokenSource
	Now      func() time.Time
}

func (u OwnerSignOut) Execute(ctx context.Context, bearer string) error {
	session, err := loadOwnerSession(ctx, u.Sessions, u.Tokens, u.now, bearer)
	if err != nil {
		return err
	}
	return u.Sessions.DeleteByTokenHash(ctx, session.TokenHash)
}

func (u OwnerSignOut) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

func issueOwnerSession(
	ctx context.Context,
	sessions domain.OwnerSessionRepository,
	tokens domain.TokenSource,
	ttl time.Duration,
	nowFn func() time.Time,
	account domain.Account,
) (OwnerAuthResult, error) {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	raw, hash, err := tokens.New()
	if err != nil {
		return OwnerAuthResult{}, err
	}
	sessionID, err := id.New()
	if err != nil {
		return OwnerAuthResult{}, err
	}
	now := nowFn()
	session := domain.OwnerSession{
		ID:        sessionID,
		AccountID: account.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if err := sessions.Create(ctx, session); err != nil {
		return OwnerAuthResult{}, err
	}
	return OwnerAuthResult{Account: account, Token: raw, ExpiresAt: session.ExpiresAt}, nil
}

func loadOwnerSession(ctx context.Context, sessions domain.OwnerSessionRepository, tokens domain.TokenSource, nowFn func() time.Time, bearer string) (domain.OwnerSession, error) {
	raw := strings.TrimSpace(bearer)
	if !strings.HasPrefix(raw, domain.OwnerTokenPrefix) || len(raw) <= len(domain.OwnerTokenPrefix) {
		return domain.OwnerSession{}, domain.ErrUnauthorized
	}
	session, err := sessions.FindByTokenHash(ctx, tokens.Hash(raw))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.OwnerSession{}, domain.ErrUnauthorized
		}
		return domain.OwnerSession{}, err
	}
	now := nowFn()
	if !session.ExpiresAt.After(now) {
		_ = sessions.DeleteByTokenHash(ctx, session.TokenHash)
		return domain.OwnerSession{}, domain.ErrUnauthorized
	}
	return session, nil
}

func normalizeOwnerEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !validEmail(email) {
		return "", domain.ErrInvalidInput
	}
	return email, nil
}

func validateOwnerPassword(password string) error {
	if len(password) < domain.MinPasswordLength {
		return domain.ErrInvalidInput
	}
	return nil
}
