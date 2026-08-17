package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/jackc/pgx/v5/pgconn"
)

// Store persists internal password credentials through the process-owned
// PostgreSQL pool. It does not own another connection pool.
type Store struct {
	pool *database.Pool
}

func New(pool *database.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) CreatePasswordCredential(
	ctx context.Context,
	applicationInstanceID applicationinstance.InternalID,
	userID identity.InternalID,
	passwordHash authentication.PasswordHash,
) (authentication.PasswordCredential, error) {
	if !applicationInstanceID.Valid() {
		return authentication.PasswordCredential{}, authentication.ErrInvalidApplicationInstanceScope
	}
	if !userID.Valid() {
		return authentication.PasswordCredential{}, authentication.ErrInvalidUserInternalID
	}
	if !passwordHash.Valid() {
		return authentication.PasswordCredential{}, authentication.ErrInvalidPasswordHash
	}
	if err := ctx.Err(); err != nil {
		return authentication.PasswordCredential{}, err
	}
	if s == nil || s.pool == nil {
		return authentication.PasswordCredential{}, authentication.ErrPasswordCredentialPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()

	var credential authentication.PasswordCredential
	var storedApplicationInstanceID int64
	var storedUserID int64
	var encoded string
	if err := db.QueryRowContext(
		ctx,
		`INSERT INTO password_credentials (application_instance_id, user_id, password_hash)
		 VALUES ($1, $2, $3)
		 RETURNING application_instance_id, user_id, password_hash, created_at`,
		int64(applicationInstanceID),
		int64(userID),
		passwordHash.StorageEncoding(),
	).Scan(
		&storedApplicationInstanceID,
		&storedUserID,
		&encoded,
		&credential.CreatedAt,
	); err != nil {
		return authentication.PasswordCredential{}, classifyError(ctx, err)
	}

	parsed, err := authentication.ParsePasswordHash(encoded)
	if err != nil {
		return authentication.PasswordCredential{}, authentication.ErrPasswordCredentialPersistence
	}
	credential.ApplicationInstanceID = applicationinstance.InternalID(storedApplicationInstanceID)
	credential.UserID = identity.InternalID(storedUserID)
	credential.PasswordHash = parsed
	credential.CreatedAt = credential.CreatedAt.UTC()
	return credential, nil
}

func (s *Store) ResolvePasswordCredential(
	ctx context.Context,
	applicationInstanceID applicationinstance.InternalID,
	userID identity.InternalID,
) (authentication.PasswordCredential, error) {
	if !applicationInstanceID.Valid() {
		return authentication.PasswordCredential{}, authentication.ErrInvalidApplicationInstanceScope
	}
	if !userID.Valid() {
		return authentication.PasswordCredential{}, authentication.ErrInvalidUserInternalID
	}
	if err := ctx.Err(); err != nil {
		return authentication.PasswordCredential{}, err
	}
	if s == nil || s.pool == nil {
		return authentication.PasswordCredential{}, authentication.ErrPasswordCredentialPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()

	var credential authentication.PasswordCredential
	var storedApplicationInstanceID int64
	var storedUserID int64
	var encoded string
	err := db.QueryRowContext(
		ctx,
		`SELECT application_instance_id, user_id, password_hash, created_at
		 FROM password_credentials
		 WHERE application_instance_id = $1 AND user_id = $2`,
		int64(applicationInstanceID),
		int64(userID),
	).Scan(
		&storedApplicationInstanceID,
		&storedUserID,
		&encoded,
		&credential.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authentication.PasswordCredential{}, authentication.ErrPasswordCredentialNotFound
		}
		return authentication.PasswordCredential{}, classifyError(ctx, err)
	}

	parsed, err := authentication.ParsePasswordHash(encoded)
	if err != nil {
		return authentication.PasswordCredential{}, authentication.ErrPasswordCredentialPersistence
	}
	credential.ApplicationInstanceID = applicationinstance.InternalID(storedApplicationInstanceID)
	credential.UserID = identity.InternalID(storedUserID)
	credential.PasswordHash = parsed
	credential.CreatedAt = credential.CreatedAt.UTC()
	return credential, nil
}

func classifyError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "password_credentials_pkey" {
		return authentication.ErrPasswordCredentialConflict
	}
	return authentication.ErrPasswordCredentialPersistence
}
