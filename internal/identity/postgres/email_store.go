package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Store) CreateEmailIdentifier(
	ctx context.Context,
	applicationInstanceID applicationinstance.InternalID,
	userID identity.InternalID,
	rawEmail string,
) (identity.EmailIdentifier, error) {
	if !applicationInstanceID.Valid() {
		return identity.EmailIdentifier{}, identity.ErrInvalidApplicationInstanceScope
	}
	if !userID.Valid() {
		return identity.EmailIdentifier{}, identity.ErrInvalidInternalID
	}
	normalized, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return identity.EmailIdentifier{}, identity.ErrInvalidEmail
	}
	if err := ctx.Err(); err != nil {
		return identity.EmailIdentifier{}, err
	}
	if s == nil || s.pool == nil {
		return identity.EmailIdentifier{}, identity.ErrEmailPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()

	var identifier identity.EmailIdentifier
	var internalID int64
	var storedApplicationInstanceID int64
	var storedUserID int64
	var verifiedAt sql.NullTime
	if err := db.QueryRowContext(
		ctx,
		`INSERT INTO email_identifiers (
			application_instance_id,
			user_id,
			email_address,
			normalized_email
		 ) VALUES ($1, $2, $3, $4)
		 RETURNING id, application_instance_id, user_id, email_address, normalized_email, verified_at, created_at`,
		int64(applicationInstanceID),
		int64(userID),
		normalized.EmailAddress,
		normalized.ComparisonKey,
	).Scan(
		&internalID,
		&storedApplicationInstanceID,
		&storedUserID,
		&identifier.EmailAddress,
		&identifier.NormalizedEmail,
		&verifiedAt,
		&identifier.CreatedAt,
	); err != nil {
		return identity.EmailIdentifier{}, classifyEmailError(ctx, err)
	}

	identifier.InternalID = identity.EmailIdentifierInternalID(internalID)
	identifier.ApplicationInstanceID = applicationinstance.InternalID(storedApplicationInstanceID)
	identifier.UserID = identity.InternalID(storedUserID)
	identifier.VerifiedAt = nullableTimeUTC(verifiedAt)
	identifier.CreatedAt = identifier.CreatedAt.UTC()
	return identifier, nil
}

func (s *Store) ResolveEmailIdentifierByAddress(
	ctx context.Context,
	applicationInstanceID applicationinstance.InternalID,
	rawEmail string,
) (identity.EmailIdentifier, error) {
	if !applicationInstanceID.Valid() {
		return identity.EmailIdentifier{}, identity.ErrInvalidApplicationInstanceScope
	}
	normalized, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return identity.EmailIdentifier{}, identity.ErrInvalidEmail
	}
	if err := ctx.Err(); err != nil {
		return identity.EmailIdentifier{}, err
	}
	if s == nil || s.pool == nil {
		return identity.EmailIdentifier{}, identity.ErrEmailPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()

	var identifier identity.EmailIdentifier
	var internalID int64
	var storedApplicationInstanceID int64
	var storedUserID int64
	var verifiedAt sql.NullTime
	err = db.QueryRowContext(
		ctx,
		`SELECT id, application_instance_id, user_id, email_address, normalized_email, verified_at, created_at
		 FROM email_identifiers
		 WHERE application_instance_id = $1 AND normalized_email = $2`,
		int64(applicationInstanceID),
		normalized.ComparisonKey,
	).Scan(
		&internalID,
		&storedApplicationInstanceID,
		&storedUserID,
		&identifier.EmailAddress,
		&identifier.NormalizedEmail,
		&verifiedAt,
		&identifier.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return identity.EmailIdentifier{}, identity.ErrEmailIdentifierNotFound
		}
		return identity.EmailIdentifier{}, classifyEmailError(ctx, err)
	}

	identifier.InternalID = identity.EmailIdentifierInternalID(internalID)
	identifier.ApplicationInstanceID = applicationinstance.InternalID(storedApplicationInstanceID)
	identifier.UserID = identity.InternalID(storedUserID)
	identifier.VerifiedAt = nullableTimeUTC(verifiedAt)
	identifier.CreatedAt = identifier.CreatedAt.UTC()
	return identifier, nil
}

func classifyEmailError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) &&
		pgErr.Code == "23505" &&
		pgErr.ConstraintName == "email_identifiers_application_normalized_email_key" {
		return identity.ErrEmailConflict
	}
	return identity.ErrEmailPersistence
}

func nullableTimeUTC(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	utc := value.Time.UTC()
	return &utc
}
