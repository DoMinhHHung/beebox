package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// PersistRegistration atomically creates user, unverified email identifier,
// password credential, and the required successful security audit fact.
func (s *Store) PersistRegistration(
	ctx context.Context,
	write authentication.RegistrationWrite,
) (authentication.RegistrationResult, error) {
	if !write.ApplicationInstanceID.Valid() {
		return authentication.RegistrationResult{}, authentication.ErrInvalidApplicationInstanceScope
	}
	if write.Email.EmailAddress == "" || write.Email.ComparisonKey == "" {
		return authentication.RegistrationResult{}, identity.ErrInvalidEmail
	}
	if !write.PasswordHash.Valid() {
		return authentication.RegistrationResult{}, authentication.ErrInvalidPasswordHash
	}
	if err := ctx.Err(); err != nil {
		return authentication.RegistrationResult{}, err
	}
	if s == nil || s.pool == nil {
		return authentication.RegistrationResult{}, authentication.ErrRegistrationPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.RegistrationResult{}, classifyRegistrationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := persistRegistrationRows(ctx, tx, write)
	if err != nil {
		return authentication.RegistrationResult{}, classifyRegistrationError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.RegistrationResult{}, classifyRegistrationError(ctx, err)
	}
	return result, nil
}

func persistRegistrationRows(
	ctx context.Context,
	tx *sql.Tx,
	write authentication.RegistrationWrite,
) (authentication.RegistrationResult, error) {
	var result authentication.RegistrationResult
	var userID int64
	var appID int64
	if err := tx.QueryRowContext(
		ctx,
		`INSERT INTO users (application_instance_id)
		 VALUES ($1)
		 RETURNING id, application_instance_id, created_at`,
		int64(write.ApplicationInstanceID),
	).Scan(&userID, &appID, &result.User.CreatedAt); err != nil {
		return authentication.RegistrationResult{}, err
	}
	result.User.InternalID = identity.InternalID(userID)
	result.User.ApplicationInstanceID = applicationinstance.InternalID(appID)
	result.User.CreatedAt = result.User.CreatedAt.UTC()

	var emailID int64
	var emailAppID int64
	var emailUserID int64
	var verifiedAt sql.NullTime
	if err := tx.QueryRowContext(
		ctx,
		`INSERT INTO email_identifiers (
			application_instance_id, user_id, email_address, normalized_email
		 ) VALUES ($1, $2, $3, $4)
		 RETURNING id, application_instance_id, user_id, email_address, normalized_email, verified_at, created_at`,
		int64(write.ApplicationInstanceID),
		userID,
		write.Email.EmailAddress,
		write.Email.ComparisonKey,
	).Scan(
		&emailID,
		&emailAppID,
		&emailUserID,
		&result.EmailIdentifier.EmailAddress,
		&result.EmailIdentifier.NormalizedEmail,
		&verifiedAt,
		&result.EmailIdentifier.CreatedAt,
	); err != nil {
		return authentication.RegistrationResult{}, err
	}
	result.EmailIdentifier.InternalID = identity.EmailIdentifierInternalID(emailID)
	result.EmailIdentifier.ApplicationInstanceID = applicationinstance.InternalID(emailAppID)
	result.EmailIdentifier.UserID = identity.InternalID(emailUserID)
	if verifiedAt.Valid {
		verifiedUTC := verifiedAt.Time.UTC()
		result.EmailIdentifier.VerifiedAt = &verifiedUTC
	}
	result.EmailIdentifier.CreatedAt = result.EmailIdentifier.CreatedAt.UTC()

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO password_credentials (application_instance_id, user_id, password_hash)
		 VALUES ($1, $2, $3)`,
		int64(write.ApplicationInstanceID),
		userID,
		write.PasswordHash.StorageEncoding(),
	); err != nil {
		return authentication.RegistrationResult{}, err
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO audit_events (
			application_instance_id, actor_kind, subject_user_id, action,
			resource_category, outcome, correlation_id, source
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		int64(write.ApplicationInstanceID),
		audit.ActorKindAnonymousRegistration,
		userID,
		audit.ActionEmailPasswordRegistration,
		audit.ResourceCategoryUserRegistration,
		audit.OutcomeSuccess,
		write.CorrelationID[:],
		audit.SourceInternalRegistration,
	); err != nil {
		return authentication.RegistrationResult{}, err
	}

	return result, nil
}

func classifyRegistrationError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "email_identifiers_application_normalized_email_key" {
		return authentication.ErrRegistrationConflict
	}
	return authentication.ErrRegistrationPersistence
}
