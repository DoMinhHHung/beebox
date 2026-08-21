package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Store) ListManagedEmails(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, limit int, cursor *authentication.AccountIdentifierCursor) ([]authentication.ManagedEmailIdentifier, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() || limit < 1 || limit > authentication.AccountIdentifierListMaxLimit+1 {
		return nil, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	query := `SELECT public_id,id,email_address,verified_at IS NOT NULL,is_primary,created_at
		FROM email_identifiers WHERE application_instance_id=$1 AND user_id=$2`
	args := []any{int64(appID), int64(userID)}
	if cursor != nil {
		query += ` AND (created_at,public_id)<($3,$4)`
		args = append(args, cursor.CreatedAt.UTC(), cursor.PublicID)
		query += ` ORDER BY created_at DESC,public_id DESC LIMIT $5`
		args = append(args, limit)
	} else {
		query += ` ORDER BY created_at DESC,public_id DESC LIMIT $3`
		args = append(args, limit)
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, classifyAccountError(ctx, err)
	}
	defer rows.Close()
	items := make([]authentication.ManagedEmailIdentifier, 0, limit)
	for rows.Next() {
		var item authentication.ManagedEmailIdentifier
		var internalID int64
		if err := rows.Scan(&item.PublicID, &internalID, &item.Email, &item.Verified, &item.Primary, &item.CreatedAt); err != nil {
			return nil, classifyAccountError(ctx, err)
		}
		item.InternalID = identity.EmailIdentifierInternalID(internalID)
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, classifyAccountError(ctx, err)
	}
	return items, nil
}

func (s *Store) ListManagedPhones(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, limit int, cursor *authentication.AccountIdentifierCursor) ([]authentication.ManagedPhoneIdentifier, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() || limit < 1 || limit > authentication.AccountIdentifierListMaxLimit+1 {
		return nil, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	query := `SELECT public_id,id,phone_e164,verified_at IS NOT NULL,is_primary,created_at
		FROM phone_identifiers WHERE application_instance_id=$1 AND user_id=$2`
	args := []any{int64(appID), int64(userID)}
	if cursor != nil {
		query += ` AND (created_at,public_id)<($3,$4)`
		args = append(args, cursor.CreatedAt.UTC(), cursor.PublicID)
		query += ` ORDER BY created_at DESC,public_id DESC LIMIT $5`
		args = append(args, limit)
	} else {
		query += ` ORDER BY created_at DESC,public_id DESC LIMIT $3`
		args = append(args, limit)
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, classifyAccountError(ctx, err)
	}
	defer rows.Close()
	items := make([]authentication.ManagedPhoneIdentifier, 0, limit)
	for rows.Next() {
		var item authentication.ManagedPhoneIdentifier
		var internalID int64
		if err := rows.Scan(&item.PublicID, &internalID, &item.Phone, &item.Verified, &item.Primary, &item.CreatedAt); err != nil {
			return nil, classifyAccountError(ctx, err)
		}
		item.InternalID = identity.PhoneIdentifierInternalID(internalID)
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, classifyAccountError(ctx, err)
	}
	return items, nil
}

func (s *Store) AddManagedEmail(ctx context.Context, current authentication.AccountManagementSession, email identity.NormalizedEmail, correlationID audit.CorrelationID) (authentication.ManagedEmailIdentifier, error) {
	if s == nil || s.pool == nil || email.EmailAddress == "" || email.ComparisonKey == "" || correlationID == (audit.CorrelationID{}) {
		return authentication.ManagedEmailIdentifier{}, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.ManagedEmailIdentifier{}, classifyAccountError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockAccountUser(ctx, tx, current); err != nil {
		return authentication.ManagedEmailIdentifier{}, err
	}
	var item authentication.ManagedEmailIdentifier
	var internalID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email)
		VALUES($1,$2,$3,$4)
		RETURNING public_id,id,email_address,verified_at IS NOT NULL,is_primary,created_at`,
		int64(current.ApplicationInstanceID), int64(current.UserID), email.EmailAddress, email.ComparisonKey,
	).Scan(&item.PublicID, &internalID, &item.Email, &item.Verified, &item.Primary, &item.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return authentication.ManagedEmailIdentifier{}, authentication.ErrAccountIdentifierUnavailable
		}
		return authentication.ManagedEmailIdentifier{}, classifyAccountError(ctx, err)
	}
	item.InternalID = identity.EmailIdentifierInternalID(internalID)
	item.CreatedAt = item.CreatedAt.UTC()
	if err := insertAccountAudit(ctx, tx, current, audit.ActionEmailIdentifierAdded, item.PublicID, correlationID); err != nil {
		return authentication.ManagedEmailIdentifier{}, classifyAccountError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.ManagedEmailIdentifier{}, classifyAccountError(ctx, err)
	}
	return item, nil
}

func (s *Store) AddManagedPhone(ctx context.Context, current authentication.AccountManagementSession, phone identity.CanonicalPhone, correlationID audit.CorrelationID) (authentication.ManagedPhoneIdentifier, error) {
	if s == nil || s.pool == nil || phone.E164 == "" || correlationID == (audit.CorrelationID{}) {
		return authentication.ManagedPhoneIdentifier{}, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.ManagedPhoneIdentifier{}, classifyAccountError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockAccountUser(ctx, tx, current); err != nil {
		return authentication.ManagedPhoneIdentifier{}, err
	}
	var item authentication.ManagedPhoneIdentifier
	var internalID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164)
		VALUES($1,$2,$3)
		RETURNING public_id,id,phone_e164,verified_at IS NOT NULL,is_primary,created_at`,
		int64(current.ApplicationInstanceID), int64(current.UserID), phone.E164,
	).Scan(&item.PublicID, &internalID, &item.Phone, &item.Verified, &item.Primary, &item.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return authentication.ManagedPhoneIdentifier{}, authentication.ErrAccountIdentifierUnavailable
		}
		return authentication.ManagedPhoneIdentifier{}, classifyAccountError(ctx, err)
	}
	item.InternalID = identity.PhoneIdentifierInternalID(internalID)
	item.CreatedAt = item.CreatedAt.UTC()
	if err := insertAccountAudit(ctx, tx, current, audit.ActionPhoneIdentifierAdded, item.PublicID, correlationID); err != nil {
		return authentication.ManagedPhoneIdentifier{}, classifyAccountError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.ManagedPhoneIdentifier{}, classifyAccountError(ctx, err)
	}
	return item, nil
}

func (s *Store) ResolveManagedEmail(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, publicID string) (authentication.ManagedEmailIdentifier, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() {
		return authentication.ManagedEmailIdentifier{}, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var item authentication.ManagedEmailIdentifier
	var internalID int64
	err := db.QueryRowContext(ctx, `
		SELECT public_id,id,email_address,verified_at IS NOT NULL,is_primary,created_at
		FROM email_identifiers
		WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3`,
		int64(appID), int64(userID), publicID,
	).Scan(&item.PublicID, &internalID, &item.Email, &item.Verified, &item.Primary, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.ManagedEmailIdentifier{}, authentication.ErrAccountIdentifierNotFound
	}
	if err != nil {
		return authentication.ManagedEmailIdentifier{}, classifyAccountError(ctx, err)
	}
	item.InternalID = identity.EmailIdentifierInternalID(internalID)
	item.CreatedAt = item.CreatedAt.UTC()
	return item, nil
}

func (s *Store) ResolveManagedPhone(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, publicID string) (authentication.ManagedPhoneIdentifier, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() {
		return authentication.ManagedPhoneIdentifier{}, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var item authentication.ManagedPhoneIdentifier
	var internalID int64
	err := db.QueryRowContext(ctx, `
		SELECT public_id,id,phone_e164,verified_at IS NOT NULL,is_primary,created_at
		FROM phone_identifiers
		WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3`,
		int64(appID), int64(userID), publicID,
	).Scan(&item.PublicID, &internalID, &item.Phone, &item.Verified, &item.Primary, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.ManagedPhoneIdentifier{}, authentication.ErrAccountIdentifierNotFound
	}
	if err != nil {
		return authentication.ManagedPhoneIdentifier{}, classifyAccountError(ctx, err)
	}
	item.InternalID = identity.PhoneIdentifierInternalID(internalID)
	item.CreatedAt = item.CreatedAt.UTC()
	return item, nil
}

func (s *Store) SetPrimaryManagedEmail(ctx context.Context, current authentication.AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	return s.setPrimary(ctx, current, "email_identifiers", publicID, audit.ActionEmailIdentifierPrimary, correlationID)
}

func (s *Store) SetPrimaryManagedPhone(ctx context.Context, current authentication.AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	return s.setPrimary(ctx, current, "phone_identifiers", publicID, audit.ActionPhoneIdentifierPrimary, correlationID)
}

func (s *Store) setPrimary(ctx context.Context, current authentication.AccountManagementSession, table, publicID, action string, correlationID audit.CorrelationID) error {
	if s == nil || s.pool == nil || correlationID == (audit.CorrelationID{}) {
		return authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyAccountError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockAccountUser(ctx, tx, current); err != nil {
		return err
	}
	query := `SELECT verified_at IS NOT NULL FROM ` + table + ` WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3 FOR UPDATE`
	var verified bool
	err = tx.QueryRowContext(ctx, query, int64(current.ApplicationInstanceID), int64(current.UserID), publicID).Scan(&verified)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.ErrAccountIdentifierNotFound
	}
	if err != nil {
		return classifyAccountError(ctx, err)
	}
	if !verified {
		return authentication.ErrAccountIdentifierUnverified
	}
	if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET is_primary=false WHERE application_instance_id=$1 AND user_id=$2 AND is_primary`, int64(current.ApplicationInstanceID), int64(current.UserID)); err != nil {
		return classifyAccountError(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET is_primary=true WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3`, int64(current.ApplicationInstanceID), int64(current.UserID), publicID); err != nil {
		return classifyAccountError(ctx, err)
	}
	if err := insertAccountAudit(ctx, tx, current, action, publicID, correlationID); err != nil {
		return classifyAccountError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return classifyAccountError(ctx, err)
	}
	return nil
}

func (s *Store) RemoveManagedEmail(ctx context.Context, current authentication.AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	return s.removeIdentifier(ctx, current, "email_identifiers", publicID, audit.ActionEmailIdentifierRemoved, correlationID, true)
}

func (s *Store) RemoveManagedPhone(ctx context.Context, current authentication.AccountManagementSession, publicID string, correlationID audit.CorrelationID) error {
	return s.removeIdentifier(ctx, current, "phone_identifiers", publicID, audit.ActionPhoneIdentifierRemoved, correlationID, false)
}

func (s *Store) removeIdentifier(ctx context.Context, current authentication.AccountManagementSession, table, publicID, action string, correlationID audit.CorrelationID, email bool) error {
	if s == nil || s.pool == nil || correlationID == (audit.CorrelationID{}) {
		return authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyAccountError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockAccountUser(ctx, tx, current); err != nil {
		return err
	}
	var internalID int64
	var verified, primary bool
	err = tx.QueryRowContext(ctx, `SELECT id,verified_at IS NOT NULL,is_primary FROM `+table+` WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID), publicID).Scan(&internalID, &verified, &primary)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return classifyAccountError(ctx, err)
		}
		return nil
	}
	if err != nil {
		return classifyAccountError(ctx, err)
	}
	if verified {
		ok, err := s.hasUsableAuthAfterIdentifierRemoval(ctx, tx, current, email, internalID)
		if err != nil {
			return err
		}
		if !ok {
			return authentication.ErrLastAuthenticationMethod
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE application_instance_id=$1 AND user_id=$2 AND id=$3`, int64(current.ApplicationInstanceID), int64(current.UserID), internalID); err != nil {
		return classifyAccountError(ctx, err)
	}
	if primary {
		if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET is_primary=true WHERE id=(SELECT id FROM `+table+` WHERE application_instance_id=$1 AND user_id=$2 AND verified_at IS NOT NULL ORDER BY created_at,id LIMIT 1)`, int64(current.ApplicationInstanceID), int64(current.UserID)); err != nil {
			return classifyAccountError(ctx, err)
		}
	}
	if err := insertAccountAudit(ctx, tx, current, action, publicID, correlationID); err != nil {
		return classifyAccountError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return classifyAccountError(ctx, err)
	}
	return nil
}

func (s *Store) hasUsableAuthAfterIdentifierRemoval(ctx context.Context, tx *sql.Tx, current authentication.AccountManagementSession, removingEmail bool, internalID int64) (bool, error) {
	var appPublic string
	if err := tx.QueryRowContext(ctx, `SELECT public_id FROM application_instances WHERE id=$1`, int64(current.ApplicationInstanceID)).Scan(&appPublic); err != nil {
		return false, classifyAccountError(ctx, err)
	}
	var password bool
	if removingEmail {
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM password_credentials pc WHERE pc.application_instance_id=$1 AND pc.user_id=$2) AND EXISTS(SELECT 1 FROM email_identifiers e WHERE e.application_instance_id=$1 AND e.user_id=$2 AND e.id<>$3 AND e.verified_at IS NOT NULL)`, int64(current.ApplicationInstanceID), int64(current.UserID), internalID).Scan(&password); err != nil {
			return false, classifyAccountError(ctx, err)
		}
	} else {
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM password_credentials pc JOIN email_identifiers e ON e.application_instance_id=pc.application_instance_id AND e.user_id=pc.user_id AND e.verified_at IS NOT NULL WHERE pc.application_instance_id=$1 AND pc.user_id=$2)`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&password); err != nil {
			return false, classifyAccountError(ctx, err)
		}
	}
	if password {
		return true, nil
	}
	if s.availability.EmailOTP {
		query := `SELECT EXISTS(SELECT 1 FROM email_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND verified_at IS NOT NULL`
		args := []any{int64(current.ApplicationInstanceID), int64(current.UserID)}
		if removingEmail {
			query += ` AND id<>$3`
			args = append(args, internalID)
		}
		query += `)`
		var ok bool
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&ok); err != nil {
			return false, classifyAccountError(ctx, err)
		}
		if ok {
			return true, nil
		}
	}
	if s.availability.PhoneOTP {
		query := `SELECT EXISTS(SELECT 1 FROM phone_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND verified_at IS NOT NULL`
		args := []any{int64(current.ApplicationInstanceID), int64(current.UserID)}
		if !removingEmail {
			query += ` AND id<>$3`
			args = append(args, internalID)
		}
		query += `)`
		var ok bool
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&ok); err != nil {
			return false, classifyAccountError(ctx, err)
		}
		if ok {
			return true, nil
		}
	}
	var passkey bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2)`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&passkey); err != nil {
		return false, classifyAccountError(ctx, err)
	}
	if passkey {
		return true, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT provider FROM external_identities WHERE application_instance_id=$1 AND user_id=$2`, int64(current.ApplicationInstanceID), int64(current.UserID))
	if err != nil {
		return false, classifyAccountError(ctx, err)
	}
	defer rows.Close()
	for rows.Next() {
		var provider authentication.Provider
		if err := rows.Scan(&provider); err != nil {
			return false, classifyAccountError(ctx, err)
		}
		if s.availability.Social != nil {
			if _, ok := s.availability.Social.Resolve(applicationinstance.PublicID(appPublic), provider); ok {
				return true, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, classifyAccountError(ctx, err)
	}
	return false, nil
}

func (s *Store) IssuePhoneIdentifierVerification(ctx context.Context, current authentication.AccountManagementSession, phoneID identity.PhoneIdentifierInternalID, codeHash authentication.VerificationCodeHash, correlationID audit.CorrelationID) (string, time.Time, error) {
	if s == nil || s.pool == nil || !phoneID.Valid() || !codeHash.Valid() || correlationID == (audit.CorrelationID{}) {
		return "", time.Time{}, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, classifyAccountError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockAccountUser(ctx, tx, current); err != nil {
		return "", time.Time{}, err
	}
	var publicID, destination string
	var verified bool
	err = tx.QueryRowContext(ctx, `SELECT public_id,phone_e164,verified_at IS NOT NULL FROM phone_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID), int64(phoneID)).Scan(&publicID, &destination, &verified)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, authentication.ErrAccountIdentifierNotFound
	}
	if err != nil {
		return "", time.Time{}, classifyAccountError(ctx, err)
	}
	if verified {
		return "", time.Time{}, authentication.ErrAccountManagementInvalid
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return "", time.Time{}, classifyAccountError(ctx, err)
	}
	now = now.UTC()
	expiresAt := now.Add(authentication.PhoneOTPCodeTTL)
	var generation int64
	var issueCount int
	var windowStartedAt, lastIssuedAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT generation,issue_count,issue_window_started_at,last_issued_at FROM phone_identifier_verification_challenges WHERE application_instance_id=$1 AND phone_identifier_id=$2 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(phoneID)).Scan(&generation, &issueCount, &windowStartedAt, &lastIssuedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		generation = 1
		issueCount = 1
		windowStartedAt = now
	case err != nil:
		return "", time.Time{}, classifyAccountError(ctx, err)
	default:
		windowStartedAt = windowStartedAt.UTC()
		lastIssuedAt = lastIssuedAt.UTC()
		if now.Before(lastIssuedAt.Add(authentication.PhoneOTPResendCooldown)) {
			return "", time.Time{}, authentication.ErrEmailVerificationResendCooldown
		}
		if !now.Before(windowStartedAt.Add(authentication.PhoneOTPIssueWindow)) {
			issueCount = 1
			windowStartedAt = now
		} else {
			if issueCount >= authentication.PhoneOTPMaxIssues {
				return "", time.Time{}, authentication.ErrEmailVerificationIssueLimit
			}
			issueCount++
		}
		generation++
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO phone_identifier_verification_challenges(
			application_instance_id,phone_identifier_id,generation,code_hash,expires_at,
			failed_attempts,issue_count,issue_window_started_at,last_issued_at,consumed_at,updated_at
		) VALUES($1,$2,$3,$4,$5,0,$6,$7,$8,NULL,$8)
		ON CONFLICT(application_instance_id,phone_identifier_id) DO UPDATE SET
			generation=EXCLUDED.generation,code_hash=EXCLUDED.code_hash,expires_at=EXCLUDED.expires_at,
			failed_attempts=0,issue_count=EXCLUDED.issue_count,
			issue_window_started_at=EXCLUDED.issue_window_started_at,last_issued_at=EXCLUDED.last_issued_at,
			consumed_at=NULL,updated_at=EXCLUDED.updated_at`,
		int64(current.ApplicationInstanceID), int64(phoneID), generation, codeHash.StorageEncoding(), expiresAt, issueCount, windowStartedAt, now,
	)
	if err != nil {
		return "", time.Time{}, classifyAccountError(ctx, err)
	}
	if err := insertAccountAudit(ctx, tx, current, audit.ActionPhoneIdentifierVerificationIssued, publicID, correlationID); err != nil {
		return "", time.Time{}, classifyAccountError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, classifyAccountError(ctx, err)
	}
	return destination, expiresAt, nil
}

func (s *Store) LoadPhoneIdentifierVerification(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, phoneID identity.PhoneIdentifierInternalID) (authentication.PhoneIdentifierVerificationSnapshot, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() || !phoneID.Valid() {
		return authentication.PhoneIdentifierVerificationSnapshot{}, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var snapshot authentication.PhoneIdentifierVerificationSnapshot
	var encoded sql.NullString
	var consumed sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT c.generation,c.code_hash,c.expires_at,c.failed_attempts,c.consumed_at
		FROM phone_identifier_verification_challenges c
		JOIN phone_identifiers p ON p.application_instance_id=c.application_instance_id AND p.id=c.phone_identifier_id
		WHERE c.application_instance_id=$1 AND p.user_id=$2 AND c.phone_identifier_id=$3`,
		int64(appID), int64(userID), int64(phoneID),
	).Scan(&snapshot.Generation, &encoded, &snapshot.ExpiresAt, &snapshot.FailedAttempts, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return snapshot, authentication.ErrAccountIdentifierNotFound
	}
	if err != nil {
		return snapshot, classifyAccountError(ctx, err)
	}
	if consumed.Valid || !encoded.Valid || snapshot.FailedAttempts >= authentication.PhoneOTPMaxAttempts {
		return snapshot, authentication.ErrAccountManagementInvalid
	}
	parsed, err := authentication.ParseVerificationCodeHash(encoded.String)
	if err != nil {
		return snapshot, authentication.ErrAccountManagementPersistence
	}
	snapshot.CodeHash = parsed
	snapshot.ExpiresAt = snapshot.ExpiresAt.UTC()
	return snapshot, nil
}

func (s *Store) FinalizePhoneIdentifierVerification(ctx context.Context, current authentication.AccountManagementSession, phoneID identity.PhoneIdentifierInternalID, generation int64, matched bool, correlationID audit.CorrelationID) (authentication.ManagedPhoneIdentifier, error) {
	if s == nil || s.pool == nil || !phoneID.Valid() || generation <= 0 || correlationID == (audit.CorrelationID{}) {
		return authentication.ManagedPhoneIdentifier{}, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.ManagedPhoneIdentifier{}, classifyAccountError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockAccountUser(ctx, tx, current); err != nil {
		return authentication.ManagedPhoneIdentifier{}, err
	}
	var item authentication.ManagedPhoneIdentifier
	var internalID int64
	var verified bool
	err = tx.QueryRowContext(ctx, `SELECT public_id,id,phone_e164,verified_at IS NOT NULL,is_primary,created_at FROM phone_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID), int64(phoneID)).Scan(&item.PublicID, &internalID, &item.Phone, &verified, &item.Primary, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return item, authentication.ErrAccountIdentifierNotFound
	}
	if err != nil {
		return item, classifyAccountError(ctx, err)
	}
	if verified {
		item.InternalID = phoneID
		item.Verified = true
		item.CreatedAt = item.CreatedAt.UTC()
		return item, nil
	}
	var storedGeneration int64
	var expiresAt time.Time
	var failedAttempts int
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT generation,expires_at,failed_attempts,consumed_at FROM phone_identifier_verification_challenges WHERE application_instance_id=$1 AND phone_identifier_id=$2 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(phoneID)).Scan(&storedGeneration, &expiresAt, &failedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return item, authentication.ErrAccountManagementInvalid
	}
	if err != nil {
		return item, classifyAccountError(ctx, err)
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return item, classifyAccountError(ctx, err)
	}
	now = now.UTC()
	if storedGeneration != generation || consumedAt.Valid || !now.Before(expiresAt.UTC()) || failedAttempts >= authentication.PhoneOTPMaxAttempts {
		return item, authentication.ErrAccountManagementInvalid
	}
	if !matched {
		if _, err := tx.ExecContext(ctx, `UPDATE phone_identifier_verification_challenges SET failed_attempts=failed_attempts+1,updated_at=$3 WHERE application_instance_id=$1 AND phone_identifier_id=$2`, int64(current.ApplicationInstanceID), int64(phoneID), now); err != nil {
			return item, classifyAccountError(ctx, err)
		}
		if err := insertAccountAuditOutcome(ctx, tx, current, audit.ActionPhoneIdentifierVerificationDenied, item.PublicID, audit.OutcomeDenied, correlationID); err != nil {
			return item, classifyAccountError(ctx, err)
		}
		if err := tx.Commit(); err != nil {
			return item, classifyAccountError(ctx, err)
		}
		return item, authentication.ErrAccountManagementInvalid
	}
	if _, err := tx.ExecContext(ctx, `UPDATE phone_identifiers SET verified_at=$4,updated_at=$4 WHERE application_instance_id=$1 AND user_id=$2 AND id=$3`, int64(current.ApplicationInstanceID), int64(current.UserID), int64(phoneID), now); err != nil {
		if isUniqueViolation(err) {
			return item, authentication.ErrAccountIdentifierUnavailable
		}
		return item, classifyAccountError(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE phone_identifier_verification_challenges SET consumed_at=$3,code_hash=NULL,updated_at=$3 WHERE application_instance_id=$1 AND phone_identifier_id=$2`, int64(current.ApplicationInstanceID), int64(phoneID), now); err != nil {
		return item, classifyAccountError(ctx, err)
	}
	if err := insertAccountAudit(ctx, tx, current, audit.ActionPhoneIdentifierVerified, item.PublicID, correlationID); err != nil {
		return item, classifyAccountError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return item, classifyAccountError(ctx, err)
	}
	item.InternalID = phoneID
	item.Verified = true
	item.CreatedAt = item.CreatedAt.UTC()
	if err := db.QueryRowContext(ctx, `SELECT is_primary FROM phone_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND id=$3`, int64(current.ApplicationInstanceID), int64(current.UserID), int64(phoneID)).Scan(&item.Primary); err != nil {
		return item, classifyAccountError(ctx, err)
	}
	return item, nil
}

func (s *Store) GetAccountProfile(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID) (authentication.AccountProfile, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() {
		return authentication.AccountProfile{}, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var displayName, givenName, familyName, locale sql.NullString
	err := db.QueryRowContext(ctx, `SELECT display_name,given_name,family_name,locale FROM users WHERE application_instance_id=$1 AND id=$2`, int64(appID), int64(userID)).Scan(&displayName, &givenName, &familyName, &locale)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.AccountProfile{}, authentication.ErrAccountManagementSession
	}
	if err != nil {
		return authentication.AccountProfile{}, classifyAccountError(ctx, err)
	}
	return authentication.AccountProfile{
		DisplayName: nullStringPtr(displayName),
		GivenName:   nullStringPtr(givenName),
		FamilyName:  nullStringPtr(familyName),
		Locale:      nullStringPtr(locale),
	}, nil
}

func (s *Store) UpdateAccountProfile(ctx context.Context, current authentication.AccountManagementSession, profile authentication.AccountProfile, correlationID audit.CorrelationID) (authentication.AccountProfile, error) {
	if s == nil || s.pool == nil || correlationID == (audit.CorrelationID{}) {
		return authentication.AccountProfile{}, authentication.ErrAccountManagementPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.AccountProfile{}, classifyAccountError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockAccountUser(ctx, tx, current); err != nil {
		return authentication.AccountProfile{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET display_name=$3,given_name=$4,family_name=$5,locale=$6 WHERE application_instance_id=$1 AND id=$2`, int64(current.ApplicationInstanceID), int64(current.UserID), profile.DisplayName, profile.GivenName, profile.FamilyName, profile.Locale); err != nil {
		return authentication.AccountProfile{}, classifyAccountError(ctx, err)
	}
	if err := insertAccountAudit(ctx, tx, current, audit.ActionProfileUpdated, "profile", correlationID); err != nil {
		return authentication.AccountProfile{}, classifyAccountError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.AccountProfile{}, classifyAccountError(ctx, err)
	}
	return profile, nil
}

func lockAccountUser(ctx context.Context, tx *sql.Tx, current authentication.AccountManagementSession) error {
	if !current.ApplicationInstanceID.Valid() || !current.UserID.Valid() {
		return authentication.ErrAccountManagementSession
	}
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE application_instance_id=$1 AND id=$2 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.ErrAccountManagementSession
	}
	if err != nil {
		return classifyAccountError(ctx, err)
	}
	return nil
}

func insertAccountAudit(ctx context.Context, tx *sql.Tx, current authentication.AccountManagementSession, action, reference string, correlationID audit.CorrelationID) error {
	return insertAccountAuditOutcome(ctx, tx, current, action, reference, audit.OutcomeSuccess, correlationID)
}

func insertAccountAuditOutcome(ctx context.Context, tx *sql.Tx, current authentication.AccountManagementSession, action, reference, outcome string, correlationID audit.CorrelationID) error {
	category := audit.ResourceCategoryIdentifier
	if action == audit.ActionProfileUpdated {
		category = audit.ResourceCategoryProfile
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(application_instance_id,actor_kind,actor_user_id,subject_user_id,action,resource_category,resource_reference,outcome,correlation_id,source) VALUES($1,$2,$3,$3,$4,$5,$6,$7,$8,$9)`, int64(current.ApplicationInstanceID), audit.ActorKindUser, int64(current.UserID), action, category, reference, outcome, correlationID[:], audit.SourceInternalAccountManagement)
	return err
}

func nullStringPtr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	value := v.String
	return &value
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func classifyAccountError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, authentication.ErrAccountIdentifierUnavailable) ||
		errors.Is(err, authentication.ErrAccountIdentifierNotFound) ||
		errors.Is(err, authentication.ErrAccountIdentifierUnverified) ||
		errors.Is(err, authentication.ErrLastAuthenticationMethod) ||
		errors.Is(err, authentication.ErrEmailVerificationResendCooldown) ||
		errors.Is(err, authentication.ErrEmailVerificationIssueLimit) ||
		errors.Is(err, authentication.ErrAccountManagementInvalid) ||
		errors.Is(err, authentication.ErrAccountManagementSession) {
		return err
	}
	return authentication.ErrAccountManagementPersistence
}
