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
	"github.com/DoMinhHHung/beebox/internal/session"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Store) IssuePhoneSignup(ctx context.Context, issue authentication.PhoneSignupIssue) (authentication.PhoneSignupIssueResult, error) {
	if s == nil || s.pool == nil || !issue.ApplicationInstanceID.Valid() || issue.PhoneFingerprint == ([32]byte{}) || !issue.CodeHash.Valid() || issue.CorrelationID == (audit.CorrelationID{}) {
		return authentication.PhoneSignupIssueResult{}, authentication.ErrPhoneSignupPersistence
	}
	phone, err := identity.NormalizePhone(issue.PhoneE164)
	if err != nil || phone.E164 != issue.PhoneE164 {
		return authentication.PhoneSignupIssueResult{}, authentication.ErrPhoneSignupPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PhoneSignupIssueResult{}, classifyPhoneSignup(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var existingID int64
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM phone_identifiers
		WHERE application_instance_id=$1 AND phone_e164=$2 AND verified_at IS NOT NULL
		LIMIT 1`, int64(issue.ApplicationInstanceID), issue.PhoneE164).Scan(&existingID)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return authentication.PhoneSignupIssueResult{}, classifyPhoneSignup(ctx, err)
		}
		return authentication.PhoneSignupIssueResult{}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return authentication.PhoneSignupIssueResult{}, classifyPhoneSignup(ctx, err)
	}

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.PhoneSignupIssueResult{}, classifyPhoneSignup(ctx, err)
	}
	now = now.UTC()
	expiresAt := now.Add(authentication.PhoneOTPCodeTTL)

	var generation int64
	var issueCount int
	var windowStartedAt, lastIssuedAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT generation,issue_count,issue_window_started_at,last_issued_at
		FROM phone_signup_challenges
		WHERE application_instance_id=$1 AND phone_fingerprint=$2
		FOR UPDATE`, int64(issue.ApplicationInstanceID), issue.PhoneFingerprint[:],
	).Scan(&generation, &issueCount, &windowStartedAt, &lastIssuedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO phone_signup_challenges(
				application_instance_id,phone_fingerprint,generation,code_hash,expires_at,
				failed_attempts,issue_count,issue_window_started_at,last_issued_at,consumed_at,updated_at
			) VALUES($1,$2,1,$3,$4,0,1,$5,$5,NULL,$5)`,
			int64(issue.ApplicationInstanceID), issue.PhoneFingerprint[:], issue.CodeHash.StorageEncoding(), expiresAt, now,
		); err != nil {
			return authentication.PhoneSignupIssueResult{}, classifyPhoneSignup(ctx, err)
		}
	case err != nil:
		return authentication.PhoneSignupIssueResult{}, classifyPhoneSignup(ctx, err)
	default:
		windowStartedAt = windowStartedAt.UTC()
		lastIssuedAt = lastIssuedAt.UTC()
		if now.Before(lastIssuedAt.Add(authentication.PhoneOTPResendCooldown)) {
			if err := tx.Commit(); err != nil {
				return authentication.PhoneSignupIssueResult{}, classifyPhoneSignup(ctx, err)
			}
			return authentication.PhoneSignupIssueResult{}, nil
		}
		if !now.Before(windowStartedAt.Add(authentication.PhoneOTPIssueWindow)) {
			issueCount = 1
			windowStartedAt = now
		} else {
			if issueCount >= authentication.PhoneOTPMaxIssues {
				if err := tx.Commit(); err != nil {
					return authentication.PhoneSignupIssueResult{}, classifyPhoneSignup(ctx, err)
				}
				return authentication.PhoneSignupIssueResult{}, nil
			}
			issueCount++
		}
		generation++
		if _, err := tx.ExecContext(ctx, `
			UPDATE phone_signup_challenges
			SET generation=$3,code_hash=$4,expires_at=$5,failed_attempts=0,
			    issue_count=$6,issue_window_started_at=$7,last_issued_at=$8,
			    consumed_at=NULL,updated_at=$8
			WHERE application_instance_id=$1 AND phone_fingerprint=$2`,
			int64(issue.ApplicationInstanceID), issue.PhoneFingerprint[:], generation,
			issue.CodeHash.StorageEncoding(), expiresAt, issueCount, windowStartedAt, now,
		); err != nil {
			return authentication.PhoneSignupIssueResult{}, classifyPhoneSignup(ctx, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return authentication.PhoneSignupIssueResult{}, classifyPhoneSignup(ctx, err)
	}
	return authentication.PhoneSignupIssueResult{ShouldSend: true, Destination: issue.PhoneE164, ExpiresAt: expiresAt}, nil
}

func (s *Store) LoadPhoneSignup(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) (authentication.PhoneSignupChallengeSnapshot, error) {
	if s == nil || s.pool == nil || !appID.Valid() || fingerprint == ([32]byte{}) {
		return authentication.PhoneSignupChallengeSnapshot{}, authentication.ErrPhoneSignupPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var snapshot authentication.PhoneSignupChallengeSnapshot
	var encoded sql.NullString
	var consumedAt sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT generation,code_hash,expires_at,failed_attempts,consumed_at
		FROM phone_signup_challenges
		WHERE application_instance_id=$1 AND phone_fingerprint=$2`, int64(appID), fingerprint[:],
	).Scan(&snapshot.ChallengeGeneration, &encoded, &snapshot.ExpiresAt, &snapshot.FailedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PhoneSignupChallengeSnapshot{}, authentication.ErrPhoneSignupInvalid
	}
	if err != nil {
		return authentication.PhoneSignupChallengeSnapshot{}, classifyPhoneSignup(ctx, err)
	}
	if consumedAt.Valid || !encoded.Valid || snapshot.FailedAttempts >= authentication.PhoneOTPMaxAttempts {
		return authentication.PhoneSignupChallengeSnapshot{}, authentication.ErrPhoneSignupInvalid
	}
	hash, err := authentication.ParseVerificationCodeHash(encoded.String)
	if err != nil {
		return authentication.PhoneSignupChallengeSnapshot{}, authentication.ErrPhoneSignupPersistence
	}
	snapshot.CodeHash = hash
	snapshot.ExpiresAt = snapshot.ExpiresAt.UTC()
	return snapshot, nil
}

func (s *Store) FinalizePhoneSignup(ctx context.Context, final authentication.PhoneSignupFinalize) (authentication.PhoneSignupFinalizeResult, error) {
	if s == nil || s.pool == nil || !final.ApplicationInstanceID.Valid() || final.PhoneFingerprint == ([32]byte{}) || final.ChallengeGeneration <= 0 || final.CorrelationID == (audit.CorrelationID{}) {
		return authentication.PhoneSignupFinalizeResult{}, authentication.ErrPhoneSignupPersistence
	}
	phone, err := identity.NormalizePhone(final.PhoneE164)
	if err != nil || phone.E164 != final.PhoneE164 {
		return authentication.PhoneSignupFinalizeResult{}, authentication.ErrPhoneSignupPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var generation int64
	var encoded sql.NullString
	var expiresAt time.Time
	var failedAttempts int
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT generation,code_hash,expires_at,failed_attempts,consumed_at
		FROM phone_signup_challenges
		WHERE application_instance_id=$1 AND phone_fingerprint=$2
		FOR UPDATE`, int64(final.ApplicationInstanceID), final.PhoneFingerprint[:],
	).Scan(&generation, &encoded, &expiresAt, &failedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PhoneSignupFinalizeResult{}, authentication.ErrPhoneSignupInvalid
	}
	if err != nil {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	if generation != final.ChallengeGeneration || consumedAt.Valid || !encoded.Valid {
		return authentication.PhoneSignupFinalizeResult{}, authentication.ErrPhoneSignupStale
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	now = now.UTC()
	if !now.Before(expiresAt.UTC()) || failedAttempts >= authentication.PhoneOTPMaxAttempts {
		return authentication.PhoneSignupFinalizeResult{}, authentication.ErrPhoneSignupInvalid
	}
	if !final.Matched {
		if _, err := tx.ExecContext(ctx, `
			UPDATE phone_signup_challenges
			SET failed_attempts=failed_attempts+1,updated_at=$3
			WHERE application_instance_id=$1 AND phone_fingerprint=$2`,
			int64(final.ApplicationInstanceID), final.PhoneFingerprint[:], now,
		); err != nil {
			return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
		}
		if err := tx.Commit(); err != nil {
			return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
		}
		return authentication.PhoneSignupFinalizeResult{}, authentication.ErrPhoneSignupInvalid
	}
	if !session.ValidPublicID(final.SessionPublicID) || final.IdleExpiresAt.IsZero() || final.ExpiresAt.IsZero() || final.IdleExpiresAt.After(final.ExpiresAt) {
		return authentication.PhoneSignupFinalizeResult{}, authentication.ErrPhoneSignupPersistence
	}

	var existingID int64
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM phone_identifiers
		WHERE application_instance_id=$1 AND phone_e164=$2 AND verified_at IS NOT NULL
		LIMIT 1`, int64(final.ApplicationInstanceID), final.PhoneE164).Scan(&existingID)
	if err == nil {
		return authentication.PhoneSignupFinalizeResult{}, authentication.ErrPhoneSignupStale
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}

	var userID int64
	var result authentication.PhoneSignupFinalizeResult
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO users(application_instance_id) VALUES($1)
		RETURNING id,public_id`, int64(final.ApplicationInstanceID)).Scan(&userID, &result.UserPublicID); err != nil {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164,verified_at,updated_at)
		VALUES($1,$2,$3,$4,$4)`, int64(final.ApplicationInstanceID), userID, final.PhoneE164, now); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "phone_identifiers_verified_application_phone_key" {
			return authentication.PhoneSignupFinalizeResult{}, authentication.ErrPhoneSignupStale
		}
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE phone_signup_challenges
		SET consumed_at=$4,code_hash=NULL,updated_at=$4
		WHERE application_instance_id=$1 AND phone_fingerprint=$2 AND generation=$3 AND consumed_at IS NULL`,
		int64(final.ApplicationInstanceID), final.PhoneFingerprint[:], final.ChallengeGeneration, now,
	); err != nil {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	var sessionID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		VALUES($1,$2,$3,$4,$5) RETURNING id`, final.SessionPublicID, int64(final.ApplicationInstanceID), userID, final.IdleExpiresAt, final.ExpiresAt,
	).Scan(&sessionID); err != nil {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_refresh_credentials(session_id,verifier_hash) VALUES($1,$2)`, sessionID, final.RefreshVerifier[:]); err != nil {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(application_instance_id,actor_kind,subject_user_id,action,resource_category,outcome,correlation_id,source)
		VALUES($1,'anonymous_phone_signup',$2,'authentication.phone_signup.confirm','user_registration','success',$3,'internal_phone_signup')`,
		int64(final.ApplicationInstanceID), userID, final.CorrelationID[:],
	); err != nil {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT public_id FROM application_instances WHERE id=$1`, int64(final.ApplicationInstanceID)).Scan(&result.ApplicationPublicID); err != nil {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.PhoneSignupFinalizeResult{}, classifyPhoneSignup(ctx, err)
	}
	return result, nil
}

func (s *Store) IssuePhoneOTP(ctx context.Context, issue authentication.PhoneOTPIssue) (authentication.PhoneOTPIssueResult, error) {
	if s == nil || s.pool == nil || !issue.ApplicationInstanceID.Valid() || !issue.CodeHash.Valid() || issue.CorrelationID == (audit.CorrelationID{}) {
		return authentication.PhoneOTPIssueResult{}, authentication.ErrPhoneOTPPersistence
	}
	phone, err := identity.NormalizePhone(issue.PhoneE164)
	if err != nil || phone.E164 != issue.PhoneE164 {
		return authentication.PhoneOTPIssueResult{}, authentication.ErrPhoneOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PhoneOTPIssueResult{}, classifyPhoneOTP(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var phoneID, userID int64
	var destination string
	var verifiedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT id,user_id,phone_e164,verified_at
		FROM phone_identifiers
		WHERE application_instance_id=$1 AND phone_e164=$2 AND verified_at IS NOT NULL
		FOR UPDATE`, int64(issue.ApplicationInstanceID), issue.PhoneE164,
	).Scan(&phoneID, &userID, &destination, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !verifiedAt.Valid) {
		if err := tx.Commit(); err != nil {
			return authentication.PhoneOTPIssueResult{}, classifyPhoneOTP(ctx, err)
		}
		return authentication.PhoneOTPIssueResult{}, nil
	}
	if err != nil {
		return authentication.PhoneOTPIssueResult{}, classifyPhoneOTP(ctx, err)
	}

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.PhoneOTPIssueResult{}, classifyPhoneOTP(ctx, err)
	}
	now = now.UTC()
	expiresAt := now.Add(authentication.PhoneOTPCodeTTL)
	var generation int64
	var issueCount int
	var windowStartedAt, lastIssuedAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT generation,issue_count,issue_window_started_at,last_issued_at
		FROM phone_otp_signin_challenges
		WHERE application_instance_id=$1 AND phone_identifier_id=$2
		FOR UPDATE`, int64(issue.ApplicationInstanceID), phoneID,
	).Scan(&generation, &issueCount, &windowStartedAt, &lastIssuedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO phone_otp_signin_challenges(
				application_instance_id,phone_identifier_id,generation,code_hash,expires_at,
				failed_attempts,issue_count,issue_window_started_at,last_issued_at,consumed_at,updated_at
			) VALUES($1,$2,1,$3,$4,0,1,$5,$5,NULL,$5)`,
			int64(issue.ApplicationInstanceID), phoneID, issue.CodeHash.StorageEncoding(), expiresAt, now,
		); err != nil {
			return authentication.PhoneOTPIssueResult{}, classifyPhoneOTP(ctx, err)
		}
	case err != nil:
		return authentication.PhoneOTPIssueResult{}, classifyPhoneOTP(ctx, err)
	default:
		windowStartedAt = windowStartedAt.UTC()
		lastIssuedAt = lastIssuedAt.UTC()
		if now.Before(lastIssuedAt.Add(authentication.PhoneOTPResendCooldown)) {
			if err := tx.Commit(); err != nil {
				return authentication.PhoneOTPIssueResult{}, classifyPhoneOTP(ctx, err)
			}
			return authentication.PhoneOTPIssueResult{}, nil
		}
		if !now.Before(windowStartedAt.Add(authentication.PhoneOTPIssueWindow)) {
			issueCount = 1
			windowStartedAt = now
		} else {
			if issueCount >= authentication.PhoneOTPMaxIssues {
				if err := tx.Commit(); err != nil {
					return authentication.PhoneOTPIssueResult{}, classifyPhoneOTP(ctx, err)
				}
				return authentication.PhoneOTPIssueResult{}, nil
			}
			issueCount++
		}
		generation++
		if _, err := tx.ExecContext(ctx, `
			UPDATE phone_otp_signin_challenges
			SET generation=$3,code_hash=$4,expires_at=$5,failed_attempts=0,
			    issue_count=$6,issue_window_started_at=$7,last_issued_at=$8,
			    consumed_at=NULL,updated_at=$8
			WHERE application_instance_id=$1 AND phone_identifier_id=$2`,
			int64(issue.ApplicationInstanceID), phoneID, generation, issue.CodeHash.StorageEncoding(), expiresAt, issueCount, windowStartedAt, now,
		); err != nil {
			return authentication.PhoneOTPIssueResult{}, classifyPhoneOTP(ctx, err)
		}
	}
	if err := insertPhoneOTPAudit(ctx, tx, issue.ApplicationInstanceID, identity.InternalID(userID), "authentication.phone_otp.challenge_issued", "success", issue.CorrelationID, "phone_identifier"); err != nil {
		return authentication.PhoneOTPIssueResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return authentication.PhoneOTPIssueResult{}, classifyPhoneOTP(ctx, err)
	}
	return authentication.PhoneOTPIssueResult{ShouldSend: true, Destination: destination, ExpiresAt: expiresAt}, nil
}

func (s *Store) LoadPhoneOTP(ctx context.Context, appID applicationinstance.InternalID, phoneE164 string) (authentication.PhoneOTPChallengeSnapshot, error) {
	if s == nil || s.pool == nil || !appID.Valid() || phoneE164 == "" {
		return authentication.PhoneOTPChallengeSnapshot{}, authentication.ErrPhoneOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var snapshot authentication.PhoneOTPChallengeSnapshot
	var userID, phoneID int64
	var encoded sql.NullString
	var consumedAt, verifiedAt sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT p.user_id,p.id,p.verified_at,c.generation,c.code_hash,c.expires_at,c.failed_attempts,c.consumed_at
		FROM phone_identifiers p
		JOIN phone_otp_signin_challenges c
		  ON c.application_instance_id=p.application_instance_id AND c.phone_identifier_id=p.id
		WHERE p.application_instance_id=$1 AND p.phone_e164=$2`, int64(appID), phoneE164,
	).Scan(&userID, &phoneID, &verifiedAt, &snapshot.ChallengeGeneration, &encoded, &snapshot.ExpiresAt, &snapshot.FailedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PhoneOTPChallengeSnapshot{}, authentication.ErrPhoneOTPInvalid
	}
	if err != nil {
		return authentication.PhoneOTPChallengeSnapshot{}, classifyPhoneOTP(ctx, err)
	}
	if !verifiedAt.Valid || consumedAt.Valid || !encoded.Valid || snapshot.FailedAttempts >= authentication.PhoneOTPMaxAttempts {
		return authentication.PhoneOTPChallengeSnapshot{}, authentication.ErrPhoneOTPInvalid
	}
	hash, err := authentication.ParseVerificationCodeHash(encoded.String)
	if err != nil {
		return authentication.PhoneOTPChallengeSnapshot{}, authentication.ErrPhoneOTPPersistence
	}
	snapshot.UserID = identity.InternalID(userID)
	snapshot.PhoneIdentifierID = identity.PhoneIdentifierInternalID(phoneID)
	snapshot.CodeHash = hash
	snapshot.ExpiresAt = snapshot.ExpiresAt.UTC()
	return snapshot, nil
}

func (s *Store) FinalizePhoneOTP(ctx context.Context, final authentication.PhoneOTPFinalize) (authentication.PhoneOTPFinalizeResult, error) {
	if s == nil || s.pool == nil || !final.ApplicationInstanceID.Valid() || !final.PhoneIdentifierID.Valid() || !final.UserID.Valid() || final.ChallengeGeneration <= 0 || final.CorrelationID == (audit.CorrelationID{}) {
		return authentication.PhoneOTPFinalizeResult{}, authentication.ErrPhoneOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var verifiedAt sql.NullTime
	var currentUserID int64
	err = tx.QueryRowContext(ctx, `
		SELECT user_id,verified_at FROM phone_identifiers
		WHERE application_instance_id=$1 AND id=$2
		FOR UPDATE`, int64(final.ApplicationInstanceID), int64(final.PhoneIdentifierID),
	).Scan(&currentUserID, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (!verifiedAt.Valid || currentUserID != int64(final.UserID))) {
		return authentication.PhoneOTPFinalizeResult{}, authentication.ErrPhoneOTPStale
	}
	if err != nil {
		return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
	}

	var generation int64
	var encoded sql.NullString
	var expiresAt time.Time
	var failedAttempts int
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT generation,code_hash,expires_at,failed_attempts,consumed_at
		FROM phone_otp_signin_challenges
		WHERE application_instance_id=$1 AND phone_identifier_id=$2
		FOR UPDATE`, int64(final.ApplicationInstanceID), int64(final.PhoneIdentifierID),
	).Scan(&generation, &encoded, &expiresAt, &failedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PhoneOTPFinalizeResult{}, authentication.ErrPhoneOTPInvalid
	}
	if err != nil {
		return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
	}
	if generation != final.ChallengeGeneration || consumedAt.Valid || !encoded.Valid {
		return authentication.PhoneOTPFinalizeResult{}, authentication.ErrPhoneOTPStale
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
	}
	now = now.UTC()
	if !now.Before(expiresAt.UTC()) || failedAttempts >= authentication.PhoneOTPMaxAttempts {
		if err := insertPhoneOTPAudit(ctx, tx, final.ApplicationInstanceID, final.UserID, "authentication.phone_otp.confirm", "denied", final.CorrelationID, "phone_identifier"); err != nil {
			return authentication.PhoneOTPFinalizeResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
		}
		return authentication.PhoneOTPFinalizeResult{}, authentication.ErrPhoneOTPInvalid
	}
	if !final.Matched {
		if _, err := tx.ExecContext(ctx, `
			UPDATE phone_otp_signin_challenges
			SET failed_attempts=failed_attempts+1,updated_at=$3
			WHERE application_instance_id=$1 AND phone_identifier_id=$2`, int64(final.ApplicationInstanceID), int64(final.PhoneIdentifierID), now,
		); err != nil {
			return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
		}
		if err := insertPhoneOTPAudit(ctx, tx, final.ApplicationInstanceID, final.UserID, "authentication.phone_otp.confirm", "denied", final.CorrelationID, "phone_identifier"); err != nil {
			return authentication.PhoneOTPFinalizeResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
		}
		return authentication.PhoneOTPFinalizeResult{}, authentication.ErrPhoneOTPInvalid
	}
	if !session.ValidPublicID(final.SessionPublicID) || final.IdleExpiresAt.IsZero() || final.ExpiresAt.IsZero() || final.IdleExpiresAt.After(final.ExpiresAt) {
		return authentication.PhoneOTPFinalizeResult{}, authentication.ErrPhoneOTPPersistence
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE phone_otp_signin_challenges
		SET consumed_at=$4,code_hash=NULL,updated_at=$4
		WHERE application_instance_id=$1 AND phone_identifier_id=$2 AND generation=$3 AND consumed_at IS NULL`,
		int64(final.ApplicationInstanceID), int64(final.PhoneIdentifierID), final.ChallengeGeneration, now,
	); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
	}
	var sessionID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		VALUES($1,$2,$3,$4,$5) RETURNING id`, final.SessionPublicID, int64(final.ApplicationInstanceID), int64(final.UserID), final.IdleExpiresAt, final.ExpiresAt,
	).Scan(&sessionID); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_refresh_credentials(session_id,verifier_hash) VALUES($1,$2)`, sessionID, final.RefreshVerifier[:]); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
	}
	if err := insertPhoneOTPAudit(ctx, tx, final.ApplicationInstanceID, final.UserID, "authentication.phone_otp.confirm", "success", final.CorrelationID, "session"); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, err
	}
	var result authentication.PhoneOTPFinalizeResult
	if err := tx.QueryRowContext(ctx, `
		SELECT u.public_id,a.public_id
		FROM users u JOIN application_instances a ON a.id=u.application_instance_id
		WHERE u.application_instance_id=$1 AND u.id=$2`, int64(final.ApplicationInstanceID), int64(final.UserID),
	).Scan(&result.UserPublicID, &result.ApplicationPublicID); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, classifyPhoneOTP(ctx, err)
	}
	return result, nil
}

func insertPhoneOTPAudit(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, action, outcome string, correlationID audit.CorrelationID, resource string) error {
	actorKind := "anonymous_phone_otp"
	var actorUser any
	if outcome == "success" && action == "authentication.phone_otp.confirm" {
		actorKind = "user"
		actorUser = int64(userID)
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(application_instance_id,actor_kind,actor_user_id,subject_user_id,action,resource_category,outcome,correlation_id,source)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'internal_phone_otp')`,
		int64(appID), actorKind, actorUser, int64(userID), action, resource, outcome, correlationID[:],
	)
	return classifyPhoneOTP(ctx, err)
}

func classifyPhoneSignup(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return authentication.ErrPhoneSignupPersistence
}

func classifyPhoneOTP(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return authentication.ErrPhoneOTPPersistence
}
