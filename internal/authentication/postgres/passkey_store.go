package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func (s *Store) ListPasskeyCredentials(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID) ([]authentication.PasskeyCredential, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() {
		return nil, authentication.ErrPasskeyPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT public_id, rp_id, credential_id, credential_json, name, created_at FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2 ORDER BY created_at, public_id LIMIT $3`, int64(appID), int64(userID), authentication.PasskeyListLimit+1)
	if err != nil {
		return nil, classifyPasskeyError(ctx, err)
	}
	defer rows.Close()
	out := make([]authentication.PasskeyCredential, 0)
	for rows.Next() {
		var item authentication.PasskeyCredential
		var raw []byte
		var name sql.NullString
		if err := rows.Scan(&item.PublicID, &item.RPID, &item.CredentialID, &raw, &name, &item.CreatedAt); err != nil {
			return nil, authentication.ErrPasskeyPersistence
		}
		item.CredentialJSON = append(json.RawMessage(nil), raw...)
		if name.Valid {
			item.Name = name.String
		}
		item.CreatedAt = item.CreatedAt.UTC()
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, authentication.ErrPasskeyPersistence
	}
	return out, nil
}

func (s *Store) CreatePasskeyAttempt(ctx context.Context, write authentication.PasskeyAttemptWrite) (string, error) {
	if s == nil || s.pool == nil || !write.ApplicationInstanceID.Valid() || (write.Purpose != "registration" && write.Purpose != "authentication") || write.Origin == "" || write.RPID == "" || len(write.SessionData) == 0 || write.ChallengeHash == ([32]byte{}) || !write.ExpiresAt.After(write.CreatedAt) {
		return "", authentication.ErrPasskeyPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", classifyPasskeyError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if write.Purpose == "registration" {
		if !write.UserID.Valid() || write.SessionPublicID == "" {
			return "", authentication.ErrPasskeyInvalidSession
		}
		var sessionCreated, idleExpires, expires, now time.Time
		var revoked sql.NullTime
		var app, user int64
		err := tx.QueryRowContext(ctx, `SELECT application_instance_id,user_id,created_at,idle_expires_at,expires_at,revoked_at,CURRENT_TIMESTAMP FROM sessions WHERE public_id=$1`, write.SessionPublicID).Scan(&app, &user, &sessionCreated, &idleExpires, &expires, &revoked, &now)
		if err != nil || app != int64(write.ApplicationInstanceID) || user != int64(write.UserID) || revoked.Valid || !now.Before(idleExpires) || !now.Before(expires) {
			return "", authentication.ErrPasskeyInvalidSession
		}
		if !now.Before(sessionCreated.Add(authentication.SocialLinkFreshness)) {
			return "", authentication.ErrPasskeyReverificationRequired
		}
		if write.ExpiresAt.After(sessionCreated.Add(authentication.SocialLinkFreshness)) {
			return "", authentication.ErrPasskeyPersistence
		}
	} else if write.UserID.Valid() || write.SessionPublicID != "" {
		return "", authentication.ErrPasskeyPersistence
	}
	var publicID string
	err = tx.QueryRowContext(ctx, `INSERT INTO passkey_attempts(application_instance_id,user_id,session_public_id,purpose,origin,rp_id,session_data,challenge_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10) RETURNING public_id`, int64(write.ApplicationInstanceID), nullablePasskeyUser(write.UserID), nullablePasskeyString(write.SessionPublicID), write.Purpose, write.Origin, write.RPID, string(write.SessionData), write.ChallengeHash[:], write.CreatedAt.UTC(), write.ExpiresAt.UTC()).Scan(&publicID)
	if err != nil {
		return "", classifyPasskeyError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return "", classifyPasskeyError(ctx, err)
	}
	return publicID, nil
}

func (s *Store) ConsumePasskeyAttempt(ctx context.Context, appID applicationinstance.InternalID, publicID, purpose, origin string) (authentication.PasskeyAttempt, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !authentication.ValidPasskeyAttemptPublicID(publicID) || (purpose != "registration" && purpose != "authentication") || origin == "" {
		return authentication.PasskeyAttempt{}, authentication.ErrPasskeyInvalidAttempt
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PasskeyAttempt{}, classifyPasskeyError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	var out authentication.PasskeyAttempt
	var userID sql.NullInt64
	var userPublic, sessionPublic sql.NullString
	var sessionData []byte
	var appPublic string
	var now time.Time
	err = tx.QueryRowContext(ctx, `SELECT p.public_id,p.application_instance_id,a.public_id,p.user_id,u.public_id,p.session_public_id,p.purpose,p.origin,p.rp_id,p.session_data,p.created_at,p.expires_at,CURRENT_TIMESTAMP FROM passkey_attempts p JOIN application_instances a ON a.id=p.application_instance_id LEFT JOIN users u ON u.application_instance_id=p.application_instance_id AND u.id=p.user_id WHERE p.application_instance_id=$1 AND p.public_id=$2 AND p.purpose=$3 AND p.origin=$4 AND p.consumed_at IS NULL FOR UPDATE OF p`, int64(appID), publicID, purpose, origin).Scan(&out.PublicID, &out.ApplicationInstanceID, &appPublic, &userID, &userPublic, &sessionPublic, &out.Purpose, &out.Origin, &out.RPID, &sessionData, &out.CreatedAt, &out.ExpiresAt, &now)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PasskeyAttempt{}, authentication.ErrPasskeyInvalidAttempt
	}
	if err != nil {
		return authentication.PasskeyAttempt{}, classifyPasskeyError(ctx, err)
	}
	if !now.Before(out.ExpiresAt) {
		return authentication.PasskeyAttempt{}, authentication.ErrPasskeyInvalidAttempt
	}
	if _, err := tx.ExecContext(ctx, `UPDATE passkey_attempts SET consumed_at=CURRENT_TIMESTAMP WHERE application_instance_id=$1 AND public_id=$2`, int64(appID), publicID); err != nil {
		return authentication.PasskeyAttempt{}, classifyPasskeyError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.PasskeyAttempt{}, classifyPasskeyError(ctx, err)
	}
	out.ApplicationPublicID = applicationinstance.PublicID(appPublic)
	if userID.Valid {
		out.UserID = identity.InternalID(userID.Int64)
	}
	if userPublic.Valid {
		out.UserPublicID = identity.PublicID(userPublic.String)
	}
	if sessionPublic.Valid {
		out.SessionPublicID = sessionPublic.String
	}
	out.SessionData = append(json.RawMessage(nil), sessionData...)
	out.CreatedAt = out.CreatedAt.UTC()
	out.ExpiresAt = out.ExpiresAt.UTC()
	return out, nil
}

func (s *Store) CreatePasskeyCredential(ctx context.Context, attempt authentication.PasskeyAttempt, credential authentication.PasskeyCredential, correlationID audit.CorrelationID) (authentication.PasskeyCredential, error) {
	if s == nil || s.pool == nil || !attempt.ApplicationInstanceID.Valid() || !attempt.UserID.Valid() || attempt.Purpose != "registration" || attempt.SessionPublicID == "" || len(credential.CredentialID) == 0 || len(credential.CredentialID) > 1024 || len(credential.CredentialJSON) == 0 || credential.RPID != attempt.RPID || correlationID == (audit.CorrelationID{}) {
		return authentication.PasskeyCredential{}, authentication.ErrPasskeyPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PasskeyCredential{}, classifyPasskeyError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	var app, user int64
	var created, idle, expires, now time.Time
	var revoked sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT application_instance_id,user_id,created_at,idle_expires_at,expires_at,revoked_at,CURRENT_TIMESTAMP FROM sessions WHERE public_id=$1 FOR UPDATE`, attempt.SessionPublicID).Scan(&app, &user, &created, &idle, &expires, &revoked, &now)
	if err != nil || app != int64(attempt.ApplicationInstanceID) || user != int64(attempt.UserID) || revoked.Valid || !now.Before(idle) || !now.Before(expires) {
		return authentication.PasskeyCredential{}, authentication.ErrPasskeyInvalidSession
	}
	if !now.Before(created.Add(authentication.SocialLinkFreshness)) {
		return authentication.PasskeyCredential{}, authentication.ErrPasskeyReverificationRequired
	}
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM passkey_attempts WHERE application_instance_id=$1 AND public_id=$2 AND user_id=$3 AND session_public_id=$4 AND purpose='registration' AND consumed_at IS NOT NULL AND expires_at>CURRENT_TIMESTAMP)`, int64(attempt.ApplicationInstanceID), attempt.PublicID, int64(attempt.UserID), attempt.SessionPublicID).Scan(&active); err != nil || !active {
		return authentication.PasskeyCredential{}, authentication.ErrPasskeyInvalidAttempt
	}
	var out authentication.PasskeyCredential
	var raw []byte
	var storedName sql.NullString
	var name any
	if credential.Name != "" {
		name = credential.Name
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO passkey_credentials(application_instance_id,user_id,rp_id,credential_id,credential_json,name) VALUES($1,$2,$3,$4,$5::jsonb,$6) RETURNING public_id,rp_id,credential_id,credential_json,name,created_at`, int64(attempt.ApplicationInstanceID), int64(attempt.UserID), credential.RPID, credential.CredentialID, string(credential.CredentialJSON), name).Scan(&out.PublicID, &out.RPID, &out.CredentialID, &raw, &storedName, &out.CreatedAt)
	if err != nil {
		return authentication.PasskeyCredential{}, classifyPasskeyError(ctx, err)
	}
	out.CredentialJSON = append(json.RawMessage(nil), raw...)
	if storedName.Valid {
		out.Name = storedName.String
	}
	if err := insertPasskeyAudit(ctx, tx, attempt.ApplicationInstanceID, attempt.UserID, audit.ActionPasskeyRegistered, audit.OutcomeSuccess, "passkey:"+out.PublicID, correlationID); err != nil {
		return authentication.PasskeyCredential{}, authentication.ErrPasskeyPersistence
	}
	if err := tx.Commit(); err != nil {
		return authentication.PasskeyCredential{}, classifyPasskeyError(ctx, err)
	}
	out.CreatedAt = out.CreatedAt.UTC()
	return out, nil
}

func (s *Store) LoadPasskeyUserByHandle(ctx context.Context, appID applicationinstance.InternalID, rpID string, rawID, userHandle []byte) (authentication.PasskeyProtocolUser, error) {
	if s == nil || s.pool == nil || !appID.Valid() || rpID == "" || len(rawID) == 0 || len(userHandle) == 0 {
		return authentication.PasskeyProtocolUser{}, authentication.ErrPasskeyProof
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var userID int64
	var userPublic string
	err := db.QueryRowContext(ctx, `SELECT u.id,u.public_id FROM users u JOIN passkey_credentials p ON p.application_instance_id=u.application_instance_id AND p.user_id=u.id WHERE u.application_instance_id=$1 AND u.public_id=$2 AND p.rp_id=$3 AND p.credential_id=$4`, int64(appID), string(userHandle), rpID, rawID).Scan(&userID, &userPublic)
	if err != nil {
		return authentication.PasskeyProtocolUser{}, authentication.ErrPasskeyProof
	}
	credentials, err := s.listPasskeysForRP(ctx, db, appID, identity.InternalID(userID), rpID)
	if err != nil {
		return authentication.PasskeyProtocolUser{}, err
	}
	return authentication.PasskeyProtocolUser{UserID: identity.InternalID(userID), PublicID: identity.PublicID(userPublic), Credentials: credentials}, nil
}

func (s *Store) listPasskeysForRP(ctx context.Context, db *sql.DB, appID applicationinstance.InternalID, userID identity.InternalID, rpID string) ([]authentication.PasskeyCredential, error) {
	rows, err := db.QueryContext(ctx, `SELECT public_id,rp_id,credential_id,credential_json,name,created_at FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2 AND rp_id=$3 ORDER BY created_at,public_id`, int64(appID), int64(userID), rpID)
	if err != nil {
		return nil, authentication.ErrPasskeyPersistence
	}
	defer rows.Close()
	var out []authentication.PasskeyCredential
	for rows.Next() {
		var item authentication.PasskeyCredential
		var name sql.NullString
		var raw []byte
		if err := rows.Scan(&item.PublicID, &item.RPID, &item.CredentialID, &raw, &name, &item.CreatedAt); err != nil {
			return nil, authentication.ErrPasskeyPersistence
		}
		item.CredentialJSON = append(json.RawMessage(nil), raw...)
		if name.Valid {
			item.Name = name.String
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, authentication.ErrPasskeyPersistence
	}
	return out, nil
}

func (s *Store) FinalizePasskeyAuthentication(ctx context.Context, final authentication.PasskeyAuthFinalize) (authentication.PasskeyAuthResult, error) {
	if s == nil || s.pool == nil || !authentication.ValidPasskeyAttemptPublicID(final.AttemptPublicID) || !final.UserID.Valid() || len(final.Credential.CredentialID) == 0 || len(final.Credential.CredentialJSON) == 0 || final.Credential.RPID == "" || final.SessionPublicID == "" || final.RefreshVerifier == ([32]byte{}) || correlationZero(final.CorrelationID) {
		return authentication.PasskeyAuthResult{}, authentication.ErrPasskeyPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PasskeyAuthResult{}, classifyPasskeyError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	var appID int64
	var appPublic, userPublic string
	err = tx.QueryRowContext(ctx, `SELECT p.application_instance_id,a.public_id,u.public_id FROM passkey_attempts p JOIN application_instances a ON a.id=p.application_instance_id JOIN users u ON u.application_instance_id=p.application_instance_id AND u.id=$2 WHERE p.public_id=$1 AND p.purpose='authentication' AND p.consumed_at IS NOT NULL AND p.expires_at>CURRENT_TIMESTAMP FOR SHARE OF p`, final.AttemptPublicID, int64(final.UserID)).Scan(&appID, &appPublic, &userPublic)
	if err != nil {
		return authentication.PasskeyAuthResult{}, authentication.ErrPasskeyInvalidAttempt
	}
	var credentialPublic string
	err = tx.QueryRowContext(ctx, `SELECT public_id FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2 AND rp_id=$3 AND credential_id=$4 FOR UPDATE`, appID, int64(final.UserID), final.Credential.RPID, final.Credential.CredentialID).Scan(&credentialPublic)
	if err != nil {
		return authentication.PasskeyAuthResult{}, authentication.ErrPasskeyProof
	}
	if _, err = tx.ExecContext(ctx, `UPDATE passkey_credentials SET credential_json=$1::jsonb,updated_at=CURRENT_TIMESTAMP WHERE application_instance_id=$2 AND user_id=$3 AND public_id=$4`, string(final.Credential.CredentialJSON), appID, int64(final.UserID), credentialPublic); err != nil {
		return authentication.PasskeyAuthResult{}, classifyPasskeyError(ctx, err)
	}
	var sessionID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING id`, final.SessionPublicID, appID, int64(final.UserID), final.IdleExpiresAt.UTC(), final.ExpiresAt.UTC()).Scan(&sessionID); err != nil {
		return authentication.PasskeyAuthResult{}, classifyPasskeyError(ctx, err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO session_refresh_credentials(session_id,verifier_hash) VALUES($1,$2)`, sessionID, final.RefreshVerifier[:]); err != nil {
		return authentication.PasskeyAuthResult{}, classifyPasskeyError(ctx, err)
	}
	if err = insertPasskeyAudit(ctx, tx, applicationinstance.InternalID(appID), final.UserID, audit.ActionPasskeyAuthenticated, audit.OutcomeSuccess, "passkey:"+credentialPublic, final.CorrelationID); err != nil {
		return authentication.PasskeyAuthResult{}, authentication.ErrPasskeyPersistence
	}
	if err = tx.Commit(); err != nil {
		return authentication.PasskeyAuthResult{}, classifyPasskeyError(ctx, err)
	}
	return authentication.PasskeyAuthResult{UserPublicID: identity.PublicID(userPublic), ApplicationPublicID: applicationinstance.PublicID(appPublic)}, nil
}

func (s *Store) RemovePasskeyCredential(ctx context.Context, current authentication.PasskeySession, publicID string, correlationID audit.CorrelationID) error {
	if s == nil || s.pool == nil || !current.ApplicationInstanceID.Valid() || !current.UserID.Valid() || !authentication.ValidPasskeyPublicID(publicID) || correlationZero(correlationID) {
		return authentication.ErrPasskeyPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyPasskeyError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	var user int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE application_instance_id=$1 AND id=$2 FOR NO KEY UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&user); err != nil {
		return authentication.ErrPasskeyPersistence
	}
	var targetID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID), publicID).Scan(&targetID)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return authentication.ErrPasskeyPersistence
	}
	var app, userID int64
	var created, idle, expires, now time.Time
	var revoked sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT application_instance_id,user_id,created_at,idle_expires_at,expires_at,revoked_at,CURRENT_TIMESTAMP FROM sessions WHERE public_id=$1 FOR UPDATE`, current.SessionPublicID).Scan(&app, &userID, &created, &idle, &expires, &revoked, &now)
	if err != nil || app != int64(current.ApplicationInstanceID) || userID != int64(current.UserID) || revoked.Valid || !now.Before(idle) || !now.Before(expires) || !created.Equal(current.CreatedAt) {
		return authentication.ErrPasskeyInvalidSession
	}
	if !now.Before(created.Add(authentication.SocialLinkFreshness)) {
		return authentication.ErrPasskeyReverificationRequired
	}
	usable, err := s.usableAfterPasskeyRemoval(ctx, tx, current, targetID)
	if err != nil {
		return err
	}
	if !usable {
		if err = insertPasskeyAudit(ctx, tx, current.ApplicationInstanceID, current.UserID, audit.ActionPasskeyRemoveDenied, audit.OutcomeDenied, "passkey:"+publicID, correlationID); err != nil {
			return authentication.ErrPasskeyPersistence
		}
		if err = tx.Commit(); err != nil {
			return authentication.ErrPasskeyPersistence
		}
		return authentication.ErrLastAuthenticationMethod
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2 AND id=$3`, int64(current.ApplicationInstanceID), int64(current.UserID), targetID); err != nil {
		return authentication.ErrPasskeyPersistence
	}
	if err = insertPasskeyAudit(ctx, tx, current.ApplicationInstanceID, current.UserID, audit.ActionPasskeyRemoved, audit.OutcomeSuccess, "passkey:"+publicID, correlationID); err != nil {
		return authentication.ErrPasskeyPersistence
	}
	if err = tx.Commit(); err != nil {
		return authentication.ErrPasskeyPersistence
	}
	return nil
}

func (s *Store) usableAfterPasskeyRemoval(ctx context.Context, tx *sql.Tx, current authentication.PasskeySession, targetID int64) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2 AND id<>$3`, int64(current.ApplicationInstanceID), int64(current.UserID), targetID).Scan(&count); err != nil {
		return false, authentication.ErrPasskeyPersistence
	}
	if count > 0 {
		return true, nil
	}
	var verifiedEmails, passwords, verifiedPhones int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND verified_at IS NOT NULL`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&verifiedEmails); err != nil {
		return false, authentication.ErrPasskeyPersistence
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM password_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&passwords); err != nil {
		return false, authentication.ErrPasskeyPersistence
	}
	if passwords > 0 && verifiedEmails > 0 {
		return true, nil
	}
	if s.availability.EmailOTP && verifiedEmails > 0 {
		return true, nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM phone_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND verified_at IS NOT NULL`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&verifiedPhones); err != nil {
		return false, authentication.ErrPasskeyPersistence
	}
	if s.availability.PhoneOTP && verifiedPhones > 0 {
		return true, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT provider FROM external_identities WHERE application_instance_id=$1 AND user_id=$2`, int64(current.ApplicationInstanceID), int64(current.UserID))
	if err != nil {
		return false, authentication.ErrPasskeyPersistence
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return false, authentication.ErrPasskeyPersistence
		}
		if s.availability.Social != nil {
			if _, ok := s.availability.Social.Resolve(current.ApplicationPublicID, authentication.Provider(raw)); ok {
				return true, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, authentication.ErrPasskeyPersistence
	}
	return false, nil
}

func insertPasskeyAudit(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, action, outcome, resource string, correlationID audit.CorrelationID) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(application_instance_id,actor_kind,actor_user_id,subject_user_id,action,resource_category,resource_reference,outcome,correlation_id,source) VALUES($1,$2,$3,$3,$4,$5,$6,$7,$8,$9)`, int64(appID), audit.ActorKindSocialUser, int64(userID), action, audit.ResourceCategoryPasskey, resource, outcome, correlationID[:], audit.SourceInternalPasskey)
	return err
}

func classifyPasskeyError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return authentication.ErrPasskeyInvalidRequest
	}
	return authentication.ErrPasskeyPersistence
}

func nullablePasskeyUser(id identity.InternalID) any {
	if id.Valid() {
		return int64(id)
	}
	return nil
}

func nullablePasskeyString(value string) any {
	if value != "" {
		return value
	}
	return nil
}

func correlationZero(id audit.CorrelationID) bool {
	return id == (audit.CorrelationID{})
}
