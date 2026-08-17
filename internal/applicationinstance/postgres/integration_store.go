package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
)

type IntegrationStore struct {
	pool *database.Pool
}

func NewIntegrationStore(pool *database.Pool) *IntegrationStore {
	return &IntegrationStore{pool: pool}
}

func (s *IntegrationStore) CreateCredential(
	ctx context.Context,
	appID applicationinstance.InternalID,
	kind applicationinstance.CredentialKind,
	material applicationinstance.CredentialMaterial,
	correlation applicationinstance.CorrelationID,
) (applicationinstance.Credential, error) {
	if err := ctx.Err(); err != nil {
		return applicationinstance.Credential{}, err
	}
	if s == nil || s.pool == nil || !appID.Valid() || !material.PublicID.Valid() {
		return applicationinstance.Credential{}, applicationinstance.ErrIntegrationPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return applicationinstance.Credential{}, classifyIntegrationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var credential applicationinstance.Credential
	var storedAppID int64
	var publishable sql.NullString
	var revokedAt sql.NullTime
	var lastUsedAt sql.NullTime
	if err := tx.QueryRowContext(
		ctx,
		`INSERT INTO application_credentials (
			public_id, application_instance_id, kind, publishable_key, secret_hash
		 ) VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, public_id, application_instance_id, kind, publishable_key, created_at, revoked_at, last_used_at`,
		string(material.PublicID),
		int64(appID),
		string(kind),
		nullableString(material.PublishableKey),
		nullableBytes(material.SecretHash),
	).Scan(
		&credential.InternalID,
		&credential.PublicID,
		&storedAppID,
		&credential.Kind,
		&publishable,
		&credential.CreatedAt,
		&revokedAt,
		&lastUsedAt,
	); err != nil {
		return applicationinstance.Credential{}, classifyIntegrationError(ctx, err)
	}

	if err := insertIntegrationAudit(
		ctx,
		tx,
		appID,
		applicationinstance.AuditActionCredentialCreated,
		applicationinstance.AuditResourceCredential,
		correlation,
	); err != nil {
		return applicationinstance.Credential{}, classifyIntegrationError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return applicationinstance.Credential{}, classifyIntegrationError(ctx, err)
	}

	credential.ApplicationInstanceID = applicationinstance.InternalID(storedAppID)
	credential.CreatedAt = credential.CreatedAt.UTC()
	if publishable.Valid {
		credential.PublishableKey = publishable.String
	}
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		credential.RevokedAt = &t
	}
	if lastUsedAt.Valid {
		t := lastUsedAt.Time.UTC()
		credential.LastUsedAt = &t
	}
	return credential, nil
}

func (s *IntegrationStore) RevokeCredential(
	ctx context.Context,
	id applicationinstance.CredentialPublicID,
	correlation applicationinstance.CorrelationID,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.pool == nil || !id.Valid() {
		return applicationinstance.ErrInvalidCredential
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyIntegrationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var appID int64
	var revokedAt sql.NullTime
	err = tx.QueryRowContext(
		ctx,
		`SELECT application_instance_id, revoked_at
		 FROM application_credentials
		 WHERE public_id = $1
		 FOR UPDATE`,
		string(id),
	).Scan(&appID, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return applicationinstance.ErrCredentialNotFound
	}
	if err != nil {
		return classifyIntegrationError(ctx, err)
	}

	if !revokedAt.Valid {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE application_credentials
			 SET revoked_at = CURRENT_TIMESTAMP
			 WHERE public_id = $1`,
			string(id),
		); err != nil {
			return classifyIntegrationError(ctx, err)
		}
		if err := insertIntegrationAudit(
			ctx,
			tx,
			applicationinstance.InternalID(appID),
			applicationinstance.AuditActionCredentialRevoked,
			applicationinstance.AuditResourceCredential,
			correlation,
		); err != nil {
			return classifyIntegrationError(ctx, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return classifyIntegrationError(ctx, err)
	}
	return nil
}

func (s *IntegrationStore) ResolvePublishable(ctx context.Context, key string) (applicationinstance.Instance, error) {
	if err := ctx.Err(); err != nil {
		return applicationinstance.Instance{}, err
	}
	if s == nil || s.pool == nil {
		return applicationinstance.Instance{}, applicationinstance.ErrIntegrationPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	var instance applicationinstance.Instance
	var internalID int64
	err := db.QueryRowContext(
		ctx,
		`SELECT a.id, a.public_id, a.created_at
		 FROM application_credentials c
		 JOIN application_instances a ON a.id = c.application_instance_id
		 WHERE c.kind = 'publishable'
		   AND c.publishable_key = $1
		   AND c.revoked_at IS NULL`,
		key,
	).Scan(&internalID, &instance.PublicID, &instance.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return applicationinstance.Instance{}, applicationinstance.ErrCredentialNotFound
	}
	if err != nil {
		return applicationinstance.Instance{}, classifyIntegrationError(ctx, err)
	}
	instance.InternalID = applicationinstance.InternalID(internalID)
	instance.CreatedAt = instance.CreatedAt.UTC()
	return instance, nil
}

func (s *IntegrationStore) LoadSecretCredential(
	ctx context.Context,
	publicID string,
) (applicationinstance.Credential, []byte, error) {
	if err := ctx.Err(); err != nil {
		return applicationinstance.Credential{}, nil, err
	}
	if s == nil || s.pool == nil {
		return applicationinstance.Credential{}, nil, applicationinstance.ErrIntegrationPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	var credential applicationinstance.Credential
	var appID int64
	var secretHash []byte
	var revokedAt sql.NullTime
	var lastUsedAt sql.NullTime
	err := db.QueryRowContext(
		ctx,
		`SELECT id, public_id, application_instance_id, kind, secret_hash, created_at, revoked_at, last_used_at
		 FROM application_credentials
		 WHERE public_id = $1 AND kind = 'secret'`,
		publicID,
	).Scan(
		&credential.InternalID,
		&credential.PublicID,
		&appID,
		&credential.Kind,
		&secretHash,
		&credential.CreatedAt,
		&revokedAt,
		&lastUsedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return applicationinstance.Credential{}, nil, applicationinstance.ErrCredentialNotFound
	}
	if err != nil {
		return applicationinstance.Credential{}, nil, classifyIntegrationError(ctx, err)
	}
	credential.ApplicationInstanceID = applicationinstance.InternalID(appID)
	credential.CreatedAt = credential.CreatedAt.UTC()
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		credential.RevokedAt = &t
	}
	if lastUsedAt.Valid {
		t := lastUsedAt.Time.UTC()
		credential.LastUsedAt = &t
	}
	return credential, secretHash, nil
}

func (s *IntegrationStore) FinalizeSecretCredential(
	ctx context.Context,
	publicID string,
	candidateHash []byte,
) (applicationinstance.Credential, error) {
	if err := ctx.Err(); err != nil {
		return applicationinstance.Credential{}, err
	}
	if s == nil || s.pool == nil || len(candidateHash) != 32 {
		return applicationinstance.Credential{}, applicationinstance.ErrInvalidCredential
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	var credential applicationinstance.Credential
	var appID int64
	var lastUsedAt time.Time
	err := db.QueryRowContext(
		ctx,
		`UPDATE application_credentials
		 SET last_used_at = CURRENT_TIMESTAMP
		 WHERE public_id = $1
		   AND kind = 'secret'
		   AND revoked_at IS NULL
		   AND secret_hash = $2
		 RETURNING id, public_id, application_instance_id, kind, created_at, last_used_at`,
		publicID,
		candidateHash,
	).Scan(
		&credential.InternalID,
		&credential.PublicID,
		&appID,
		&credential.Kind,
		&credential.CreatedAt,
		&lastUsedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return applicationinstance.Credential{}, applicationinstance.ErrInvalidCredential
	}
	if err != nil {
		return applicationinstance.Credential{}, classifyIntegrationError(ctx, err)
	}
	credential.ApplicationInstanceID = applicationinstance.InternalID(appID)
	credential.CreatedAt = credential.CreatedAt.UTC()
	lastUsedUTC := lastUsedAt.UTC()
	credential.LastUsedAt = &lastUsedUTC
	return credential, nil
}

func (s *IntegrationStore) AddAllowedOrigin(
	ctx context.Context,
	appID applicationinstance.InternalID,
	canonical string,
	correlation applicationinstance.CorrelationID,
) (applicationinstance.AllowedOrigin, error) {
	if err := ctx.Err(); err != nil {
		return applicationinstance.AllowedOrigin{}, err
	}
	if s == nil || s.pool == nil || !appID.Valid() {
		return applicationinstance.AllowedOrigin{}, applicationinstance.ErrIntegrationPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return applicationinstance.AllowedOrigin{}, classifyIntegrationError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var origin applicationinstance.AllowedOrigin
	var storedAppID int64
	if err := tx.QueryRowContext(
		ctx,
		`INSERT INTO application_allowed_origins (application_instance_id, canonical_origin)
		 VALUES ($1, $2)
		 RETURNING id, application_instance_id, canonical_origin, created_at`,
		int64(appID),
		canonical,
	).Scan(&origin.InternalID, &storedAppID, &origin.CanonicalOrigin, &origin.CreatedAt); err != nil {
		return applicationinstance.AllowedOrigin{}, classifyIntegrationError(ctx, err)
	}
	if err := insertIntegrationAudit(
		ctx,
		tx,
		appID,
		applicationinstance.AuditActionOriginAdded,
		applicationinstance.AuditResourceOrigin,
		correlation,
	); err != nil {
		return applicationinstance.AllowedOrigin{}, classifyIntegrationError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return applicationinstance.AllowedOrigin{}, classifyIntegrationError(ctx, err)
	}
	origin.ApplicationInstanceID = applicationinstance.InternalID(storedAppID)
	origin.CreatedAt = origin.CreatedAt.UTC()
	return origin, nil
}

func insertIntegrationAudit(
	ctx context.Context,
	tx *sql.Tx,
	appID applicationinstance.InternalID,
	action string,
	resource string,
	correlation applicationinstance.CorrelationID,
) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO audit_events (
			application_instance_id, actor_kind, action, resource_category,
			outcome, correlation_id, source
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		int64(appID),
		applicationinstance.AuditActorOperator,
		action,
		resource,
		applicationinstance.AuditOutcomeSuccess,
		correlation[:],
		applicationinstance.AuditSourceOperator,
	)
	return err
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func classifyIntegrationError(ctx context.Context, _ error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return applicationinstance.ErrIntegrationPersistence
}
