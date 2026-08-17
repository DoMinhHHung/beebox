package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
)

type IntegrationStore struct { pool *database.Pool }
func NewIntegrationStore(pool *database.Pool) *IntegrationStore { return &IntegrationStore{pool:pool} }

func (s *IntegrationStore) CreateCredential(ctx context.Context, appID applicationinstance.InternalID, kind applicationinstance.CredentialKind, material applicationinstance.CredentialMaterial, correlation applicationinstance.CorrelationID) (applicationinstance.Credential, error) {
	if err := ctx.Err(); err != nil { return applicationinstance.Credential{}, err }
	if s == nil || s.pool == nil || !appID.Valid() || !material.PublicID.Valid() { return applicationinstance.Credential{}, applicationinstance.ErrIntegrationPersistence }
	db := s.pool.OpenSQLDB(); defer db.Close()
	tx,err:=db.BeginTx(ctx,nil); if err!=nil{return applicationinstance.Credential{},classifyIntegrationError(ctx,err)}
	defer func(){_ = tx.Rollback()}()
	var c applicationinstance.Credential
	var app int64
	var publishable sql.NullString
	var revoked, lastUsed sql.NullTime
	err = tx.QueryRowContext(ctx, `INSERT INTO application_credentials (public_id,application_instance_id,kind,publishable_key,secret_hash)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id,public_id,application_instance_id,kind,publishable_key,created_at,revoked_at,last_used_at`,
		string(material.PublicID), int64(appID), string(kind), nullableString(material.PublishableKey), nullableBytes(material.SecretHash),
	).Scan(&c.InternalID,&c.PublicID,&app,&c.Kind,&publishable,&c.CreatedAt,&revoked,&lastUsed)
	if err != nil { return applicationinstance.Credential{}, classifyIntegrationError(ctx,err) }
	if err:=insertIntegrationAudit(ctx,tx,appID,applicationinstance.AuditActionCredentialCreated,applicationinstance.AuditResourceCredential,correlation);err!=nil{return applicationinstance.Credential{},classifyIntegrationError(ctx,err)}
	if err:=tx.Commit();err!=nil{return applicationinstance.Credential{},classifyIntegrationError(ctx,err)}
	c.ApplicationInstanceID=applicationinstance.InternalID(app); if publishable.Valid { c.PublishableKey=publishable.String }; if revoked.Valid { t:=revoked.Time.UTC(); c.RevokedAt=&t }; if lastUsed.Valid { t:=lastUsed.Time.UTC(); c.LastUsedAt=&t }; c.CreatedAt=c.CreatedAt.UTC(); return c,nil
}

func (s *IntegrationStore) RevokeCredential(ctx context.Context, id applicationinstance.CredentialPublicID, correlation applicationinstance.CorrelationID) error {
	if err := ctx.Err(); err != nil { return err }
	if s==nil || s.pool==nil || !id.Valid() { return applicationinstance.ErrInvalidCredential }
	db:=s.pool.OpenSQLDB(); defer db.Close(); tx,err:=db.BeginTx(ctx,nil);if err!=nil{return classifyIntegrationError(ctx,err)};defer func(){_ = tx.Rollback()}()
	var appID int64; var revoked sql.NullTime
	err=tx.QueryRowContext(ctx,`SELECT application_instance_id,revoked_at FROM application_credentials WHERE public_id=$1 FOR UPDATE`,string(id)).Scan(&appID,&revoked)
	if errors.Is(err,sql.ErrNoRows){return applicationinstance.ErrCredentialNotFound};if err!=nil{return classifyIntegrationError(ctx,err)}
	if !revoked.Valid {
		if _,err:=tx.ExecContext(ctx,`UPDATE application_credentials SET revoked_at=CURRENT_TIMESTAMP WHERE public_id=$1`,string(id));err!=nil{return classifyIntegrationError(ctx,err)}
		if err:=insertIntegrationAudit(ctx,tx,applicationinstance.InternalID(appID),applicationinstance.AuditActionCredentialRevoked,applicationinstance.AuditResourceCredential,correlation);err!=nil{return classifyIntegrationError(ctx,err)}
	}
	if err:=tx.Commit();err!=nil{return classifyIntegrationError(ctx,err)};return nil
}

func (s *IntegrationStore) ResolvePublishable(ctx context.Context, key string) (applicationinstance.Instance,error) {
	if err:=ctx.Err(); err!=nil { return applicationinstance.Instance{},err }; if s==nil||s.pool==nil { return applicationinstance.Instance{},applicationinstance.ErrIntegrationPersistence }
	db:=s.pool.OpenSQLDB(); defer db.Close(); var instance applicationinstance.Instance; var id int64
	err:=db.QueryRowContext(ctx,`SELECT a.id,a.public_id,a.created_at FROM application_credentials c JOIN application_instances a ON a.id=c.application_instance_id WHERE c.kind='publishable' AND c.publishable_key=$1 AND c.revoked_at IS NULL`,key).Scan(&id,&instance.PublicID,&instance.CreatedAt)
	if errors.Is(err,sql.ErrNoRows){return applicationinstance.Instance{},applicationinstance.ErrCredentialNotFound}; if err!=nil{return applicationinstance.Instance{},classifyIntegrationError(ctx,err)}; instance.InternalID=applicationinstance.InternalID(id); instance.CreatedAt=instance.CreatedAt.UTC(); return instance,nil
}

func (s *IntegrationStore) LoadSecretCredential(ctx context.Context, publicID string) (applicationinstance.Credential,[]byte,error) {
	if err:=ctx.Err(); err!=nil{return applicationinstance.Credential{},nil,err}; if s==nil||s.pool==nil{return applicationinstance.Credential{},nil,applicationinstance.ErrIntegrationPersistence}
	db:=s.pool.OpenSQLDB(); defer db.Close(); var c applicationinstance.Credential; var app int64; var hash []byte; var revoked,lastUsed sql.NullTime
	err:=db.QueryRowContext(ctx,`SELECT id,public_id,application_instance_id,kind,secret_hash,created_at,revoked_at,last_used_at FROM application_credentials WHERE public_id=$1 AND kind='secret'`,publicID).Scan(&c.InternalID,&c.PublicID,&app,&c.Kind,&hash,&c.CreatedAt,&revoked,&lastUsed)
	if errors.Is(err,sql.ErrNoRows){return applicationinstance.Credential{},nil,applicationinstance.ErrCredentialNotFound}; if err!=nil{return applicationinstance.Credential{},nil,classifyIntegrationError(ctx,err)}; c.ApplicationInstanceID=applicationinstance.InternalID(app); c.CreatedAt=c.CreatedAt.UTC(); if revoked.Valid{t:=revoked.Time.UTC();c.RevokedAt=&t}; if lastUsed.Valid{t:=lastUsed.Time.UTC();c.LastUsedAt=&t}; return c,hash,nil
}

func (s *IntegrationStore) AddAllowedOrigin(ctx context.Context, appID applicationinstance.InternalID, canonical string, correlation applicationinstance.CorrelationID) (applicationinstance.AllowedOrigin,error) {
	if err:=ctx.Err();err!=nil{return applicationinstance.AllowedOrigin{},err}; if s==nil||s.pool==nil||!appID.Valid(){return applicationinstance.AllowedOrigin{},applicationinstance.ErrIntegrationPersistence}
	db:=s.pool.OpenSQLDB(); defer db.Close(); tx,err:=db.BeginTx(ctx,nil);if err!=nil{return applicationinstance.AllowedOrigin{},classifyIntegrationError(ctx,err)};defer func(){_ = tx.Rollback()}()
	var o applicationinstance.AllowedOrigin; var app int64
	err=tx.QueryRowContext(ctx,`INSERT INTO application_allowed_origins (application_instance_id,canonical_origin) VALUES ($1,$2) RETURNING id,application_instance_id,canonical_origin,created_at`,int64(appID),canonical).Scan(&o.InternalID,&app,&o.CanonicalOrigin,&o.CreatedAt)
	if err!=nil{return applicationinstance.AllowedOrigin{},classifyIntegrationError(ctx,err)}
	if err:=insertIntegrationAudit(ctx,tx,appID,applicationinstance.AuditActionOriginAdded,applicationinstance.AuditResourceOrigin,correlation);err!=nil{return applicationinstance.AllowedOrigin{},classifyIntegrationError(ctx,err)}
	if err:=tx.Commit();err!=nil{return applicationinstance.AllowedOrigin{},classifyIntegrationError(ctx,err)};o.ApplicationInstanceID=applicationinstance.InternalID(app);o.CreatedAt=o.CreatedAt.UTC();return o,nil
}

func insertIntegrationAudit(ctx context.Context,tx *sql.Tx,appID applicationinstance.InternalID,action,resource string,correlation applicationinstance.CorrelationID)error{
	_,err:=tx.ExecContext(ctx,`INSERT INTO audit_events (application_instance_id,actor_kind,action,resource_category,outcome,correlation_id,source) VALUES ($1,$2,$3,$4,$5,$6,$7)`,int64(appID),applicationinstance.AuditActorOperator,action,resource,applicationinstance.AuditOutcomeSuccess,correlation[:],applicationinstance.AuditSourceOperator);return err
}
func nullableString(v string) any { if v=="" { return nil }; return v }
func nullableBytes(v []byte) any { if len(v)==0 { return nil }; return v }
func classifyIntegrationError(ctx context.Context, err error) error { if e:=ctx.Err();e!=nil{return e}; return applicationinstance.ErrIntegrationPersistence }
