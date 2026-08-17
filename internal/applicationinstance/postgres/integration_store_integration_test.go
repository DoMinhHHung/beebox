//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

func TestPublicTrustCredentialsOriginsAndPublicIDs(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_public_trust")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil { t.Fatalf("migration.Up()=%v",err) }

	apps := New(pool)
	appA, err := apps.Create(ctx); if err != nil { t.Fatal(err) }
	appB, err := apps.Create(ctx); if err != nil { t.Fatal(err) }
	if !appA.PublicID.Valid() || !appB.PublicID.Valid() || appA.PublicID==appB.PublicID { t.Fatal("application public IDs invalid or duplicate") }
	resolved,err:=apps.ResolveByPublicID(ctx,appA.PublicID); if err!=nil || resolved.InternalID!=appA.InternalID || resolved.PublicID!=appA.PublicID { t.Fatalf("public resolve=%#v err=%v",resolved,err) }

	service:=applicationinstance.NewIntegrationService(NewIntegrationStore(pool))
	pubA,publishable,err:=service.CreateCredential(ctx,appA.InternalID,applicationinstance.CredentialKindPublishable); if err!=nil{t.Fatal(err)}
	secretA,secret,err:=service.CreateCredential(ctx,appA.InternalID,applicationinstance.CredentialKindSecret); if err!=nil{t.Fatal(err)}
	if pubA.ApplicationInstanceID!=appA.InternalID || secretA.ApplicationInstanceID!=appA.InternalID {t.Fatal("credential scope mismatch")}
	if got,err:=service.ResolvePublishable(ctx,publishable);err!=nil||got.InternalID!=appA.InternalID{t.Fatalf("publishable resolve=%#v err=%v",got,err)}
	if got,err:=service.AuthenticateSecret(ctx,secret);err!=nil||got.InternalID!=appA.InternalID{t.Fatalf("secret auth=%#v err=%v",got,err)}

	db:=pool.OpenSQLDB(); defer db.Close()
	var secretHash []byte; var publishableStored sql.NullString
	if err:=db.QueryRowContext(ctx,`SELECT secret_hash,publishable_key FROM application_credentials WHERE public_id=$1`,string(secretA.PublicID)).Scan(&secretHash,&publishableStored);err!=nil{t.Fatal(err)}
	if len(secretHash)!=32 || strings.Contains(string(secretHash),secret) || publishableStored.Valid {t.Fatal("secret plaintext/value combination persisted unsafely")}

	if err:=service.RevokeCredential(ctx,secretA.PublicID);err!=nil{t.Fatal(err)}
	if _,err:=service.AuthenticateSecret(ctx,secret);!errors.Is(err,applicationinstance.ErrCredentialRevoked){t.Fatalf("revoked secret err=%v",err)}

	origin,err:=service.AddAllowedOrigin(ctx,appA.InternalID,"HTTPS://Example.TEST:8443/");if err!=nil{t.Fatal(err)}
	if origin.CanonicalOrigin!="https://example.test:8443"{t.Fatalf("origin=%q",origin.CanonicalOrigin)}
	if _,err:=service.AddAllowedOrigin(ctx,appA.InternalID,"https://example.test:8443");err==nil{t.Fatal("duplicate origin unexpectedly succeeded")}

	pubB,keyB,err:=service.CreateCredential(ctx,appB.InternalID,applicationinstance.CredentialKindPublishable);if err!=nil{t.Fatal(err)}
	if pubB.ApplicationInstanceID==pubA.ApplicationInstanceID{t.Fatal("cross-app credentials share scope")}
	if got,err:=service.ResolvePublishable(ctx,keyB);err!=nil||got.InternalID!=appB.InternalID{t.Fatalf("app B publishable resolve=%#v err=%v",got,err)}
}
