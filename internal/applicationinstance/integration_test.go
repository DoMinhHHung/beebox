package applicationinstance

import (
	"context"
	"errors"
	"testing"
)

type integrationStub struct {
	material CredentialMaterial
	kind CredentialKind
	credential Credential
	hash []byte
	loadErr error
	origin string
}
func (s *integrationStub) CreateCredential(_ context.Context, _ InternalID, kind CredentialKind, material CredentialMaterial) (Credential,error){s.kind=kind;s.material=material;return Credential{PublicID:material.PublicID,Kind:kind,ApplicationInstanceID:1},nil}
func (*integrationStub) RevokeCredential(context.Context,CredentialPublicID) error{return nil}
func (*integrationStub) ResolvePublishable(context.Context,string)(Instance,error){return Instance{InternalID:1},nil}
func (s *integrationStub) LoadSecretCredential(context.Context,string)(Credential,[]byte,error){return s.credential,s.hash,s.loadErr}
func (s *integrationStub) AddAllowedOrigin(_ context.Context,_ InternalID,origin string)(AllowedOrigin,error){s.origin=origin;return AllowedOrigin{CanonicalOrigin:origin},nil}

func TestCredentialFormatsAndSecretVerification(t *testing.T){
	stub:=&integrationStub{}; service:=NewIntegrationService(stub)
	cred,publishable,err:=service.CreateCredential(context.Background(),1,CredentialKindPublishable); if err!=nil{t.Fatal(err)}
	if !cred.PublicID.Valid() || !validPublishableKey(publishable) || stub.material.SecretHash!=nil {t.Fatal("invalid publishable credential material")}
	secretCred,secret,err:=service.CreateCredential(context.Background(),1,CredentialKindSecret); if err!=nil{t.Fatal(err)}
	if !secretCred.PublicID.Valid() || len(stub.material.SecretHash)!=32 || secret=="" {t.Fatal("invalid secret credential material")}
	locator,raw,ok:=parseSecretKey(secret); if !ok || len(raw)!=32 {t.Fatal("secret key parse failed")}
	stub.credential=Credential{PublicID:secretCred.PublicID,ApplicationInstanceID:1,Kind:CredentialKindSecret}; stub.hash=append([]byte(nil),stub.material.SecretHash...)
	if _,err:=service.AuthenticateSecret(context.Background(),secret);err!=nil{t.Fatalf("AuthenticateSecret()=%v",err)}
	_ = locator
	bad:=secret[:len(secret)-1]+"A"; if _,err:=service.AuthenticateSecret(context.Background(),bad);!errors.Is(err,ErrInvalidCredential){t.Fatalf("bad secret err=%v",err)}
}

func TestCanonicalizeOrigin(t *testing.T){
	got,err:=CanonicalizeOrigin("HTTPS://Example.COM:8443/"); if err!=nil || got!="https://example.com:8443"{t.Fatalf("origin=%q err=%v",got,err)}
	for _,raw:=range []string{"https://example.com/path","https://example.com?q=1","https://example.com/#x","ftp://example.com"," https://example.com"}{if _,err:=CanonicalizeOrigin(raw);!errors.Is(err,ErrInvalidOrigin){t.Fatalf("%q accepted",raw)}}
}
