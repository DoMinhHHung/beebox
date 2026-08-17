package applicationinstance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

type CredentialKind string

const (
	CredentialKindPublishable CredentialKind = "publishable"
	CredentialKindSecret      CredentialKind = "secret"

	AuditActorOperator             = "trusted_operator"
	AuditActionCredentialCreated   = "application.credential.created"
	AuditActionCredentialRevoked   = "application.credential.revoked"
	AuditActionOriginAdded         = "application.allowed_origin.added"
	AuditResourceCredential        = "application_credential"
	AuditResourceOrigin            = "application_allowed_origin"
	AuditOutcomeSuccess            = "success"
	AuditSourceOperator            = "trusted_operator_cli"
)

var (
	ErrInvalidCredential      = errors.New("invalid application credential")
	ErrCredentialNotFound     = errors.New("application credential not found")
	ErrCredentialRevoked      = errors.New("application credential revoked")
	ErrInvalidOrigin          = errors.New("invalid application allowed origin")
	ErrOriginConflict         = errors.New("application allowed origin conflict")
	ErrIntegrationPersistence = errors.New("application integration persistence failure")
)

type CorrelationID [16]byte

type CredentialPublicID string

func (id CredentialPublicID) Valid() bool {
	return publicid.IsUUIDv4(string(id), "cred")
}

type Credential struct {
	InternalID            int64
	PublicID              CredentialPublicID
	ApplicationInstanceID InternalID
	Kind                  CredentialKind
	PublishableKey        string
	CreatedAt             time.Time
	RevokedAt             *time.Time
	LastUsedAt            *time.Time
}

type AllowedOrigin struct {
	InternalID            int64
	ApplicationInstanceID InternalID
	CanonicalOrigin       string
	CreatedAt             time.Time
}

type IntegrationPersistence interface {
	CreateCredential(context.Context, InternalID, CredentialKind, CredentialMaterial, CorrelationID) (Credential, error)
	RevokeCredential(context.Context, CredentialPublicID, CorrelationID) error
	ResolvePublishable(context.Context, string) (Instance, error)
	LoadSecretCredential(context.Context, string) (Credential, []byte, error)
	FinalizeSecretCredential(context.Context, string, []byte) (Credential, error)
	AddAllowedOrigin(context.Context, InternalID, string, CorrelationID) (AllowedOrigin, error)
}

type CredentialMaterial struct {
	PublicID       CredentialPublicID
	PublishableKey string
	SecretHash     []byte
}

type IntegrationService struct {
	persistence IntegrationPersistence
}

func NewIntegrationService(p IntegrationPersistence) *IntegrationService {
	return &IntegrationService{persistence: p}
}

func (s *IntegrationService) CreateCredential(ctx context.Context, appID InternalID, kind CredentialKind) (Credential, string, error) {
	if !appID.Valid() || s == nil || s.persistence == nil {
		return Credential{}, "", ErrIntegrationPersistence
	}
	material, raw, err := newCredentialMaterial(kind)
	if err != nil {
		return Credential{}, "", err
	}
	correlation, err := newCorrelationID()
	if err != nil {
		return Credential{}, "", ErrIntegrationPersistence
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, "", err
	}
	credential, err := s.persistence.CreateCredential(ctx, appID, kind, material, correlation)
	if err != nil {
		return Credential{}, "", err
	}
	return credential, raw, nil
}

func (s *IntegrationService) RevokeCredential(ctx context.Context, id CredentialPublicID) error {
	if !id.Valid() || s == nil || s.persistence == nil {
		return ErrInvalidCredential
	}
	correlation, err := newCorrelationID()
	if err != nil {
		return ErrIntegrationPersistence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.persistence.RevokeCredential(ctx, id, correlation)
}

func (s *IntegrationService) ResolvePublishable(ctx context.Context, key string) (Instance, error) {
	if !validPublishableKey(key) || s == nil || s.persistence == nil {
		return Instance{}, ErrInvalidCredential
	}
	return s.persistence.ResolvePublishable(ctx, key)
}

func (s *IntegrationService) AuthenticateSecret(ctx context.Context, key string) (Instance, error) {
	locator, secret, ok := parseSecretKey(key)
	if !ok || s == nil || s.persistence == nil {
		return Instance{}, ErrInvalidCredential
	}
	_, storedHash, err := s.persistence.LoadSecretCredential(ctx, locator)
	candidate := sha256.Sum256(secret)
	var zero [32]byte
	compare := subtle.ConstantTimeCompare(zero[:], candidate[:])
	if err == nil && len(storedHash) == 32 {
		compare = subtle.ConstantTimeCompare(storedHash, candidate[:])
	}
	if err != nil || compare != 1 {
		return Instance{}, ErrInvalidCredential
	}
	credential, err := s.persistence.FinalizeSecretCredential(ctx, locator, candidate[:])
	if err != nil {
		return Instance{}, err
	}
	return Instance{InternalID: credential.ApplicationInstanceID}, nil
}

func (s *IntegrationService) AddAllowedOrigin(ctx context.Context, appID InternalID, raw string) (AllowedOrigin, error) {
	if !appID.Valid() || s == nil || s.persistence == nil {
		return AllowedOrigin{}, ErrIntegrationPersistence
	}
	canonical, err := CanonicalizeOrigin(raw)
	if err != nil {
		return AllowedOrigin{}, err
	}
	correlation, err := newCorrelationID()
	if err != nil {
		return AllowedOrigin{}, ErrIntegrationPersistence
	}
	if err := ctx.Err(); err != nil {
		return AllowedOrigin{}, err
	}
	return s.persistence.AddAllowedOrigin(ctx, appID, canonical, correlation)
}

func CanonicalizeOrigin(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", ErrInvalidOrigin
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return "", ErrInvalidOrigin
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", ErrInvalidOrigin
	}
	if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrInvalidOrigin
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

func newCredentialMaterial(kind CredentialKind) (CredentialMaterial, string, error) {
	publicID, err := publicid.NewUUIDv4("cred")
	if err != nil {
		return CredentialMaterial{}, "", ErrInvalidCredential
	}
	material := CredentialMaterial{PublicID: CredentialPublicID(publicID)}
	body, _ := publicid.UUIDBody(publicID, "cred")
	switch kind {
	case CredentialKindPublishable:
		keyID, err := publicid.NewUUIDv4("pk")
		if err != nil {
			return CredentialMaterial{}, "", ErrInvalidCredential
		}
		keyBody, _ := publicid.UUIDBody(keyID, "pk")
		material.PublishableKey = "bb_pk_" + keyBody
		return material, material.PublishableKey, nil
	case CredentialKindSecret:
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return CredentialMaterial{}, "", ErrInvalidCredential
		}
		hash := sha256.Sum256(secret[:])
		material.SecretHash = append([]byte(nil), hash[:]...)
		encoded := base64.RawURLEncoding.EncodeToString(secret[:])
		return material, "bb_sk_" + body + "." + encoded, nil
	default:
		return CredentialMaterial{}, "", ErrInvalidCredential
	}
}

func newCorrelationID() (CorrelationID, error) {
	var id CorrelationID
	if _, err := rand.Read(id[:]); err != nil {
		return CorrelationID{}, err
	}
	return id, nil
}

func validPublishableKey(key string) bool {
	return strings.HasPrefix(key, "bb_pk_") && publicid.IsUUIDv4("pk_"+strings.TrimPrefix(key, "bb_pk_"), "pk")
}

func parseSecretKey(key string) (string, []byte, bool) {
	if !strings.HasPrefix(key, "bb_sk_") {
		return "", nil, false
	}
	parts := strings.Split(strings.TrimPrefix(key, "bb_sk_"), ".")
	if len(parts) != 2 {
		return "", nil, false
	}
	if !publicid.IsUUIDv4("cred_"+parts[0], "cred") {
		return "", nil, false
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(secret) != 32 {
		return "", nil, false
	}
	return "cred_" + parts[0], secret, true
}
