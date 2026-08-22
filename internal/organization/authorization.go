package organization

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

const AuthorizationKeyMaxBytes = 63

var (
	ErrRoleNotFound             = errors.New("organization role not found")
	ErrRoleUnavailable          = errors.New("organization role unavailable")
	ErrPermissionNotFound       = errors.New("organization permission not found")
	ErrPermissionUnavailable    = errors.New("organization permission unavailable")
	ErrGrantNotFound            = errors.New("organization role permission grant not found")
	ErrGrantUnavailable         = errors.New("organization role permission grant unavailable")
	ErrRoleAssignmentNotFound   = errors.New("organization membership role assignment not found")
	ErrAuthorizationPersistence = errors.New("organization authorization persistence failure")
)

type RoleID string

func (id RoleID) Valid() bool { return validAuthorizationUUID(string(id)) }

type PermissionID string

func (id PermissionID) Valid() bool { return validAuthorizationUUID(string(id)) }

func validAuthorizationUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	hexBody := strings.ReplaceAll(value, "-", "")
	raw, err := hex.DecodeString(hexBody)
	if err != nil || len(raw) != 16 {
		return false
	}
	return raw[6]>>4 == 4 && raw[8]&0xc0 == 0x80 && value == strings.ToLower(value)
}

type RoleDefinition struct {
	ID                    RoleID
	ApplicationInstanceID applicationinstance.InternalID
	Key                   string
	CreatedAt             time.Time
}

type PermissionDefinition struct {
	ID                    PermissionID
	ApplicationInstanceID applicationinstance.InternalID
	Key                   string
	Resource              string
	Action                string
	CreatedAt             time.Time
}

type Decision uint8

const (
	DecisionDeny Decision = iota
	DecisionAllow
)

func (d Decision) Allowed() bool { return d == DecisionAllow }

func NormalizeAuthorizationKey(input string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(input))
	if value == "" || len(value) > AuthorizationKeyMaxBytes {
		return "", ErrInvalid
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		if i > 0 && (r == '.' || r == '_' || r == '-') {
			continue
		}
		return "", ErrInvalid
	}
	last := value[len(value)-1]
	if last == '.' || last == '_' || last == '-' {
		return "", ErrInvalid
	}
	return value, nil
}

type AuthorizationRepository interface {
	CreateRoleDefinition(context.Context, MutationContext, string) (RoleDefinition, error)
	CreatePermissionDefinition(context.Context, MutationContext, string, string, string) (PermissionDefinition, error)
	GrantPermissionToRole(context.Context, MutationContext, RoleID, PermissionID) error
	RevokePermissionFromRole(context.Context, MutationContext, RoleID, PermissionID) error
	SetMembershipRole(context.Context, MutationContext, MembershipID, RoleID) error
	ClearMembershipRole(context.Context, MutationContext, MembershipID) error
	CheckOrganizationAuthorization(context.Context, applicationinstance.InternalID, identity.PublicID, ID, string, string) (Decision, error)
}

type AuthorizationService struct {
	repository AuthorizationRepository
}

func NewAuthorizationService(repository AuthorizationRepository) (*AuthorizationService, error) {
	if repository == nil {
		return nil, ErrInvalid
	}
	return &AuthorizationService{repository: repository}, nil
}

func (s *AuthorizationService) CreateRoleDefinition(ctx context.Context, current MutationContext, key string) (RoleDefinition, error) {
	if err := ctx.Err(); err != nil {
		return RoleDefinition{}, err
	}
	if s == nil || s.repository == nil || !current.Valid() {
		return RoleDefinition{}, ErrInvalid
	}
	normalized, err := NormalizeAuthorizationKey(key)
	if err != nil {
		return RoleDefinition{}, err
	}
	return s.repository.CreateRoleDefinition(ctx, current, normalized)
}

func (s *AuthorizationService) CreatePermissionDefinition(ctx context.Context, current MutationContext, key, resource, action string) (PermissionDefinition, error) {
	if err := ctx.Err(); err != nil {
		return PermissionDefinition{}, err
	}
	if s == nil || s.repository == nil || !current.Valid() {
		return PermissionDefinition{}, ErrInvalid
	}
	normalizedKey, err := NormalizeAuthorizationKey(key)
	if err != nil {
		return PermissionDefinition{}, err
	}
	normalizedResource, err := NormalizeAuthorizationKey(resource)
	if err != nil {
		return PermissionDefinition{}, err
	}
	normalizedAction, err := NormalizeAuthorizationKey(action)
	if err != nil {
		return PermissionDefinition{}, err
	}
	return s.repository.CreatePermissionDefinition(ctx, current, normalizedKey, normalizedResource, normalizedAction)
}

func (s *AuthorizationService) GrantPermissionToRole(ctx context.Context, current MutationContext, roleID RoleID, permissionID PermissionID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.repository == nil || !current.Valid() || !roleID.Valid() || !permissionID.Valid() {
		return ErrInvalid
	}
	return s.repository.GrantPermissionToRole(ctx, current, roleID, permissionID)
}

func (s *AuthorizationService) RevokePermissionFromRole(ctx context.Context, current MutationContext, roleID RoleID, permissionID PermissionID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.repository == nil || !current.Valid() || !roleID.Valid() || !permissionID.Valid() {
		return ErrInvalid
	}
	return s.repository.RevokePermissionFromRole(ctx, current, roleID, permissionID)
}

func (s *AuthorizationService) SetMembershipRole(ctx context.Context, current MutationContext, membershipID MembershipID, roleID RoleID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.repository == nil || !current.Valid() || !membershipID.Valid() || !roleID.Valid() {
		return ErrInvalid
	}
	return s.repository.SetMembershipRole(ctx, current, membershipID, roleID)
}

func (s *AuthorizationService) ClearMembershipRole(ctx context.Context, current MutationContext, membershipID MembershipID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.repository == nil || !current.Valid() || !membershipID.Valid() {
		return ErrInvalid
	}
	return s.repository.ClearMembershipRole(ctx, current, membershipID)
}

func (s *AuthorizationService) CheckOrganizationAuthorization(ctx context.Context, applicationID applicationinstance.InternalID, userPublicID identity.PublicID, organizationID ID, resource, action string) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return DecisionDeny, err
	}
	if s == nil || s.repository == nil || !applicationID.Valid() || !userPublicID.Valid() || !organizationID.Valid() {
		return DecisionDeny, ErrInvalid
	}
	normalizedResource, err := NormalizeAuthorizationKey(resource)
	if err != nil {
		return DecisionDeny, err
	}
	normalizedAction, err := NormalizeAuthorizationKey(action)
	if err != nil {
		return DecisionDeny, err
	}
	return s.repository.CheckOrganizationAuthorization(ctx, applicationID, userPublicID, organizationID, normalizedResource, normalizedAction)
}
