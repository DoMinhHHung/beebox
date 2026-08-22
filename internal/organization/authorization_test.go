package organization

import (
	"context"
	"errors"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func TestAuthorizationIdentifiersAndVocabularyAreInternalOpaqueAndCanonical(t *testing.T) {
	t.Parallel()
	validRole := RoleID("01234567-89ab-4cde-8fab-0123456789ab")
	validPermission := PermissionID("11234567-89ab-4cde-8fab-0123456789ab")
	if !validRole.Valid() || !validPermission.Valid() {
		t.Fatal("valid UUIDv4 authorization locator rejected")
	}
	for _, value := range []string{
		"rol_01234567-89ab-4cde-8fab-0123456789ab",
		"01234567-89ab-3cde-8fab-0123456789ab",
		"01234567-89AB-4CDE-8FAB-0123456789AB",
	} {
		if RoleID(value).Valid() || PermissionID(value).Valid() {
			t.Fatalf("invalid authorization locator accepted: %q", value)
		}
	}

	for input, want := range map[string]string{
		" Admin ":           "admin",
		"organization.Read": "organization.read",
		"member_manage":     "member_manage",
		"role-change":       "role-change",
	} {
		got, err := NormalizeAuthorizationKey(input)
		if err != nil || got != want {
			t.Fatalf("NormalizeAuthorizationKey(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, invalid := range []string{"", "*", ".read", "read.", "role:*", "café"} {
		if _, err := NormalizeAuthorizationKey(invalid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("NormalizeAuthorizationKey(%q) error = %v, want ErrInvalid", invalid, err)
		}
	}
}

func TestAuthorizationServiceCanonicalizesPolicyInputsWithoutAcceptingRoleAuthority(t *testing.T) {
	t.Parallel()
	repository := &authorizationTestRepository{}
	service, err := NewAuthorizationService(repository)
	if err != nil {
		t.Fatal(err)
	}
	appID := applicationinstance.InternalID(7)
	userID := identity.PublicID("usr_123e4567-e89b-42d3-a456-426614174001")
	orgID := ID("01234567-89ab-4cde-8fab-0123456789ab")
	decision, err := service.CheckOrganizationAuthorization(context.Background(), appID, userID, orgID, "Organization", "READ")
	if err != nil || decision != DecisionDeny {
		t.Fatalf("CheckOrganizationAuthorization() = %v, %v", decision, err)
	}
	if repository.resource != "organization" || repository.action != "read" {
		t.Fatalf("repository policy input = %q/%q", repository.resource, repository.action)
	}
}

type authorizationTestRepository struct {
	resource string
	action   string
}

func (*authorizationTestRepository) CreateRoleDefinition(context.Context, MutationContext, string) (RoleDefinition, error) {
	return RoleDefinition{}, errors.New("unexpected CreateRoleDefinition")
}
func (*authorizationTestRepository) CreatePermissionDefinition(context.Context, MutationContext, string, string, string) (PermissionDefinition, error) {
	return PermissionDefinition{}, errors.New("unexpected CreatePermissionDefinition")
}
func (*authorizationTestRepository) GrantPermissionToRole(context.Context, MutationContext, RoleID, PermissionID) error {
	return errors.New("unexpected GrantPermissionToRole")
}
func (*authorizationTestRepository) RevokePermissionFromRole(context.Context, MutationContext, RoleID, PermissionID) error {
	return errors.New("unexpected RevokePermissionFromRole")
}
func (*authorizationTestRepository) SetMembershipRole(context.Context, MutationContext, MembershipID, RoleID) error {
	return errors.New("unexpected SetMembershipRole")
}
func (*authorizationTestRepository) ClearMembershipRole(context.Context, MutationContext, MembershipID) error {
	return errors.New("unexpected ClearMembershipRole")
}
func (r *authorizationTestRepository) CheckOrganizationAuthorization(_ context.Context, _ applicationinstance.InternalID, _ identity.PublicID, _ ID, resource, action string) (Decision, error) {
	r.resource = resource
	r.action = action
	return DecisionDeny, nil
}
