package audit

const (
	ActionOrganizationCreated                     = "organization.created"
	ActionOrganizationUpdated                     = "organization.updated"
	ActionOrganizationMembershipCreated           = "organization.membership.created"
	ActionOrganizationMembershipRemoved           = "organization.membership.removed"
	ActionOrganizationRoleDefinitionCreated       = "organization.authorization.role.created"
	ActionOrganizationPermissionDefinitionCreated = "organization.authorization.permission.created"
	ActionOrganizationRolePermissionGranted       = "organization.authorization.role_permission.granted"
	ActionOrganizationRolePermissionRevoked       = "organization.authorization.role_permission.revoked"
	ActionOrganizationMembershipRoleSet           = "organization.authorization.membership_role.set"
	ActionOrganizationMembershipRoleCleared       = "organization.authorization.membership_role.cleared"

	ResourceCategoryOrganization               = "organization"
	ResourceCategoryOrganizationMembership     = "organization_membership"
	ResourceCategoryOrganizationRoleDefinition = "organization_role_definition"
	ResourceCategoryOrganizationPermission     = "organization_permission_definition"
	ResourceCategoryOrganizationRolePermission = "organization_role_permission_grant"
	ResourceCategoryOrganizationMembershipRole = "organization_membership_role_assignment"
	SourceInternalOrganization                 = "internal_organization"
)
