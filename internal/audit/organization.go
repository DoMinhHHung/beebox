package audit

const (
	ActionOrganizationCreated           = "organization.created"
	ActionOrganizationUpdated           = "organization.updated"
	ActionOrganizationMembershipCreated = "organization.membership.created"
	ActionOrganizationMembershipRemoved = "organization.membership.removed"

	ResourceCategoryOrganization           = "organization"
	ResourceCategoryOrganizationMembership = "organization_membership"
	SourceInternalOrganization             = "internal_organization"
)
