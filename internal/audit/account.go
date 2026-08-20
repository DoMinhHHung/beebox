package audit

const (
	ActorKindUser = "user"

	ActionEmailIdentifierAdded    = "authentication.identifier.email_added"
	ActionEmailIdentifierVerified = "authentication.identifier.email_verified"
	ActionEmailIdentifierPrimary  = "authentication.identifier.email_primary_changed"
	ActionEmailIdentifierRemoved  = "authentication.identifier.email_removed"
	ActionPhoneIdentifierAdded    = "authentication.identifier.phone_added"
	ActionPhoneIdentifierVerified = "authentication.identifier.phone_verified"
	ActionPhoneIdentifierPrimary  = "authentication.identifier.phone_primary_changed"
	ActionPhoneIdentifierRemoved  = "authentication.identifier.phone_removed"
	ActionProfileUpdated          = "authentication.profile.updated"

	ResourceCategoryIdentifier = "identifier"
	ResourceCategoryProfile    = "profile"

	SourceInternalAccountManagement = "internal_account_management"
)
