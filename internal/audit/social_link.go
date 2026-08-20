package audit

const (
	ActionSocialLinkSucceeded   = "authentication.social.link_succeeded"
	ActionSocialLinkDenied      = "authentication.social.link_denied"
	ActionSocialUnlinkSucceeded = "authentication.social.unlink_succeeded"
	ActionSocialUnlinkDenied    = "authentication.social.unlink_denied"

	ResourceCategorySocialLink = "social_link"
	SourceInternalSocialLink   = "internal_social_link"
)
