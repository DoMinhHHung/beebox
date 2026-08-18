package audit

const (
	ActorKindAnonymousSocial = "anonymous_social"
	ActorKindSocialUser      = "social_user"

	ActionSocialIdentityCreated = "authentication.social.identity_created"
	ActionSocialSessionIssued   = "authentication.social.session_issued"
	ActionSocialCompletionDenied = "authentication.social.completion_denied"

	ResourceCategoryExternalIdentity = "external_identity"
	ResourceCategorySession          = "session"
	ResourceCategorySocialCompletion = "social_completion"

	SourceInternalSocial = "internal_social_auth"
)
