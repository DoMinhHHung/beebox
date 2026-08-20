package audit

const (
	ActorKindSessionUser = "user"

	ActionSessionSelfRevoke        = "authentication.session.self_revoke"
	ActionSessionRevokeOthers      = "authentication.session.revoke_others"
	ActionSessionSignOutEverywhere = "authentication.session.sign_out_everywhere"

	ResourceCategorySession = "session"

	SourceInternalSessionSelfService = "internal_session_self_service"
)
