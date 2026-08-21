package audit

const (
	ActionPasskeyRegistered    = "authentication.passkey.registered"
	ActionPasskeyAuthenticated = "authentication.passkey.authenticated"
	ActionPasskeyRemoved       = "authentication.passkey.removed"
	ActionPasskeyRemoveDenied  = "authentication.passkey.remove_denied"

	ResourceCategoryPasskey = "passkey"
	SourceInternalPasskey   = "internal_passkey"
)
