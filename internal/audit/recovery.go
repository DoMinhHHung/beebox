package audit

const (
	ActionRecoveryCodesGenerated     = "authentication.recovery_codes.generated"
	ActionRecoveryCodesRegenerated   = "authentication.recovery_codes.regenerated"
	ActionRecoveryCodeAuthenticated  = "authentication.recovery_code.authenticated"
	ActionRecoveryCodeDenied         = "authentication.recovery_code.denied"
	ActionTOTPReplacementStarted     = "authentication.totp.replacement_started"
	ActionTOTPReplacementCompleted   = "authentication.totp.replacement_completed"

	ResourceCategoryRecovery = "recovery_code_set"
	SourceInternalRecovery   = "internal_recovery"
)
