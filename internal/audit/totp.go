package audit

const (
	ActionTOTPEnrollmentStarted = "authentication.totp.enrollment_started"
	ActionTOTPActivated         = "authentication.totp.activated"
	ActionTOTPAuthenticated     = "authentication.totp.authenticated"
	ActionTOTPRemoved           = "authentication.totp.removed"
	ActionTOTPRemoveDenied      = "authentication.totp.remove_denied"

	ResourceCategoryTOTP = "totp_credential"
	SourceInternalTOTP   = "internal_totp"
)
