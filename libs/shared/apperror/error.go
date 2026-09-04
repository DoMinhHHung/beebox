package apperror

import "net/http"

const (
	CodeInternal        = "internal"
	CodeInvalidInput    = "invalid_input"
	CodeUnauthorized    = "unauthorized"
	CodeForbidden       = "forbidden"
	CodeNotFound        = "not_found"
	CodeConflict        = "conflict"
	CodeTooManyRequests = "too_many_requests"
	CodeNotImplemented  = "not_implemented"
	CodeModuleDisabled  = "module_disabled"
	CodePlanLimitFields = "plan_limit_fields"
)

var statusByCode = map[string]int{
	CodeInternal:        http.StatusInternalServerError,
	CodeInvalidInput:    http.StatusBadRequest,
	CodeUnauthorized:    http.StatusUnauthorized,
	CodeForbidden:       http.StatusForbidden,
	CodeNotFound:        http.StatusNotFound,
	CodeConflict:        http.StatusConflict,
	CodeTooManyRequests: http.StatusTooManyRequests,
	CodeNotImplemented:  http.StatusNotImplemented,
	CodeModuleDisabled:  http.StatusForbidden,
	CodePlanLimitFields: http.StatusForbidden,
}

type Error struct {
	Code       string
	Message    string
	HTTPStatus int
	err        error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func HTTPStatus(code string) int {
	if s, ok := statusByCode[code]; ok {
		return s
	}
	return http.StatusInternalServerError
}

func New(code, message string) *Error {
	return &Error{
		Code:       code,
		Message:    message,
		HTTPStatus: HTTPStatus(code),
	}
}

func Wrap(err error, code, message string) *Error {
	return &Error{
		Code:       code,
		Message:    message,
		HTTPStatus: HTTPStatus(code),
		err:        err,
	}
}
