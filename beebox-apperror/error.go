package apperror

import "net/http"

type Code string

const (
	CodeInternal        Code = "internal"
	CodeInvalidInput    Code = "invalid_input"
	CodeUnauthorized    Code = "unauthorized"
	CodeForbidden       Code = "forbidden"
	CodeNotFound        Code = "not_found"
	CodeConflict        Code = "conflict"
	CodeTooManyRequests Code = "too_many_requests"
	CodeNotImplemented  Code = "not_implemented"
	CodeModuleDisabled  Code = "module_disabled"
	CodePlanLimitFields Code = "plan_limit_fields"
)

var statusByCode = map[Code]int{
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
	Code       Code
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

func Status(code Code) int {
	if s, ok := statusByCode[code]; ok {
		return s
	}
	return http.StatusInternalServerError
}

func New(code Code, message string) *Error {
	return &Error{
		Code:       code,
		Message:    message,
		HTTPStatus: Status(code),
	}
}

func Wrap(err error, code Code, message string) *Error {
	return &Error{
		Code:       code,
		Message:    message,
		HTTPStatus: Status(code),
		err:        err,
	}
}
