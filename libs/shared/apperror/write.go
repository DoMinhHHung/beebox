package apperror

import (
	"encoding/json"
	"errors"
	"net/http"
)

type jsonError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type jsonBody struct {
	Error jsonError `json:"error"`
}

func WriteJSON(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}

	ae := &Error{}
	if !errors.As(err, &ae) {
		ae = New(CodeInternal, "internal error")
	}

	status := ae.HTTPStatus
	if status == 0 {
		status = HTTPStatus(ae.Code)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonBody{
		Error: jsonError{
			Code:    ae.Code,
			Message: ae.Message,
		},
	})
}
