package handler

import (
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-apperror"
)

func ClientConfig(w http.ResponseWriter, _ *http.Request) {
	apperror.WriteJSON(w, apperror.New(apperror.CodeNotImplemented, "client config is not implemented"))
}

func NotFound(w http.ResponseWriter, _ *http.Request) {
	apperror.WriteJSON(w, apperror.New(apperror.CodeNotFound, "not found"))
}
