package middleware

import (
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-apperror"
)

func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				apperror.WriteJSON(w, apperror.New(apperror.CodeInternal, "internal error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
