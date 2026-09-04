package httpapi

import (
	"net/http"
	"strings"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
)

func (s *Server) postOwnerSignUp(w http.ResponseWriter, r *http.Request) {
	email, password, err := readOwnerCredentials(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	result, err := s.OwnerSignUp.Execute(r.Context(), email, password)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toOwnerAuthDTO(result))
}

func (s *Server) postOwnerSignIn(w http.ResponseWriter, r *http.Request) {
	email, password, err := readOwnerCredentials(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	result, err := s.OwnerSignIn.Execute(r.Context(), email, password)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOwnerAuthDTO(result))
}

func (s *Server) postOwnerSignOut(w http.ResponseWriter, r *http.Request) {
	if err := s.OwnerSignOut.Execute(r.Context(), bearerToken(r)); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getOwnerMe(w http.ResponseWriter, r *http.Request) {
	account, err := s.OwnerMe.Execute(r.Context(), bearerToken(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOwnerAccountDTO(account))
}

func readOwnerCredentials(r *http.Request) (string, string, error) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return "", "", domain.ErrInvalidInput
	}
	return body.Email, body.Password, nil
}

func bearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	const scheme = "bearer "
	if len(auth) < len(scheme) || !strings.EqualFold(auth[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(auth[len(scheme):])
}
