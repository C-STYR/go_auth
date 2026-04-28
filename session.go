package main

import (
	"errors"
	"net/http"
)

var AuthError = errors.New("Unauthorized")
var SessionError = errors.New("SessionError")
var CSRFError = errors.New("CSRFError")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		return AuthError
	}

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return SessionError
	}

	csrf := r.Header.Get("X-CSRF-Token")
	if csrf != user.CSRFToken || csrf == "" {
		return CSRFError
	}

	return nil 
}