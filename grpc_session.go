package main

import (
	"context"
	"errors"

	"google.golang.org/grpc/metadata"
)

var AuthError = errors.New("Unauthorized")
var SessionError = errors.New("SessionError")
var CSRFError = errors.New("CSRFError")

func (s *Store) Authorize(ctx context.Context, username string) error {
	// get tokens from metadata
	md, _ := metadata.FromIncomingContext(ctx)
	tokens := md.Get("session-token")	
	if len(tokens) == 0 {
		return SessionError
	}
	sessionToken := tokens[0]
	tokens = md.Get("csrf-token")	
	if len(tokens) == 0 {
		return CSRFError
	}
	csrfToken := tokens[0]

	user, err := s.getUser(username)
	if err != nil {
		return AuthError
	}

	if user.SessionToken != sessionToken {
		return SessionError
	}

	if user.CSRFToken != csrfToken {
		return CSRFError
	}

	return nil
}
