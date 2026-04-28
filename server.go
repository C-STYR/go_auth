package main

import (
	"context"
	pb "go_auth/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthServer struct {
	pb.UnimplementedAuthServer
	store *Store
}

func (s *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {

	// validate username length
	if len(req.Username) < 8 || len(req.Password) < 8 {
		return nil, status.Error(codes.InvalidArgument, "Invalid username/password")
	}

	// check user exists
	if s.store.userExists(req.Username) {
		return nil, status.Error(codes.AlreadyExists, "User already exists")
	}

	// hash password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash password")
	}

	// create user
	err = s.store.createUser(req.Username, hashedPassword)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create user")
	}

	return &pb.RegisterResponse{Message: "User registered successfully!"}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// get user
	user, err := s.store.getUser(req.Username)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid username")
	}

	if !checkPasswordHash(req.Password, user.HashedPassword) {
		return nil, status.Error(codes.Unauthenticated, "Invalid password")
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	err = s.store.updateTokens(req.Username, sessionToken, csrfToken)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not set tokens")
	}

	md := metadata.Pairs(
		"session-token", sessionToken,
		"csrf-token", csrfToken,
	)

	// queues the metadata to be sent when response goes out
	// client reads it from the resp header
	grpc.SetHeader(ctx, md)

	return &pb.LoginResponse{Message: "User successfully logged in"}, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	if err := s.store.Authorize(ctx, req.Username); err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	if err := s.store.clearTokens(req.Username); err != nil {
		return nil, status.Error(codes.Internal, "could not clear tokens")
	}

	return &pb.LogoutResponse{Message: "User successfully logged out"}, nil
}

func (s *AuthServer) Protected(ctx context.Context, req *pb.ProtectedRequest) (*pb.ProtectedResponse, error) {
	if err := s.store.Authorize(ctx, req.Username); err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &pb.ProtectedResponse{Message: "Authorized!"}, nil
}
