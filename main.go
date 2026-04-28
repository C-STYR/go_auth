package main

import (
	"go_auth/proto"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	db := initDB()
	lis, _ := net.Listen("tcp", ":50051")
	s := grpc.NewServer()
	reflection.Register(s)
	proto.RegisterAuthServer(s, &AuthServer{store: &Store{db: db}})

	s.Serve(lis)
}
