package grpc

import (
	"fmt"
	"net"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/auth"

	"google.golang.org/grpc"
)

type Server struct {
	grpcServer *grpc.Server
	port       string
}

func NewServer(port string, authServer *AuthServer, secretServer *SecretServer, binaryServer *BinaryServer, jwtManager *auth.JWT) *Server {
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(
			JWTUnaryInterceptor(jwtManager),
		),
		grpc.StreamInterceptor(
			JWTStreamInterceptor(jwtManager),
		),
	)

	pb.RegisterAuthServiceServer(
		grpcServer,
		authServer,
	)

	pb.RegisterSecretServiceServer(
		grpcServer,
		secretServer,
	)

	pb.RegisterBinaryServiceServer(
		grpcServer,
		binaryServer,
	)

	return &Server{
		grpcServer: grpcServer,
		port:       port,
	}
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.port)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.port, err)
	}

	return s.grpcServer.Serve(listener)
}

func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}
