package grpc

import (
	"context"
	"fmt"
	"net"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/auth"
	"github.com/onbehalfofhim/secrets-keeper/internal/logger"

	"google.golang.org/grpc"
)

type Server struct {
	grpcServer *grpc.Server
	port       string
	logger     *logger.Logger
}

func NewServer(port string, authServer *AuthServer, secretServer *SecretServer, binaryServer *BinaryServer, jwtManager *auth.JWT, logger *logger.Logger) *Server {
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
		logger:     logger,
	}
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.port)
	if err != nil {
		s.logger.Error("failed to start gRPC server", "address", s.port, "error", err)

		return fmt.Errorf("listen on %s: %w", s.port, err)
	}

	s.logger.Info("gRPC server started", "address", listener.Addr().String())

	if err := s.grpcServer.Serve(listener); err != nil {
		if err == grpc.ErrServerStopped {
			return nil
		}

		s.logger.Error(
			"gRPC server stopped with error",
			"address", listener.Addr().String(),
			"error", err,
		)

		return err
	}

	return nil
}

func (s *Server) Stop(ctx context.Context) {
	s.logger.Info("stopping gRPC server", "address", s.port)

	stopped := make(chan struct{})

	go func() {
		s.grpcServer.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
		s.logger.Info("gRPC server stopped gracefully", "address", s.port)
	case <-ctx.Done():
		s.logger.Error("gRPC graceful shutdown timeout", "address", s.port, "error", ctx.Err())

		s.grpcServer.Stop()

		s.logger.Info("gRPC server forcefully stopped", "address", s.port)
	}
}
