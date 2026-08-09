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

// Server представляет gRPC-сервер приложения.
//
// Server отвечает за создание gRPC-сервера, регистрацию RPC-сервисов,
// запуск сервера и его корректное завершение.
type Server struct {
	grpcServer *grpc.Server
	port       string
	logger     *logger.Logger
}

// NewServer создаёт и настраивает gRPC-сервер.
//
// Регистрирует сервисы аутентификации, работы с секретами и
// бинарными файлами, а также подключает JWT-interceptor'ы
// для unary и streaming RPC.
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

// Start запускает gRPC-сервер.
//
// Метод блокируется до остановки сервера или возникновения ошибки.
// Ошибка grpc.ErrServerStopped считается штатным завершением сервера
// и не возвращается вызывающему коду.
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

// Stop корректно останавливает gRPC-сервер.
//
// Сначала вызывается GracefulStop, который прекращает принимать
// новые RPC и ожидает завершения уже выполняющихся запросов.
// Если сервер не успевает завершить работу до истечения ctx,
// выполняется принудительная остановка через Stop.
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
