package grpc

import (
	"context"
	"errors"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/logger"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthServer struct {
	pb.UnimplementedAuthServiceServer

	service *service.AuthService
	logger  *logger.Logger
}

func NewAuthServer(service *service.AuthService, logger *logger.Logger) *AuthServer {
	return &AuthServer{
		service: service,
		logger:  logger,
	}
}

func (s *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	login := req.GetLogin()

	user, err := s.service.Register(ctx, login, req.GetPassword())

	if err != nil {
		s.logger.Error("user registration failed", "login", login, "error", err)

		return nil, mapAuthError(err)
	}

	s.logger.Info("user registered", "userId", user.ID, "login", user.Login)

	return &pb.RegisterResponse{
		UserId: user.ID.String(),
	}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	login := req.GetLogin()

	result, err := s.service.Login(ctx, login, req.GetPassword())

	if err != nil {
		s.logger.Error("user login failed", "login", login, "error", err)

		return nil, mapAuthError(err)
	}

	s.logger.Info("user logged in", "login", login, "expiresIn", result.ExpiresIn)

	return &pb.LoginResponse{
		AccessToken: result.AccessToken,
		ExpiresIn:   result.ExpiresIn,
	}, nil
}

func mapAuthError(err error) error {
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		return status.Error(
			codes.Unauthenticated,
			"invalid credentials",
		)

	case errors.Is(err, repository.ErrUserExists):
		return status.Error(
			codes.AlreadyExists,
			"user already exists",
		)

	case errors.Is(err, service.ErrInvalidLogin),
		errors.Is(err, service.ErrInvalidPassword):
		return status.Error(
			codes.InvalidArgument,
			"invalid registration data",
		)

	default:
		return status.Error(
			codes.Internal,
			"internal server error",
		)
	}
}
