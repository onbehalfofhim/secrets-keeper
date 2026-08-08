package grpc

import (
	"context"
	"errors"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthServer struct {
	pb.UnimplementedAuthServiceServer

	service *service.AuthService
}

func NewAuthServer(service *service.AuthService) *AuthServer {
	return &AuthServer{
		service: service,
	}
}

func (s *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	user, err := s.service.Register(
		ctx,
		req.GetLogin(),
		req.GetPassword(),
	)
	if err != nil {
		return nil, mapAuthError(err)
	}

	return &pb.RegisterResponse{
		UserId: user.ID.String(),
	}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	result, err := s.service.Login(
		ctx,
		req.GetLogin(),
		req.GetPassword(),
	)

	if err != nil {
		return nil, mapAuthError(err)
	}

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
