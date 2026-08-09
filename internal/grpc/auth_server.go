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

// AuthServer реализует gRPC API для регистрации
// и авторизации пользователей.
type AuthServer struct {
	pb.UnimplementedAuthServiceServer

	service *service.AuthService
	logger  *logger.Logger
}

// NewAuthServer создаёт gRPC-сервер для работы с пользователями.
func NewAuthServer(service *service.AuthService, logger *logger.Logger) *AuthServer {
	return &AuthServer{
		service: service,
		logger:  logger,
	}
}

// Register регистрирует нового пользователя.
//
// В случае успешной регистрации возвращает идентификатор пользователя.
// Ошибки сервиса преобразуются в соответствующие gRPC status codes.
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

// Login выполняет аутентификацию пользователя.
//
// В случае успешной аутентификации возвращает JWT access token
// и время его действия в секундах.
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

// mapAuthError преобразует внутренние ошибки auth/service
// в соответствующие gRPC-коды.
//
// Ошибки валидации преобразуются в InvalidArgument,
// неверные credentials — в Unauthenticated,
// попытка регистрации существующего пользователя —
// в AlreadyExists.
//
// Неизвестные ошибки преобразуются в Internal.
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
