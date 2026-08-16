package grpc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/onbehalfofhim/secrets-keeper/internal/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// contextKey используется для хранения идентификаторов
// аутентифицированного пользователя в context.Context.
type contextKey string

const userIDKey contextKey = "userID"

var (
	ErrUserIDNotFound = errors.New("user ID not found in context")
	ErrInvalidUserID  = errors.New("invalid user ID in context")
)

// UserIDFromContext возвращает идентификатор пользователя
// из контекста текущего gRPC-запроса.
func UserIDFromContext(ctx context.Context) (string, error) {
	value := ctx.Value(userIDKey)
	if value == nil {
		return "", ErrUserIDNotFound
	}

	userID, ok := value.(string)
	if !ok {
		return "", fmt.Errorf(
			"%w: got %T",
			ErrInvalidUserID,
			value,
		)
	}

	return userID, nil
}

// JWTUnaryInterceptor проверяет JWT для unary gRPC-запросов.
//
// Публичные методы регистрации и авторизации доступны без JWT.
// Для остальных методов interceptor извлекает Bearer token
// из metadata, проверяет его и добавляет ID пользователя
// в context запроса.
func JWTUnaryInterceptor(jwtManager *auth.JWT) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if isPublicMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		token, err := extractToken(ctx)
		if err != nil {
			return nil, status.Error(
				codes.Unauthenticated,
				"authentication required",
			)
		}

		userID, err := jwtManager.ValidateToken(token)
		if err != nil {
			return nil, status.Error(
				codes.Unauthenticated,
				"invalid or expired token",
			)
		}

		ctx = context.WithValue(
			ctx,
			userIDKey,
			userID,
		)

		return handler(ctx, req)
	}
}

// extractToken извлекает JWT из authorization metadata.
//
// Ожидаемый формат значения:
//
//	Bearer <token>
func extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("metadata is missing")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return "", errors.New("authorization metadata is missing")
	}

	authHeader := values[0]

	parts := strings.Fields(authHeader)

	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("invalid authorization format")
	}

	return parts[1], nil
}

// isPublicMethod определяет, может ли gRPC-метод
// выполняться без JWT-аутентификации.
func isPublicMethod(method string) bool {
	switch method {
	case "/secretkeeper.v1.AuthService/Register",
		"/secretkeeper.v1.AuthService/Login":
		return true
	default:
		return false
	}
}

// JWTStreamInterceptor проверяет JWT для server-streaming
// и client-streaming gRPC-запросов.
//
// После успешной проверки токена ID пользователя добавляется
// в context stream, доступный обработчику RPC.
func JWTStreamInterceptor(jwtManager *auth.JWT) grpc.StreamServerInterceptor {
	return func(
		srv any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := stream.Context()

		token, err := extractToken(ctx)
		if err != nil {
			return status.Error(
				codes.Unauthenticated,
				"authentication required",
			)
		}

		userID, err := jwtManager.ValidateToken(token)
		if err != nil {
			return status.Error(
				codes.Unauthenticated,
				"invalid or expired token",
			)
		}

		ctx = context.WithValue(
			ctx,
			userIDKey,
			userID,
		)

		wrappedStream := &authenticatedServerStream{
			ServerStream: stream,
			ctx:          ctx,
		}

		return handler(
			srv,
			wrappedStream,
		)
	}
}

// authenticatedServerStream оборачивает grpc.ServerStream,
// заменяя его context на context с идентификатором пользователя.
type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context возвращает context текущего stream с информацией
// об аутентифицированном пользователе.
func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}
