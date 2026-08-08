package grpc

import (
	"context"
	"errors"
	"strings"

	"github.com/onbehalfofhim/secrets-keeper/internal/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKey string

const userIDKey contextKey = "userID"

func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userIDKey).(string)
	return userID, ok
}

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

func isPublicMethod(method string) bool {
	switch method {
	case "/secretkeeper.v1.AuthService/Register",
		"/secretkeeper.v1.AuthService/Login":
		return true
	default:
		return false
	}
}

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

type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}
