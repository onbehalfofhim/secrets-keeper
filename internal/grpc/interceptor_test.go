package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/onbehalfofhim/secrets-keeper/internal/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestUserIDFromContext(t *testing.T) {
	userID := "550e8400-e29b-41d4-a716-446655440000"

	tests := []struct {
		name    string
		ctx     context.Context
		wantID  string
		wantErr error
	}{
		{
			name: "user ID exists",
			ctx: context.WithValue(
				context.Background(),
				userIDKey,
				userID,
			),
			wantID:  userID,
			wantErr: nil,
		},
		{
			name:    "user ID does not exist",
			ctx:     context.Background(),
			wantID:  "",
			wantErr: ErrUserIDNotFound,
		},
		{
			name: "wrong value type",
			ctx: context.WithValue(
				context.Background(),
				userIDKey,
				123,
			),
			wantID:  "",
			wantErr: ErrInvalidUserID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, err := UserIDFromContext(tt.ctx)

			if gotID != tt.wantID {
				t.Errorf(
					"ID = %q, want %q",
					gotID,
					tt.wantID,
				)
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf(
					"error = %v, want %v",
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name      string
		md        metadata.MD
		wantToken string
		wantErr   bool
	}{
		{
			name: "valid bearer token",
			md: metadata.Pairs(
				"authorization",
				"Bearer test-token",
			),
			wantToken: "test-token",
		},
		{
			name: "bearer is case insensitive",
			md: metadata.Pairs(
				"authorization",
				"bEaReR test-token",
			),
			wantToken: "test-token",
		},
		{
			name: "extra spaces",
			md: metadata.Pairs(
				"authorization",
				"  Bearer   test-token  ",
			),
			wantToken: "test-token",
		},
		{
			name:    "no metadata",
			md:      nil,
			wantErr: true,
		},
		{
			name: "authorization missing",
			md: metadata.Pairs(
				"content-type",
				"application/grpc",
			),
			wantErr: true,
		},
		{
			name: "invalid scheme",
			md: metadata.Pairs(
				"authorization",
				"Basic test-token",
			),
			wantErr: true,
		},
		{
			name: "token missing",
			md: metadata.Pairs(
				"authorization",
				"Bearer",
			),
			wantErr: true,
		},
		{
			name: "too many fields",
			md: metadata.Pairs(
				"authorization",
				"Bearer token extra",
			),
			wantErr: true,
		},
		{
			name: "empty authorization",
			md: metadata.Pairs(
				"authorization",
				"",
			),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			if tt.md != nil {
				ctx = metadata.NewIncomingContext(
					ctx,
					tt.md,
				)
			}

			token, err := extractToken(ctx)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if token != tt.wantToken {
				t.Errorf(
					"token = %q, want %q",
					token,
					tt.wantToken,
				)
			}
		})
	}
}

func TestIsPublicMethod(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{
			method: "/secretkeeper.v1.AuthService/Register",
			want:   true,
		},
		{
			method: "/secretkeeper.v1.AuthService/Login",
			want:   true,
		},
		{
			method: "/secretkeeper.v1.SecretService/CreateSecret",
			want:   false,
		},
		{
			method: "/secretkeeper.v1.SecretService/GetSecret",
			want:   false,
		},
		{
			method: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := isPublicMethod(tt.method)

			if got != tt.want {
				t.Errorf(
					"isPublicMethod(%q) = %v, want %v",
					tt.method,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestJWTUnaryInterceptor_PublicMethod(t *testing.T) {
	jwtManager := auth.NewJWT(
		"test-secret",
		time.Hour,
	)

	interceptor := JWTUnaryInterceptor(jwtManager)

	handlerCalled := false

	handler := func(
		ctx context.Context,
		req any,
	) (any, error) {
		handlerCalled = true

		return "success", nil
	}

	result, err := interceptor(
		context.Background(),
		nil,
		&grpc.UnaryServerInfo{
			FullMethod: "/secretkeeper.v1.AuthService/Login",
		},
		handler,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !handlerCalled {
		t.Fatal("expected handler to be called")
	}

	if result != "success" {
		t.Errorf(
			"result = %v, want success",
			result,
		)
	}
}

func TestJWTUnaryInterceptor_ValidToken(t *testing.T) {
	jwtManager := auth.NewJWT(
		"test-secret",
		time.Hour,
	)

	userID := "550e8400-e29b-41d4-a716-446655440000"

	token, _, err := jwtManager.GenerateToken(userID)
	if err != nil {
		t.Fatalf(
			"failed to generate token: %v",
			err,
		)
	}

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			"authorization",
			"Bearer "+token,
		),
	)

	interceptor := JWTUnaryInterceptor(jwtManager)

	handler := func(
		ctx context.Context,
		req any,
	) (any, error) {
		gotUserID, err := UserIDFromContext(ctx)

		if err != nil {
			t.Fatal("expected user ID in context")
		}

		if gotUserID != userID {
			t.Errorf(
				"userID = %q, want %q",
				gotUserID,
				userID,
			)
		}

		return "success", nil
	}

	result, err := interceptor(
		ctx,
		nil,
		&grpc.UnaryServerInfo{
			FullMethod: "/secretkeeper.v1.SecretService/GetSecret",
		},
		handler,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "success" {
		t.Errorf(
			"result = %v, want success",
			result,
		)
	}
}

func TestJWTUnaryInterceptor_MissingToken(t *testing.T) {
	jwtManager := auth.NewJWT(
		"test-secret",
		time.Hour,
	)

	interceptor := JWTUnaryInterceptor(jwtManager)

	handlerCalled := false

	handler := func(
		ctx context.Context,
		req any,
	) (any, error) {
		handlerCalled = true
		return nil, nil
	}

	_, err := interceptor(
		context.Background(),
		nil,
		&grpc.UnaryServerInfo{
			FullMethod: "/secretkeeper.v1.SecretService/GetSecret",
		},
		handler,
	)

	if status.Code(err) != codes.Unauthenticated {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.Unauthenticated,
		)
	}

	if status.Convert(err).Message() !=
		"authentication required" {
		t.Errorf(
			"message = %q, want %q",
			status.Convert(err).Message(),
			"authentication required",
		)
	}

	if handlerCalled {
		t.Error("handler should not be called")
	}
}

func TestJWTUnaryInterceptor_InvalidToken(t *testing.T) {
	jwtManager := auth.NewJWT(
		"test-secret",
		time.Hour,
	)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			"authorization",
			"Bearer invalid-token",
		),
	)

	interceptor := JWTUnaryInterceptor(jwtManager)

	handlerCalled := false

	handler := func(
		ctx context.Context,
		req any,
	) (any, error) {
		handlerCalled = true
		return nil, nil
	}

	_, err := interceptor(
		ctx,
		nil,
		&grpc.UnaryServerInfo{
			FullMethod: "/secretkeeper.v1.SecretService/GetSecret",
		},
		handler,
	)

	if status.Code(err) != codes.Unauthenticated {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.Unauthenticated,
		)
	}

	if status.Convert(err).Message() !=
		"invalid or expired token" {
		t.Errorf(
			"message = %q, want %q",
			status.Convert(err).Message(),
			"invalid or expired token",
		)
	}

	if handlerCalled {
		t.Error("handler should not be called")
	}
}

func TestJWTUnaryInterceptor_WrongSecret(t *testing.T) {
	generator := auth.NewJWT(
		"secret-1",
		time.Hour,
	)

	validator := auth.NewJWT(
		"secret-2",
		time.Hour,
	)

	token, _, err := generator.GenerateToken(
		"550e8400-e29b-41d4-a716-446655440000",
	)
	if err != nil {
		t.Fatalf(
			"failed to generate token: %v",
			err,
		)
	}

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			"authorization",
			"Bearer "+token,
		),
	)

	interceptor := JWTUnaryInterceptor(validator)

	_, err = interceptor(
		ctx,
		nil,
		&grpc.UnaryServerInfo{
			FullMethod: "/secretkeeper.v1.SecretService/GetSecret",
		},
		func(ctx context.Context, req any) (any, error) {
			return nil, nil
		},
	)

	if status.Code(err) != codes.Unauthenticated {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.Unauthenticated,
		)
	}
}

func TestJWTStreamInterceptor_ValidToken(t *testing.T) {
	jwtManager := auth.NewJWT(
		"test-secret",
		time.Hour,
	)

	userID := "550e8400-e29b-41d4-a716-446655440000"

	token, _, err := jwtManager.GenerateToken(userID)
	if err != nil {
		t.Fatalf(
			"failed to generate token: %v",
			err,
		)
	}

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			"authorization",
			"Bearer "+token,
		),
	)

	stream := &mockServerStream{
		ctx: ctx,
	}

	interceptor := JWTStreamInterceptor(jwtManager)

	handler := func(
		srv any,
		stream grpc.ServerStream,
	) error {
		gotUserID, err := UserIDFromContext(
			stream.Context(),
		)

		if err != nil {
			t.Fatal("expected user ID in context")
		}

		if gotUserID != userID {
			t.Errorf(
				"userID = %q, want %q",
				gotUserID,
				userID,
			)
		}

		return nil
	}

	err = interceptor(
		nil,
		stream,
		&grpc.StreamServerInfo{
			FullMethod: "/secretkeeper.v1.BinaryService/UploadBinary",
		},
		handler,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJWTStreamInterceptor_MissingToken(t *testing.T) {
	jwtManager := auth.NewJWT(
		"test-secret",
		time.Hour,
	)

	stream := &mockServerStream{
		ctx: context.Background(),
	}

	interceptor := JWTStreamInterceptor(jwtManager)

	handlerCalled := false

	handler := func(
		srv any,
		stream grpc.ServerStream,
	) error {
		handlerCalled = true
		return nil
	}

	err := interceptor(
		nil,
		stream,
		&grpc.StreamServerInfo{
			FullMethod: "/secretkeeper.v1.BinaryService/UploadBinary",
		},
		handler,
	)

	if status.Code(err) != codes.Unauthenticated {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.Unauthenticated,
		)
	}

	if status.Convert(err).Message() !=
		"authentication required" {
		t.Errorf(
			"message = %q, want %q",
			status.Convert(err).Message(),
			"authentication required",
		)
	}

	if handlerCalled {
		t.Error("handler should not be called")
	}
}

func TestJWTStreamInterceptor_InvalidToken(t *testing.T) {
	jwtManager := auth.NewJWT(
		"test-secret",
		time.Hour,
	)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			"authorization",
			"Bearer invalid-token",
		),
	)

	stream := &mockServerStream{
		ctx: ctx,
	}

	interceptor := JWTStreamInterceptor(jwtManager)

	handlerCalled := false

	handler := func(
		srv any,
		stream grpc.ServerStream,
	) error {
		handlerCalled = true
		return nil
	}

	err := interceptor(
		nil,
		stream,
		&grpc.StreamServerInfo{
			FullMethod: "/secretkeeper.v1.BinaryService/UploadBinary",
		},
		handler,
	)

	if status.Code(err) != codes.Unauthenticated {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.Unauthenticated,
		)
	}

	if handlerCalled {
		t.Error("handler should not be called")
	}
}

func TestAuthenticatedServerStream_Context(t *testing.T) {
	originalCtx := context.Background()

	expectedCtx := context.WithValue(
		originalCtx,
		userIDKey,
		"test-user",
	)

	stream := &authenticatedServerStream{
		ServerStream: &mockServerStream{
			ctx: originalCtx,
		},
		ctx: expectedCtx,
	}

	if stream.Context() != expectedCtx {
		t.Error(
			"Context() returned unexpected context",
		)
	}

	userID, err := UserIDFromContext(stream.Context())

	if err != nil {
		t.Fatal("expected user ID in context")
	}

	if userID != "test-user" {
		t.Errorf(
			"userID = %q, want %q",
			userID,
			"test-user",
		)
	}
}

type mockServerStream struct {
	grpc.ServerStream

	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}
