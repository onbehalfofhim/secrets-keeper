package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/auth"
	"github.com/onbehalfofhim/secrets-keeper/internal/logger"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockUserRepo struct {
	createFunc func(ctx context.Context, login, passwordHash string) (*models.User, error)

	getByLoginFunc func(ctx context.Context, login string) (*models.User, error)

	createCalled     bool
	getByLoginCalled bool

	createLogin        string
	createPasswordHash string
	getByLogin         string
}

func (m *mockUserRepo) Create(ctx context.Context, login, passwordHash string) (*models.User, error) {
	m.createCalled = true
	m.createLogin = login
	m.createPasswordHash = passwordHash

	if m.createFunc != nil {
		return m.createFunc(ctx, login, passwordHash)
	}

	return nil, nil
}

func (m *mockUserRepo) GetByLogin(ctx context.Context, login string) (*models.User, error) {
	m.getByLoginCalled = true
	m.getByLogin = login

	if m.getByLoginFunc != nil {
		return m.getByLoginFunc(ctx, login)
	}

	return nil, nil
}

func (m *mockUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return nil, nil
}

func newTestAuthServer(repo repository.UserRepo) *AuthServer {
	authService := service.NewAuthService(
		repo,
		auth.NewJWT("test-secret", time.Hour),
	)

	logger := logger.NewLogger()
	return NewAuthServer(authService, logger)
}

func TestNewAuthServer(t *testing.T) {
	authService := service.NewAuthService(
		&mockUserRepo{},
		auth.NewJWT("test-secret", time.Hour),
	)

	logger := logger.NewLogger()

	server := NewAuthServer(authService, logger)

	if server == nil {
		t.Fatal("expected server, got nil")
	}

	if server.service != authService {
		t.Error("server contains unexpected service")
	}
}

func TestAuthServer_Register(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	tests := []struct {
		name string

		request *pb.RegisterRequest

		createFunc func(
			ctx context.Context,
			login, passwordHash string,
		) (*models.User, error)

		wantUserID string
		wantCode   codes.Code
	}{
		{
			name: "success",
			request: &pb.RegisterRequest{
				Login:    "test-user",
				Password: "password",
			},
			createFunc: func(
				ctx context.Context,
				login, passwordHash string,
			) (*models.User, error) {
				return &models.User{
					ID:           userID,
					Login:        login,
					PasswordHash: passwordHash,
				}, nil
			},
			wantUserID: userID.String(),
			wantCode:   codes.OK,
		},
		{
			name: "invalid login",
			request: &pb.RegisterRequest{
				Login:    "",
				Password: "password",
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "invalid password",
			request: &pb.RegisterRequest{
				Login:    "test-user",
				Password: "",
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "user already exists",
			request: &pb.RegisterRequest{
				Login:    "existing-user",
				Password: "password",
			},
			createFunc: func(
				ctx context.Context,
				login, passwordHash string,
			) (*models.User, error) {
				return nil, repository.ErrUserExists
			},
			wantCode: codes.AlreadyExists,
		},
		{
			name: "internal error",
			request: &pb.RegisterRequest{
				Login:    "test-user",
				Password: "password",
			},
			createFunc: func(
				ctx context.Context,
				login, passwordHash string,
			) (*models.User, error) {
				return nil, errors.New("database error")
			},
			wantCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockUserRepo{
				createFunc: tt.createFunc,
			}

			server := newTestAuthServer(repo)

			response, err := server.Register(
				ctx,
				tt.request,
			)

			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if response == nil {
					t.Fatal("expected response, got nil")
				}

				if response.UserId != tt.wantUserID {
					t.Errorf(
						"UserId = %q, want %q",
						response.UserId,
						tt.wantUserID,
					)
				}

				if !repo.createCalled {
					t.Fatal("expected Create to be called")
				}

				if repo.createLogin != tt.request.GetLogin() {
					t.Errorf(
						"Create login = %q, want %q",
						repo.createLogin,
						tt.request.GetLogin(),
					)
				}

				return
			}

			if response != nil {
				t.Errorf(
					"expected nil response, got %+v",
					response,
				)
			}

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if status.Code(err) != tt.wantCode {
				t.Errorf(
					"status code = %v, want %v",
					status.Code(err),
					tt.wantCode,
				)
			}
		})
	}
}

func TestAuthServer_Login(t *testing.T) {
	ctx := context.Background()

	userID := uuid.New()
	password := "password"

	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	tests := []struct {
		name string

		request *pb.LoginRequest

		getByLoginFunc func(
			ctx context.Context,
			login string,
		) (*models.User, error)

		wantCode codes.Code
	}{
		{
			name: "success",
			request: &pb.LoginRequest{
				Login:    "test-user",
				Password: password,
			},
			getByLoginFunc: func(
				ctx context.Context,
				login string,
			) (*models.User, error) {
				return &models.User{
					ID:           userID,
					Login:        login,
					PasswordHash: passwordHash,
				}, nil
			},
			wantCode: codes.OK,
		},
		{
			name: "empty login",
			request: &pb.LoginRequest{
				Login:    "",
				Password: password,
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "empty password",
			request: &pb.LoginRequest{
				Login:    "test-user",
				Password: "",
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "user not found",
			request: &pb.LoginRequest{
				Login:    "unknown",
				Password: password,
			},
			getByLoginFunc: func(
				ctx context.Context,
				login string,
			) (*models.User, error) {
				return nil, repository.ErrUserNotFound
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "wrong password",
			request: &pb.LoginRequest{
				Login:    "test-user",
				Password: "wrong-password",
			},
			getByLoginFunc: func(
				ctx context.Context,
				login string,
			) (*models.User, error) {
				return &models.User{
					ID:           userID,
					Login:        login,
					PasswordHash: passwordHash,
				}, nil
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "repository error",
			request: &pb.LoginRequest{
				Login:    "test-user",
				Password: password,
			},
			getByLoginFunc: func(
				ctx context.Context,
				login string,
			) (*models.User, error) {
				return nil, errors.New("database error")
			},
			wantCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockUserRepo{
				getByLoginFunc: tt.getByLoginFunc,
			}

			server := newTestAuthServer(repo)

			response, err := server.Login(
				ctx,
				tt.request,
			)

			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if response == nil {
					t.Fatal("expected response, got nil")
				}

				if response.AccessToken == "" {
					t.Error("expected non-empty access token")
				}

				expectedExpiresIn := int64(time.Hour.Seconds())

				if response.ExpiresIn != expectedExpiresIn {
					t.Errorf(
						"ExpiresIn = %d, want %d",
						response.ExpiresIn,
						expectedExpiresIn,
					)
				}

				if !repo.getByLoginCalled {
					t.Fatal("expected GetByLogin to be called")
				}

				if repo.getByLogin != tt.request.GetLogin() {
					t.Errorf(
						"GetByLogin login = %q, want %q",
						repo.getByLogin,
						tt.request.GetLogin(),
					)
				}

				return
			}

			if response != nil {
				t.Errorf(
					"expected nil response, got %+v",
					response,
				)
			}

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if status.Code(err) != tt.wantCode {
				t.Errorf(
					"status code = %v, want %v",
					status.Code(err),
					tt.wantCode,
				)
			}
		})
	}
}

func TestMapAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error

		wantCode    codes.Code
		wantMessage string
	}{
		{
			name:        "invalid credentials",
			err:         service.ErrInvalidCredentials,
			wantCode:    codes.Unauthenticated,
			wantMessage: "invalid credentials",
		},
		{
			name:        "user already exists",
			err:         repository.ErrUserExists,
			wantCode:    codes.AlreadyExists,
			wantMessage: "user already exists",
		},
		{
			name:        "invalid login",
			err:         service.ErrInvalidLogin,
			wantCode:    codes.InvalidArgument,
			wantMessage: "invalid registration data",
		},
		{
			name:        "invalid password",
			err:         service.ErrInvalidPassword,
			wantCode:    codes.InvalidArgument,
			wantMessage: "invalid registration data",
		},
		{
			name:        "unknown error",
			err:         errors.New("some internal error"),
			wantCode:    codes.Internal,
			wantMessage: "internal server error",
		},
		{
			name: "wrapped invalid credentials",
			err: errors.Join(
				errors.New("wrapped"),
				service.ErrInvalidCredentials,
			),
			wantCode:    codes.Unauthenticated,
			wantMessage: "invalid credentials",
		},
		{
			name: "wrapped user exists",
			err: errors.Join(
				errors.New("wrapped"),
				repository.ErrUserExists,
			),
			wantCode:    codes.AlreadyExists,
			wantMessage: "user already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapAuthError(tt.err)

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if status.Code(err) != tt.wantCode {
				t.Errorf(
					"status code = %v, want %v",
					status.Code(err),
					tt.wantCode,
				)
			}

			if status.Convert(err).Message() != tt.wantMessage {
				t.Errorf(
					"message = %q, want %q",
					status.Convert(err).Message(),
					tt.wantMessage,
				)
			}
		})
	}
}

func TestMapAuthError_ReturnsGRPCStatus(t *testing.T) {
	err := mapAuthError(service.ErrInvalidCredentials)

	if _, ok := status.FromError(err); !ok {
		t.Fatal("expected gRPC status error")
	}
}
