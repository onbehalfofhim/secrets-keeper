package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/onbehalfofhim/secrets-keeper/internal/auth"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/service/mocks"

	"github.com/stretchr/testify/mock"
)

func newTestAuthService(repo repository.UserRepo) *AuthService {
	jwt := auth.NewJWT(
		"test-secret",
		time.Hour,
	)

	return NewAuthService(repo, jwt)
}

func TestNewAuthService(t *testing.T) {
	repo := mocks.NewMockUserRepo(t)
	jwt := auth.NewJWT("secret", time.Hour)

	service := NewAuthService(repo, jwt)

	if service == nil {
		t.Fatal("expected service, got nil")
	}

	if service.users != repo {
		t.Error("service contains unexpected user repository")
	}

	if service.jwt != jwt {
		t.Error("service contains unexpected JWT")
	}
}

func TestAuthService_Register(t *testing.T) {
	ctx := context.Background()

	userID := uuid.New()
	createdAt := time.Now()

	repositoryErr := errors.New("database error")

	tests := []struct {
		name      string
		login     string
		password  string
		setupMock func(*mocks.MockUserRepo, string)
		want      *models.User
		wantErr   error
	}{
		{
			name:     "empty login",
			login:    "",
			password: "password",
			wantErr:  ErrInvalidLogin,
		},
		{
			name:     "empty password",
			login:    "test-user",
			password: "",
			wantErr:  ErrInvalidPassword,
		},
		{
			name:     "user already exists",
			login:    "existing-user",
			password: "password",
			setupMock: func(
				repo *mocks.MockUserRepo,
				_ string,
			) {
				repo.EXPECT().
					Create(
						mock.Anything,
						"existing-user",
						mock.Anything,
					).
					Return(nil, repository.ErrUserExists)
			},
			wantErr: repository.ErrUserExists,
		},
		{
			name:     "repository error",
			login:    "test-user",
			password: "password",
			setupMock: func(
				repo *mocks.MockUserRepo,
				_ string,
			) {
				repo.EXPECT().
					Create(
						mock.Anything,
						"test-user",
						mock.Anything,
					).
					Return(nil, repositoryErr)
			},
			wantErr: repositoryErr,
		},
		{
			name:     "success",
			login:    "test-user",
			password: "password",
			setupMock: func(
				repo *mocks.MockUserRepo,
				passwordHash string,
			) {
				repo.EXPECT().
					Create(
						mock.Anything,
						"test-user",
						mock.MatchedBy(func(hash string) bool {
							if hash == passwordHash {
								t.Fatal(
									"password was passed to repository without hashing",
								)
							}

							if err := auth.CheckPassword(
								hash,
								passwordHash,
							); err != nil {
								return false
							}

							return true
						}),
					).
					Return(&models.User{
						ID:        userID,
						Login:     "test-user",
						CreatedAt: createdAt,
					}, nil)
			},
			want: &models.User{
				ID:        userID,
				Login:     "test-user",
				CreatedAt: createdAt,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockUserRepo(t)

			var passwordHash string

			if tt.setupMock != nil {
				if tt.password != "" {
					var err error

					passwordHash, err = auth.HashPassword(tt.password)
					if err != nil {
						t.Fatalf(
							"failed to hash password: %v",
							err,
						)
					}
				}

				// Для успешного сценария setupMock проверяет
				// непосредственно хеш, который будет передан
				// сервисом в repository.
				if tt.name == "success" {
					var capturedHash string

					repo.EXPECT().
						Create(
							mock.Anything,
							tt.login,
							mock.MatchedBy(func(hash string) bool {
								capturedHash = hash

								if hash == tt.password {
									return false
								}

								return auth.CheckPassword(
									hash,
									tt.password,
								) == nil
							}),
						).
						Return(&models.User{
							ID:        userID,
							Login:     tt.login,
							CreatedAt: createdAt,
						}, nil)

					service := newTestAuthService(repo)

					got, err := service.Register(
						ctx,
						tt.login,
						tt.password,
					)

					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}

					if got == nil {
						t.Fatal("expected user, got nil")
					}

					if got.ID != tt.want.ID {
						t.Errorf(
							"ID = %v, want %v",
							got.ID,
							tt.want.ID,
						)
					}

					if got.Login != tt.want.Login {
						t.Errorf(
							"Login = %q, want %q",
							got.Login,
							tt.want.Login,
						)
					}

					if !got.CreatedAt.Equal(tt.want.CreatedAt) {
						t.Errorf(
							"CreatedAt = %v, want %v",
							got.CreatedAt,
							tt.want.CreatedAt,
						)
					}

					if capturedHash == "" {
						t.Fatal("expected password hash to be captured")
					}

					if err := auth.CheckPassword(
						capturedHash,
						tt.password,
					); err != nil {
						t.Fatalf(
							"password hash does not match original password: %v",
							err,
						)
					}

					return
				}

				tt.setupMock(repo, passwordHash)
			}

			service := newTestAuthService(repo)

			got, err := service.Register(
				ctx,
				tt.login,
				tt.password,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf(
						"expected error %v, got %v",
						tt.wantErr,
						err,
					)
				}

				if got != nil {
					t.Errorf(
						"expected nil user, got %+v",
						got,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got == nil {
				t.Fatal("expected user, got nil")
			}
		})
	}
}

func TestAuthService_Register_DoesNotCallRepositoryOnInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		login    string
		password string
		wantErr  error
	}{
		{
			name:     "empty login",
			login:    "",
			password: "password",
			wantErr:  ErrInvalidLogin,
		},
		{
			name:     "empty password",
			login:    "user",
			password: "",
			wantErr:  ErrInvalidPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockUserRepo(t)
			service := newTestAuthService(repo)

			_, err := service.Register(
				context.Background(),
				tt.login,
				tt.password,
			)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf(
					"expected %v, got %v",
					tt.wantErr,
					err,
				)
			}
		})
	}
}

func TestAuthService_Register_WrapsRepositoryError(t *testing.T) {
	repoErr := errors.New("database unavailable")

	repo := mocks.NewMockUserRepo(t)

	repo.EXPECT().
		Create(
			mock.Anything,
			"user",
			mock.Anything,
		).
		Return(nil, repoErr)

	service := newTestAuthService(repo)

	_, err := service.Register(
		context.Background(),
		"user",
		"password",
	)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, repoErr) {
		t.Errorf(
			"expected wrapped repository error %v, got %v",
			repoErr,
			err,
		)
	}
}

func TestAuthService_Login(t *testing.T) {
	ctx := context.Background()

	userID := uuid.New()

	password := "correct-password"

	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	repositoryErr := errors.New("database error")

	tests := []struct {
		name      string
		login     string
		password  string
		setupMock func(*mocks.MockUserRepo)
		wantErr   error
	}{
		{
			name:     "empty login",
			login:    "",
			password: "password",
			wantErr:  ErrInvalidCredentials,
		},
		{
			name:     "empty password",
			login:    "user",
			password: "",
			wantErr:  ErrInvalidCredentials,
		},
		{
			name:     "user not found",
			login:    "unknown",
			password: "password",
			setupMock: func(repo *mocks.MockUserRepo) {
				repo.EXPECT().
					GetByLogin(
						mock.Anything,
						"unknown",
					).
					Return(nil, repository.ErrUserNotFound)
			},
			wantErr: ErrInvalidCredentials,
		},
		{
			name:     "repository error",
			login:    "user",
			password: "password",
			setupMock: func(repo *mocks.MockUserRepo) {
				repo.EXPECT().
					GetByLogin(
						mock.Anything,
						"user",
					).
					Return(nil, repositoryErr)
			},
			wantErr: repositoryErr,
		},
		{
			name:     "wrong password",
			login:    "user",
			password: "wrong-password",
			setupMock: func(repo *mocks.MockUserRepo) {
				repo.EXPECT().
					GetByLogin(
						mock.Anything,
						"user",
					).
					Return(&models.User{
						ID:           userID,
						Login:        "user",
						PasswordHash: passwordHash,
					}, nil)
			},
			wantErr: ErrInvalidCredentials,
		},
		{
			name:     "success",
			login:    "user",
			password: password,
			setupMock: func(repo *mocks.MockUserRepo) {
				repo.EXPECT().
					GetByLogin(
						mock.Anything,
						"user",
					).
					Return(&models.User{
						ID:           userID,
						Login:        "user",
						PasswordHash: passwordHash,
					}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockUserRepo(t)

			if tt.setupMock != nil {
				tt.setupMock(repo)
			}

			service := newTestAuthService(repo)

			got, err := service.Login(
				ctx,
				tt.login,
				tt.password,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf(
						"expected error %v, got %v",
						tt.wantErr,
						err,
					)
				}

				if got != nil {
					t.Errorf(
						"expected nil result, got %+v",
						got,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got == nil {
				t.Fatal("expected LoginResult, got nil")
			}

			if got.AccessToken == "" {
				t.Error("expected non-empty access token")
			}

			expectedExpiresIn := int64(time.Hour.Seconds())

			if got.ExpiresIn != expectedExpiresIn {
				t.Errorf(
					"ExpiresIn = %d, want %d",
					got.ExpiresIn,
					expectedExpiresIn,
				)
			}

			jwt := auth.NewJWT("test-secret", time.Hour)

			gotUserID, err := jwt.ValidateToken(
				got.AccessToken,
			)
			if err != nil {
				t.Fatalf(
					"generated token is invalid: %v",
					err,
				)
			}

			if gotUserID != userID.String() {
				t.Errorf(
					"token subject = %q, want %q",
					gotUserID,
					userID.String(),
				)
			}
		})
	}
}

func TestAuthService_Login_DoesNotCallRepositoryOnInvalidCredentials(t *testing.T) {
	tests := []struct {
		name     string
		login    string
		password string
	}{
		{
			name:     "empty login",
			login:    "",
			password: "password",
		},
		{
			name:     "empty password",
			login:    "user",
			password: "",
		},
		{
			name:     "both empty",
			login:    "",
			password: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockUserRepo(t)
			service := newTestAuthService(repo)

			_, err := service.Login(
				context.Background(),
				tt.login,
				tt.password,
			)

			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf(
					"expected ErrInvalidCredentials, got %v",
					err,
				)
			}
		})
	}
}

func TestAuthService_Login_WrapsRepositoryError(t *testing.T) {
	repoErr := errors.New("database unavailable")

	repo := mocks.NewMockUserRepo(t)

	repo.EXPECT().
		GetByLogin(
			mock.Anything,
			"user",
		).
		Return(nil, repoErr)

	service := newTestAuthService(repo)

	_, err := service.Login(
		context.Background(),
		"user",
		"password",
	)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, repoErr) {
		t.Errorf(
			"expected wrapped repository error %v, got %v",
			repoErr,
			err,
		)
	}
}
