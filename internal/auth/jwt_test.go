package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewJWT(t *testing.T) {
	secret := "test-secret"
	ttl := time.Hour

	j := NewJWT(secret, ttl)

	if j == nil {
		t.Fatal("expected JWT, got nil")
	}

	if string(j.secret) != secret {
		t.Errorf(
			"secret = %q, want %q",
			string(j.secret),
			secret,
		)
	}

	if j.ttl != ttl {
		t.Errorf(
			"ttl = %v, want %v",
			j.ttl,
			ttl,
		)
	}
}

func TestJWT_GenerateToken(t *testing.T) {
	const (
		secret = "test-secret"
		userID = "user-123"
	)

	ttl := time.Hour
	j := NewJWT(secret, ttl)

	token, expiresIn, err := j.GenerateToken(userID)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}

	expectedExpiresIn := int64(ttl.Seconds())

	if expiresIn != expectedExpiresIn {
		t.Errorf(
			"expiresIn = %d, want %d",
			expiresIn,
			expectedExpiresIn,
		)
	}

	claims := &Claims{}

	parsedToken, err := jwt.ParseWithClaims(
		token,
		claims,
		func(token *jwt.Token) (any, error) {
			return []byte(secret), nil
		},
	)

	if err != nil {
		t.Fatalf("failed to parse generated token: %v", err)
	}

	if !parsedToken.Valid {
		t.Fatal("generated token is invalid")
	}

	if claims.Subject != userID {
		t.Errorf(
			"subject = %q, want %q",
			claims.Subject,
			userID,
		)
	}

	if claims.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt claim")
	}

	if claims.IssuedAt == nil {
		t.Fatal("expected IssuedAt claim")
	}

	if !claims.ExpiresAt.After(claims.IssuedAt.Time) {
		t.Error("ExpiresAt should be after IssuedAt")
	}
}

func TestJWT_GenerateToken_ValidateToken(t *testing.T) {
	j := NewJWT("test-secret", time.Hour)

	userID := "user-123"

	token, _, err := j.GenerateToken(userID)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	gotUserID, err := j.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if gotUserID != userID {
		t.Errorf(
			"ValidateToken() userID = %q, want %q",
			gotUserID,
			userID,
		)
	}
}

func TestJWT_ValidateToken_InvalidToken(t *testing.T) {
	j := NewJWT("test-secret", time.Hour)

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "malformed token",
			token: "not-a-jwt",
		},
		{
			name:  "invalid jwt structure",
			token: "aaa.bbb.ccc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID, err := j.ValidateToken(tt.token)

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, ErrInvalidToken) {
				t.Errorf(
					"expected ErrInvalidToken, got %v",
					err,
				)
			}

			if userID != "" {
				t.Errorf(
					"expected empty userID, got %q",
					userID,
				)
			}
		})
	}
}

func TestJWT_ValidateToken_WrongSecret(t *testing.T) {
	j := NewJWT("correct-secret", time.Hour)
	wrongJWT := NewJWT("wrong-secret", time.Hour)

	token, _, err := j.GenerateToken("user-123")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	userID, err := wrongJWT.ValidateToken(token)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf(
			"expected ErrInvalidToken, got %v",
			err,
		)
	}

	if userID != "" {
		t.Errorf(
			"expected empty userID, got %q",
			userID,
		)
	}
}

func TestJWT_ValidateToken_ExpiredToken(t *testing.T) {
	j := NewJWT("test-secret", -time.Hour)

	token, _, err := j.GenerateToken("user-123")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	userID, err := j.ValidateToken(token)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf(
			"expected ErrInvalidToken, got %v",
			err,
		)
	}

	if userID != "" {
		t.Errorf(
			"expected empty userID, got %q",
			userID,
		)
	}
}

func TestJWT_ValidateToken_EmptySubject(t *testing.T) {
	j := NewJWT("test-secret", time.Hour)

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "",
				ExpiresAt: jwt.NewNumericDate(
					time.Now().Add(time.Hour),
				),
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
		},
	)

	tokenString, err := token.SignedString(j.secret)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	userID, err := j.ValidateToken(tokenString)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf(
			"expected ErrInvalidToken, got %v",
			err,
		)
	}

	if userID != "" {
		t.Errorf(
			"expected empty userID, got %q",
			userID,
		)
	}
}

func TestJWT_ValidateToken_WrongSigningMethod(t *testing.T) {
	j := NewJWT("test-secret", time.Hour)

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS384,
		Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "user-123",
				ExpiresAt: jwt.NewNumericDate(
					time.Now().Add(time.Hour),
				),
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
		},
	)

	tokenString, err := token.SignedString(j.secret)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	userID, err := j.ValidateToken(tokenString)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf(
			"expected ErrInvalidToken, got %v",
			err,
		)
	}

	if userID != "" {
		t.Errorf(
			"expected empty userID, got %q",
			userID,
		)
	}
}

func TestJWT_ValidateToken_TamperedToken(t *testing.T) {
	j := NewJWT("test-secret", time.Hour)

	token, _, err := j.GenerateToken("user-123")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	// Меняем payload токена.
	parts := make([]byte, len(token))
	copy(parts, token)

	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == '.' {
			continue
		}

		if parts[i] == 'a' {
			parts[i] = 'b'
		} else {
			parts[i] = 'a'
		}

		break
	}

	userID, err := j.ValidateToken(string(parts))

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf(
			"expected ErrInvalidToken, got %v",
			err,
		)
	}

	if userID != "" {
		t.Errorf(
			"expected empty userID, got %q",
			userID,
		)
	}
}

func TestJWT_GenerateToken_ZeroTTL(t *testing.T) {
	j := NewJWT("test-secret", 0)

	token, expiresIn, err := j.GenerateToken("user-123")

	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}

	if expiresIn != 0 {
		t.Errorf(
			"expiresIn = %d, want 0",
			expiresIn,
		)
	}

	_, err = j.ValidateToken(token)

	if err == nil {
		t.Fatal("expected token with zero TTL to be invalid")
	}

	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf(
			"expected ErrInvalidToken, got %v",
			err,
		)
	}
}
