package serializer

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/onbehalfofhim/secrets-keeper/internal/models"
)

func TestNewJSONSerializer(t *testing.T) {
	serializer := NewJSONSerializer()

	if serializer == nil {
		t.Fatal("expected serializer, got nil")
	}
}

func TestJSONSerializer_Serialize(t *testing.T) {
	serializer := NewJSONSerializer()

	tests := []struct {
		name string
		data any
		want string
	}{
		{
			name: "text secret",
			data: &models.TextSecret{
				// Заполни поля, если в твоей модели они обязательны.
			},
			want: `{"text":""}`,
		},
		{
			name: "login password secret",
			data: &models.LoginPasswordSecret{
				// Заполни поля, если в твоей модели они обязательны.
			},
			want: `{"login":"","password":""}`,
		},
		{
			name: "card secret",
			data: &models.CardSecret{
				// Заполни поля, если в твоей модели они обязательны.
			},
			want: `{"number":"","holder":"","expire":"","cvv":""}`,
		},
		{
			name: "text secret with data",
			data: &models.TextSecret{
				Text: "hello",
			},
			want: `{"text":"hello"}`,
		},
		{
			name: "login password secret with data",
			data: &models.LoginPasswordSecret{
				Login:    "user",
				Password: "password",
			},
			want: `{"login":"user","password":"password"}`,
		},
		{
			name: "card secret with data",
			data: &models.CardSecret{
				Number: "1234",
				Holder: "John Doe",
				Expire: "12/30",
				CVV:    "123",
			},
			want: `{"number":"1234","holder":"John Doe","expire":"12/30","cvv":"123"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := serializer.Serialize(tt.data)

			if err != nil {
				t.Fatalf("Serialize() error = %v", err)
			}

			if string(got) != tt.want {
				t.Errorf(
					"Serialize() = %q, want %q",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestJSONSerializer_Serialize_InvalidData(t *testing.T) {
	serializer := NewJSONSerializer()

	tests := []struct {
		name string
		data any
	}{
		{
			name: "nil",
			data: nil,
		},
		{
			name: "string",
			data: "secret",
		},
		{
			name: "bytes",
			data: []byte("secret"),
		},
		{
			name: "binary secret",
			data: &models.BinarySecret{},
		},
		{
			name: "struct",
			data: struct {
				Value string
			}{
				Value: "secret",
			},
		},
		{
			name: "map",
			data: map[string]string{
				"key": "value",
			},
		},
		{
			name: "integer",
			data: 123,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := serializer.Serialize(tt.data)

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, ErrInvalidSecretData) {
				t.Errorf(
					"expected ErrInvalidSecretData, got %v",
					err,
				)
			}

			if got != nil {
				t.Errorf(
					"expected nil result, got %s",
					got,
				)
			}
		})
	}
}

func TestJSONSerializer_Deserialize(t *testing.T) {
	serializer := NewJSONSerializer()

	tests := []struct {
		name       string
		secretType models.SecretType
		data       string
		wantType   any
	}{
		{
			name:       "text secret",
			secretType: models.SecretText,
			data:       `{}`,
			wantType:   &models.TextSecret{},
		},
		{
			name:       "login password secret",
			secretType: models.SecretLogin,
			data:       `{}`,
			wantType:   &models.LoginPasswordSecret{},
		},
		{
			name:       "card secret",
			secretType: models.SecretCard,
			data:       `{}`,
			wantType:   &models.CardSecret{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := serializer.Deserialize(
				tt.secretType,
				[]byte(tt.data),
			)

			if err != nil {
				t.Fatalf("Deserialize() error = %v", err)
			}

			switch tt.wantType.(type) {
			case *models.TextSecret:
				if _, ok := got.(*models.TextSecret); !ok {
					t.Fatalf(
						"expected *models.TextSecret, got %T",
						got,
					)
				}

			case *models.LoginPasswordSecret:
				if _, ok := got.(*models.LoginPasswordSecret); !ok {
					t.Fatalf(
						"expected *models.LoginPasswordSecret, got %T",
						got,
					)
				}

			case *models.CardSecret:
				if _, ok := got.(*models.CardSecret); !ok {
					t.Fatalf(
						"expected *models.CardSecret, got %T",
						got,
					)
				}
			}
		})
	}
}

func TestJSONSerializer_Deserialize_Values(t *testing.T) {
	serializer := NewJSONSerializer()

	tests := []struct {
		name       string
		secretType models.SecretType
		data       string
		check      func(t *testing.T, result any)
	}{
		{
			name:       "text secret",
			secretType: models.SecretText,
			data:       `{"text":"my secret"}`,
			check: func(t *testing.T, result any) {
				secret, ok := result.(*models.TextSecret)
				if !ok {
					t.Fatalf(
						"expected *models.TextSecret, got %T",
						result,
					)
				}

				// Если поле называется иначе, замени здесь.
				if secret.Text != "my secret" {
					t.Errorf(
						"Text = %q, want %q",
						secret.Text,
						"my secret",
					)
				}
			},
		},
		{
			name:       "login password secret",
			secretType: models.SecretLogin,
			data:       `{"login":"user","password":"pass"}`,
			check: func(t *testing.T, result any) {
				secret, ok := result.(*models.LoginPasswordSecret)
				if !ok {
					t.Fatalf(
						"expected *models.LoginPasswordSecret, got %T",
						result,
					)
				}

				if secret.Login != "user" {
					t.Errorf(
						"Login = %q, want %q",
						secret.Login,
						"user",
					)
				}

				if secret.Password != "pass" {
					t.Errorf(
						"Password = %q, want %q",
						secret.Password,
						"pass",
					)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := serializer.Deserialize(
				tt.secretType,
				[]byte(tt.data),
			)

			if err != nil {
				t.Fatalf("Deserialize() error = %v", err)
			}

			tt.check(t, got)
		})
	}
}

func TestJSONSerializer_Deserialize_BinarySecret(t *testing.T) {
	serializer := NewJSONSerializer()

	got, err := serializer.Deserialize(
		models.SecretBinary,
		[]byte(`{"data":"secret"}`),
	)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrUnsupportedSecretType) {
		t.Errorf(
			"expected ErrUnsupportedSecretType, got %v",
			err,
		)
	}

	if got != nil {
		t.Errorf("expected nil result, got %v", got)
	}
}

func TestJSONSerializer_Deserialize_UnsupportedType(t *testing.T) {
	serializer := NewJSONSerializer()

	tests := []models.SecretType{
		"",
		"unknown",
		"unsupported",
	}

	for _, secretType := range tests {
		t.Run(string(secretType), func(t *testing.T) {
			got, err := serializer.Deserialize(
				secretType,
				[]byte(`{}`),
			)

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, ErrUnsupportedSecretType) {
				t.Errorf(
					"expected ErrUnsupportedSecretType, got %v",
					err,
				)
			}

			if got != nil {
				t.Errorf(
					"expected nil result, got %v",
					got,
				)
			}
		})
	}
}

func TestJSONSerializer_Deserialize_InvalidJSON(t *testing.T) {
	serializer := NewJSONSerializer()

	tests := []struct {
		name       string
		secretType models.SecretType
		data       string
	}{
		{
			name:       "invalid json",
			secretType: models.SecretText,
			data:       `{invalid`,
		},
		{
			name:       "incomplete json",
			secretType: models.SecretLogin,
			data:       `{"login":`,
		},
		{
			name:       "invalid json string",
			secretType: models.SecretCard,
			data:       `"invalid`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := serializer.Deserialize(
				tt.secretType,
				[]byte(tt.data),
			)

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if got != nil {
				t.Errorf(
					"expected nil result, got %v",
					got,
				)
			}

			if err.Error() == "" {
				t.Error("expected non-empty error")
			}
		})
	}
}

func TestIsSupportedData(t *testing.T) {
	tests := []struct {
		name string
		data any
		want bool
	}{
		{
			name: "text secret pointer",
			data: &models.TextSecret{},
			want: true,
		},
		{
			name: "login password secret pointer",
			data: &models.LoginPasswordSecret{},
			want: true,
		},
		{
			name: "card secret pointer",
			data: &models.CardSecret{},
			want: true,
		},
		{
			name: "nil",
			data: nil,
			want: false,
		},
		{
			name: "text secret value",
			data: models.TextSecret{},
			want: false,
		},
		{
			name: "login password secret value",
			data: models.LoginPasswordSecret{},
			want: false,
		},
		{
			name: "card secret value",
			data: models.CardSecret{},
			want: false,
		},
		{
			name: "binary secret",
			data: &models.BinarySecret{},
			want: false,
		},
		{
			name: "string",
			data: "secret",
			want: false,
		},
		{
			name: "bytes",
			data: []byte("secret"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSupportedData(tt.data)

			if got != tt.want {
				t.Errorf(
					"isSupportedData(%T) = %v, want %v",
					tt.data,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestJSONSerializer_Serialize_ProducesValidJSON(t *testing.T) {
	serializer := NewJSONSerializer()

	data := &models.TextSecret{}

	got, err := serializer.Serialize(data)
	if err != nil {
		t.Fatalf("Serialize() error = %v", err)
	}

	var decoded any

	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf(
			"Serialize() returned invalid JSON: %v",
			err,
		)
	}
}
