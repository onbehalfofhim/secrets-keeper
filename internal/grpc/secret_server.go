package grpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SecretServer реализует gRPC API для создания,
// получения, изменения, просмотра и удаления секретов.
type SecretServer struct {
	pb.UnimplementedSecretServiceServer

	service *service.SecretService
	logger  *slog.Logger
}

// NewSecretServer создаёт gRPC-сервер для работы с секретами.
func NewSecretServer(service *service.SecretService, logger *slog.Logger) *SecretServer {
	return &SecretServer{
		service: service,
		logger:  logger,
	}
}

// getUserID извлекает ID аутентифицированного пользователя
// из context текущего gRPC-запроса.
func getUserID(ctx context.Context) (uuid.UUID, error) {
	userID, err := UserIDFromContext(ctx)
	if err != nil {
		return uuid.Nil, status.Error(
			codes.Unauthenticated,
			"authentication required",
		)
	}

	id, err := uuid.Parse(userID)
	if err != nil {
		return uuid.Nil, status.Error(
			codes.Unauthenticated,
			"invalid user identity",
		)
	}

	return id, nil
}

// CreateSecret создаёт новый секрет для текущего пользователя.
//
// Тип и данные секрета преобразуются из protobuf-модели
// во внутреннюю модель сервиса.
// Для бинарного секрета на этом этапе сохраняются только metadata;
// содержимое файла загружается через BinaryService.
func (s *SecretServer) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.CreateSecretResponse, error) {
	ownerID, err := getUserID(ctx)
	if err != nil {
		s.logger.Info("create secret: authentication failed", "error", err)

		return nil, fmt.Errorf("create secret: authentication failed: %w", err)
	}

	secret := req.GetSecret()
	if secret == nil {
		s.logger.Info("create secret: request is empty", "ownerId", ownerID)

		return nil, status.Error(
			codes.InvalidArgument,
			"secret is required",
		)
	}

	input, err := protoToCreateSecretInput(secret)
	if err != nil {
		s.logger.Info("create secret: invalid request", "ownerId", ownerID, "error", err)

		return nil, fmt.Errorf("create secret: invalid request: %w", err)
	}

	result, err := s.service.Create(ctx, ownerID, input)
	if err != nil {
		s.logger.Error("create secret failed", "ownerId", ownerID, "type", input.Type, "error", err)

		return nil, mapSecretError(err)
	}

	s.logger.Info("secret created", "ownerId", ownerID, "secretId", result.ID, "type", result.Type)

	return pb.CreateSecretResponse_builder{
		Id: result.ID.String(),
	}.Build(), nil
}

// protoToCreateSecretInput преобразует protobuf-секрет
// во внутреннюю модель, используемую SecretService.
//
// Для бинарного секрета формируются metadata с именем файла
// и MIME-типом. Содержимое бинарного файла передаётся
// отдельным UploadBinary RPC.
func protoToCreateSecretInput(secret *pb.Secret) (service.CreateSecretInput, error) {
	var (
		secretType models.SecretType
		data       any
	)

	switch secret.WhichPayload() {
	case pb.Secret_Text_case:
		secretType = models.SecretText

		data = &models.TextSecret{
			Text: secret.GetText().GetText(),
		}

	case pb.Secret_LoginPassword_case:
		secretType = models.SecretLogin

		data = &models.LoginPasswordSecret{
			Login:    secret.GetLoginPassword().GetLogin(),
			Password: secret.GetLoginPassword().GetPassword(),
		}

	case pb.Secret_BankCard_case:
		secretType = models.SecretCard

		data = &models.CardSecret{
			Number: secret.GetBankCard().GetNumber(),
			Holder: secret.GetBankCard().GetHolder(),
			Expire: secret.GetBankCard().GetExpire(),
			CVV:    secret.GetBankCard().GetCvv(),
		}

	case pb.Secret_Binary_case:
		secretType = models.SecretBinary
		binarySecret := &models.BinarySecret{
			Filename: secret.GetBinary().GetFilename(),
			MIMEType: secret.GetBinary().GetMimeType(),
		}

		metadata, err := json.Marshal(binarySecret)
		if err != nil {
			return service.CreateSecretInput{}, status.Errorf(
				codes.InvalidArgument,
				"marshal binary metadata: %v",
				err,
			)
		}

		return service.CreateSecretInput{
			Type:     models.SecretBinary,
			Data:     binarySecret,
			Metadata: metadata,
		}, nil

	default:
		return service.CreateSecretInput{}, status.Error(
			codes.InvalidArgument,
			"secret payload is required",
		)
	}

	metadata, err := protoMetadataToJSON(secret.GetMetadata())
	if err != nil {
		return service.CreateSecretInput{}, status.Errorf(
			codes.InvalidArgument,
			"invalid metadata: %v",
			err,
		)
	}

	return service.CreateSecretInput{
		Type:     secretType,
		Data:     data,
		Metadata: metadata,
	}, nil
}

// secretMetadata представляет metadata секрета
// во внутреннем JSON-формате.
type secretMetadata struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

// protoMetadataToJSON преобразует protobuf metadata
// во внутреннее JSON-представление.
//
// Если metadata отсутствует, возвращается пустой JSON-объект.
func protoMetadataToJSON(metadata *pb.SecretMetadata) (json.RawMessage, error) {
	if metadata == nil {
		return json.RawMessage(`{}`), nil
	}

	value := secretMetadata{
		Title:       metadata.GetTitle(),
		Description: metadata.GetDescription(),
	}

	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}

	return data, nil
}

// UpdateSecret обновляет существующий секрет.
//
// ID секрета берётся из metadata запроса.
// Доступ к секрету дополнительно проверяется на уровне сервиса
// с использованием ID текущего пользователя.
func (s *SecretServer) UpdateSecret(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.UpdateSecretResponse, error) {
	ownerID, err := getUserID(ctx)
	if err != nil {
		s.logger.Info("update secret: authentication failed", "error", err)

		return nil, fmt.Errorf("update secret: authentication failed: %w", err)
	}

	secret := req.GetSecret()
	if secret == nil {
		s.logger.Info("update secret: request is empty", "ownerId", ownerID)

		return nil, status.Error(
			codes.InvalidArgument,
			"secret is required",
		)
	}

	metadata := secret.GetMetadata()
	if metadata == nil {
		s.logger.Info("update secret: metadata is empty", "ownerId", ownerID)

		return nil, status.Error(
			codes.InvalidArgument,
			"secret metadata is required",
		)
	}

	secretID, err := uuid.Parse(metadata.GetId())
	if err != nil {
		s.logger.Info("update secret: invalid secret id", "ownerId", ownerID, "secretId", metadata.GetId(), "error", err)

		return nil, status.Error(
			codes.InvalidArgument,
			"invalid secret id",
		)
	}

	input, err := protoToUpdateSecretInput(secretID, secret)
	if err != nil {
		s.logger.Info("update secret: invalid request", "ownerId", ownerID, "secretId", secretID, "error", err)

		return nil, fmt.Errorf("update secret: invalid request: %w", err)
	}

	_, err = s.service.Update(ctx, ownerID, input)
	if err != nil {
		s.logger.Error("update secret failed", "ownerId", ownerID, "secretId", secretID, "type", input.Type, "error", err)

		return nil, mapSecretError(err)
	}

	s.logger.Info("secret updated", "ownerId", ownerID, "secretId", secretID, "type", input.Type)

	return pb.UpdateSecretResponse_builder{}.Build(), nil
}

// protoToUpdateSecretInput преобразует protobuf-секрет
// во внутреннюю модель для обновления секрета.
func protoToUpdateSecretInput(secretID uuid.UUID, secret *pb.Secret) (service.UpdateSecretInput, error) {
	var (
		secretType models.SecretType
		data       any
	)

	switch secret.WhichPayload() {
	case pb.Secret_Text_case:
		secretType = models.SecretText

		data = &models.TextSecret{
			Text: secret.GetText().GetText(),
		}

	case pb.Secret_LoginPassword_case:
		secretType = models.SecretLogin

		data = &models.LoginPasswordSecret{
			Login:    secret.GetLoginPassword().GetLogin(),
			Password: secret.GetLoginPassword().GetPassword(),
		}

	case pb.Secret_BankCard_case:
		secretType = models.SecretCard

		data = &models.CardSecret{
			Number: secret.GetBankCard().GetNumber(),
			Holder: secret.GetBankCard().GetHolder(),
			Expire: secret.GetBankCard().GetExpire(),
			CVV:    secret.GetBankCard().GetCvv(),
		}

	case pb.Secret_Binary_case:
		secretType = models.SecretBinary

		data = &models.BinarySecret{
			Filename: secret.GetBinary().GetFilename(),
			MIMEType: secret.GetBinary().GetMimeType(),
		}

	default:
		return service.UpdateSecretInput{}, status.Error(
			codes.InvalidArgument,
			"secret payload is required",
		)
	}

	metadata, err := protoMetadataToJSON(secret.GetMetadata())
	if err != nil {
		return service.UpdateSecretInput{}, status.Errorf(
			codes.InvalidArgument,
			"invalid metadata: %v",
			err,
		)
	}

	return service.UpdateSecretInput{
		ID:       secretID,
		Type:     secretType,
		Data:     data,
		Metadata: metadata,
	}, nil
}

// GetSecret возвращает секрет текущего пользователя.
//
// Для обычных секретов возвращаются расшифрованные данные.
// Для бинарных секретов возвращаются только metadata;
// содержимое файла получается через BinaryService.
func (s *SecretServer) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	ownerID, err := getUserID(ctx)
	if err != nil {
		s.logger.Info("get secret: authentication failed", "error", err)

		return nil, fmt.Errorf("get secret: authentication failed: %w", err)
	}

	secretID, err := uuid.Parse(req.GetId())
	if err != nil {
		s.logger.Info("get secret: invalid secret id", "ownerId", ownerID, "secretId", req.GetId(), "error", err)

		return nil, status.Error(
			codes.InvalidArgument,
			"invalid secret id",
		)
	}

	secret, data, err := s.service.Get(ctx, ownerID, secretID)
	if err != nil {
		s.logger.Error("get secret failed", "ownerId", ownerID, "secretId", secretID, "error", err)

		return nil, mapSecretError(err)
	}

	result, err := domainToProtoSecret(secret, data)
	if err != nil {
		s.logger.Error("convert secret to proto failed", "ownerId", ownerID, "secretId", secretID, "error", err)

		return nil, fmt.Errorf("convert secret to proto failed: %w", err)
	}

	s.logger.Info("secret retrieved", "ownerId", ownerID, "secretId", secretID, "type", secret.Type)

	return pb.GetSecretResponse_builder{
		Secret: result,
	}.Build(), nil
}

// domainToProtoSecret преобразует внутреннюю модель секрета
// в protobuf-представление.
//
// Бинарные данные не передаются через SecretService.
// Для их получения используется BinaryService.DownloadBinary.
func domainToProtoSecret(secret *models.Secret, data any) (*pb.Secret, error) {
	result := pb.Secret_builder{
		Metadata: domainMetadataToProto(secret),
	}.Build()

	switch value := data.(type) {
	case *models.TextSecret:
		result.SetText(pb.TextSecret_builder{
			Text: value.Text,
		}.Build())

	case *models.LoginPasswordSecret:
		result.SetLoginPassword(pb.LoginPasswordSecret_builder{
			Login:    value.Login,
			Password: value.Password,
		}.Build())

	case *models.CardSecret:
		result.SetBankCard(pb.BankCardSecret_builder{
			Number: value.Number,
			Holder: value.Holder,
			Expire: value.Expire,
			Cvv:    value.CVV,
		}.Build())

	case *models.BinarySecret:
		result.SetBinary(pb.BinarySecret_builder{
			Filename: value.Filename,
			MimeType: value.MIMEType,
		}.Build())

	case []byte:
		// Для binary data сейчас ничего не возвращаем через GetSecret.
		// Содержимое файла будет получать BinaryService.DownloadBinary.
		return nil, status.Error(
			codes.Internal,
			"binary data must be downloaded through BinaryService",
		)

	default:
		return nil, status.Error(
			codes.Internal,
			"unsupported secret payload",
		)
	}

	return result, nil
}

// ListSecrets возвращает список секретов текущего пользователя.
//
// В ответе передаются только metadata секретов,
// без расшифрованных данных.
func (s *SecretServer) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	ownerID, err := getUserID(ctx)
	if err != nil {
		s.logger.Info("list secrets: authentication failed", "error", err)

		return nil, fmt.Errorf("list secrets: authentication failed: %w", err)
	}

	secrets, err := s.service.List(ctx, ownerID)
	if err != nil {
		s.logger.Error("list secrets failed", "ownerId", ownerID, "error", err)

		return nil, mapSecretError(err)
	}

	response := pb.ListSecretsResponse_builder{
		Secrets: make([]*pb.SecretMetadata, 0, len(secrets)),
	}.Build()

	for _, secret := range secrets {
		response.SetSecrets(append(
			response.GetSecrets(),
			domainMetadataToProto(secret),
		))
	}

	s.logger.Info("secrets listed", "ownerId", ownerID, "count", len(secrets))

	return response, nil
}

// DeleteSecret удаляет секрет текущего пользователя.
func (s *SecretServer) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	ownerID, err := getUserID(ctx)
	if err != nil {
		s.logger.Info("delete secret: authentication failed", "error", err)
		return nil, fmt.Errorf("delete secret: authentication failed: %w", err)
	}

	secretID, err := uuid.Parse(req.GetId())
	if err != nil {
		s.logger.Info("delete secret: invalid secret id", "ownerId", ownerID, "secretId", req.GetId(), "error", err)

		return nil, status.Error(
			codes.InvalidArgument,
			"invalid secret id",
		)
	}

	err = s.service.Delete(ctx, ownerID, secretID)
	if err != nil {
		s.logger.Error("delete secret failed", "ownerId", ownerID, "secretId", secretID, "error", err)

		return nil, mapSecretError(err)
	}

	s.logger.Info("secret deleted", "ownerId", ownerID, "secretId", secretID)

	return pb.DeleteSecretResponse_builder{}.Build(), nil
}

// domainMetadataToProto преобразует metadata секрета
// из внутренней модели в protobuf.
func domainMetadataToProto(secret *models.Secret) *pb.SecretMetadata {
	return pb.SecretMetadata_builder{
		Id:        secret.ID.String(),
		Type:      secretTypeToProto(secret.Type),
		CreatedAt: timestamppb.New(secret.CreatedAt),
		UpdatedAt: timestamppb.New(secret.UpdatedAt),
	}.Build()
}

// secretTypeToProto преобразует внутренний тип секрета
// в соответствующий protobuf enum.
func secretTypeToProto(secretType models.SecretType) pb.SecretType {
	switch secretType {
	case models.SecretText:
		return pb.SecretType_SECRET_TYPE_TEXT

	case models.SecretLogin:
		return pb.SecretType_SECRET_TYPE_LOGIN_PASSWORD

	case models.SecretCard:
		return pb.SecretType_SECRET_TYPE_BANK_CARD

	case models.SecretBinary:
		return pb.SecretType_SECRET_TYPE_BINARY_FILE

	default:
		return pb.SecretType_SECRET_TYPE_UNSPECIFIED
	}
}

// mapSecretError преобразует внутренние ошибки работы с секретами
// в соответствующие gRPC-коды.
//
// Ошибка отсутствующего секрета преобразуется в NotFound.
// Ошибки валидации преобразуются в InvalidArgument.
// Остальные ошибки скрываются от клиента и возвращаются как Internal.
func mapSecretError(err error) error {
	switch {
	case errors.Is(err, repository.ErrSecretNotFound):
		return status.Error(
			codes.NotFound,
			"secret not found",
		)

	case errors.Is(err, service.ErrInvalidSecret),
		errors.Is(err, service.ErrInvalidSecretType):
		return status.Error(
			codes.InvalidArgument,
			"invalid secret",
		)

	default:
		return status.Error(
			codes.Internal,
			"internal server error",
		)
	}
}
