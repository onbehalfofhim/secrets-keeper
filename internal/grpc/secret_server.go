package grpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type SecretServer struct {
	pb.UnimplementedSecretServiceServer

	service *service.SecretService
}

func NewSecretServer(service *service.SecretService) *SecretServer {
	return &SecretServer{
		service: service,
	}
}

func getUserID(ctx context.Context) (uuid.UUID, error) {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
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

func (s *SecretServer) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.CreateSecretResponse, error) {
	ownerID, err := getUserID(ctx)
	if err != nil {
		return nil, err
	}

	secret := req.GetSecret()
	if secret == nil {
		return nil, status.Error(
			codes.InvalidArgument,
			"secret is required",
		)
	}

	input, err := protoToCreateSecretInput(secret)
	if err != nil {
		return nil, err
	}

	result, err := s.service.Create(ctx, ownerID, input)
	if err != nil {
		return nil, mapSecretError(err)
	}

	return &pb.CreateSecretResponse{
		Id: result.ID.String(),
	}, nil
}

func protoToCreateSecretInput(secret *pb.Secret) (service.CreateSecretInput, error) {
	var (
		secretType models.SecretType
		data       any
	)

	switch payload := secret.GetPayload().(type) {
	case *pb.Secret_Text:
		secretType = models.SecretText

		data = &models.TextSecret{
			Text: payload.Text.GetText(),
		}

	case *pb.Secret_LoginPassword:
		secretType = models.SecretLogin

		data = &models.LoginPasswordSecret{
			Login:    payload.LoginPassword.GetLogin(),
			Password: payload.LoginPassword.GetPassword(),
		}

	case *pb.Secret_BankCard:
		secretType = models.SecretCard

		data = &models.CardSecret{
			Number: payload.BankCard.GetNumber(),
			Holder: payload.BankCard.GetHolder(),
			Expire: payload.BankCard.GetExpire(),
			CVV:    payload.BankCard.GetCvv(),
		}

	case *pb.Secret_Binary:
		secretType = models.SecretBinary
		binarySecret := &models.BinarySecret{
			Filename: payload.Binary.GetFilename(),
			MIMEType: payload.Binary.GetMimeType(),
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

type secretMetadata struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

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

func (s *SecretServer) UpdateSecret(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.UpdateSecretResponse, error) {
	ownerID, err := getUserID(ctx)
	if err != nil {
		return nil, err
	}

	secret := req.GetSecret()
	if secret == nil {
		return nil, status.Error(
			codes.InvalidArgument,
			"secret is required",
		)
	}

	metadata := secret.GetMetadata()
	if metadata == nil {
		return nil, status.Error(
			codes.InvalidArgument,
			"secret metadata is required",
		)
	}

	secretID, err := uuid.Parse(metadata.GetId())
	if err != nil {
		return nil, status.Error(
			codes.InvalidArgument,
			"invalid secret id",
		)
	}

	input, err := protoToUpdateSecretInput(secretID, secret)
	if err != nil {
		return nil, err
	}

	_, err = s.service.Update(ctx, ownerID, input)
	if err != nil {
		return nil, mapSecretError(err)
	}

	return &pb.UpdateSecretResponse{}, nil
}

func protoToUpdateSecretInput(secretID uuid.UUID, secret *pb.Secret) (service.UpdateSecretInput, error) {
	var (
		secretType models.SecretType
		data       any
	)

	switch payload := secret.GetPayload().(type) {
	case *pb.Secret_Text:
		secretType = models.SecretText

		data = &models.TextSecret{
			Text: payload.Text.GetText(),
		}

	case *pb.Secret_LoginPassword:
		secretType = models.SecretLogin

		data = &models.LoginPasswordSecret{
			Login:    payload.LoginPassword.GetLogin(),
			Password: payload.LoginPassword.GetPassword(),
		}

	case *pb.Secret_BankCard:
		secretType = models.SecretCard

		data = &models.CardSecret{
			Number: payload.BankCard.GetNumber(),
			Holder: payload.BankCard.GetHolder(),
			Expire: payload.BankCard.GetExpire(),
			CVV:    payload.BankCard.GetCvv(),
		}

	case *pb.Secret_Binary:
		secretType = models.SecretBinary

		data = &models.BinarySecret{
			Filename: payload.Binary.GetFilename(),
			MIMEType: payload.Binary.GetMimeType(),
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

func (s *SecretServer) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	ownerID, err := getUserID(ctx)
	if err != nil {
		return nil, err
	}

	secretID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(
			codes.InvalidArgument,
			"invalid secret id",
		)
	}

	secret, data, err := s.service.Get(ctx, ownerID, secretID)
	if err != nil {
		return nil, mapSecretError(err)
	}

	result, err := domainToProtoSecret(secret, data)
	if err != nil {
		return nil, err
	}

	return &pb.GetSecretResponse{
		Secret: result,
	}, nil
}

func domainToProtoSecret(secret *models.Secret, data any) (*pb.Secret, error) {
	result := &pb.Secret{
		Metadata: domainMetadataToProto(secret),
	}

	switch value := data.(type) {
	case *models.TextSecret:
		result.Payload = &pb.Secret_Text{
			Text: &pb.TextSecret{
				Text: value.Text,
			},
		}

	case *models.LoginPasswordSecret:
		result.Payload = &pb.Secret_LoginPassword{
			LoginPassword: &pb.LoginPasswordSecret{
				Login:    value.Login,
				Password: value.Password,
			},
		}

	case *models.CardSecret:
		result.Payload = &pb.Secret_BankCard{
			BankCard: &pb.BankCardSecret{
				Number: value.Number,
				Holder: value.Holder,
				Expire: value.Expire,
				Cvv:    value.CVV,
			},
		}

	case *models.BinarySecret:
		result.Payload = &pb.Secret_Binary{
			Binary: &pb.BinarySecret{
				Filename: value.Filename,
				MimeType: value.MIMEType,
			},
		}

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

func (s *SecretServer) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	ownerID, err := getUserID(ctx)
	if err != nil {
		return nil, err
	}

	secrets, err := s.service.List(ctx, ownerID)
	if err != nil {
		return nil, mapSecretError(err)
	}

	response := &pb.ListSecretsResponse{
		Secrets: make([]*pb.SecretMetadata, 0, len(secrets)),
	}

	for _, secret := range secrets {
		response.Secrets = append(
			response.Secrets,
			domainMetadataToProto(secret),
		)
	}

	return response, nil
}

func (s *SecretServer) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	ownerID, err := getUserID(ctx)
	if err != nil {
		return nil, err
	}

	secretID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(
			codes.InvalidArgument,
			"invalid secret id",
		)
	}

	err = s.service.Delete(ctx, ownerID, secretID)
	if err != nil {
		return nil, mapSecretError(err)
	}

	return &pb.DeleteSecretResponse{}, nil
}

func domainMetadataToProto(secret *models.Secret) *pb.SecretMetadata {
	return &pb.SecretMetadata{
		Id:        secret.ID.String(),
		Type:      secretTypeToProto(secret.Type),
		CreatedAt: timestamppb.New(secret.CreatedAt),
		UpdatedAt: timestamppb.New(secret.UpdatedAt),
	}
}

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

	// default:
	// 	return status.Error(
	// 		codes.Internal,
	// 		"internal server error",
	// 	)
	default:

		return status.Errorf(
			codes.Internal,
			"internal server error: %v",
			err,
		)
	}
}
