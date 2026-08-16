package grpc

import (
	"errors"
	"io"
	"log/slog"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BinaryServer реализует gRPC API для загрузки
// и скачивания бинарных данных секретов.
type BinaryServer struct {
	pb.UnimplementedBinaryServiceServer

	service *service.BinaryService
	logger  *slog.Logger
}

// NewBinaryServer создаёт gRPC-сервер для работы
// с бинарными данными секретов.
func NewBinaryServer(service *service.BinaryService, logger *slog.Logger) *BinaryServer {
	return &BinaryServer{
		service: service,
		logger:  logger,
	}
}

// UploadBinary принимает бинарный файл через client-streaming RPC.
//
// Клиент передаёт файл несколькими chunks. Все chunks должны
// содержать один и тот же идентификатор секрета.
//
// После получения всех chunks данные передаются в BinaryService
// для сохранения.
func (s *BinaryServer) UploadBinary(stream pb.BinaryService_UploadBinaryServer) error {
	ctx := stream.Context()

	ownerID, err := getUserID(ctx)
	if err != nil {
		s.logger.Info("upload binary: authentication failed", "error", err)

		return err
	}

	var (
		secretID uuid.UUID
		data     []byte
	)

	for {
		req, err := stream.Recv()

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return status.Errorf(
				codes.Internal,
				"receive binary chunk: %v",
				err,
			)
		}

		// Получаем secret ID
		if req.GetSecretId() == "" {
			s.logger.Info("binary upload: secret id is empty", "ownerId", ownerID)

			return status.Error(
				codes.InvalidArgument,
				"secret id is required",
			)
		}

		currentSecretID, err := uuid.Parse(
			req.GetSecretId(),
		)
		if err != nil {
			s.logger.Info("binary upload: invalid secret id", "ownerId", ownerID, "secretId", req.GetSecretId(), "error", err)

			return status.Error(
				codes.InvalidArgument,
				"invalid secret id",
			)
		}

		// Первый chunk определяет secret ID.
		if secretID == uuid.Nil {
			secretID = currentSecretID
		} else if secretID != currentSecretID {
			s.logger.Info(
				"binary upload: secret id changed between chunks",
				"ownerId", ownerID,
				"secretId", secretID,
				"receivedSecretId", currentSecretID,
			)

			return status.Error(
				codes.InvalidArgument,
				"secret id must be the same for all chunks",
			)
		}

		// Получаем данные
		chunk := req.GetChunk()

		if len(chunk) == 0 {
			continue
		}

		data = append(data, chunk...)
	}

	// Проверяем stream
	if secretID == uuid.Nil {
		return status.Error(
			codes.InvalidArgument,
			"upload stream is empty",
		)
	}

	// Передаем файл в service
	if err := s.service.Upload(ctx, ownerID, secretID, data); err != nil {
		s.logger.Error(
			"binary upload failed",
			"ownerId", ownerID,
			"secretId", secretID,
			"error", err,
		)

		return mapBinaryError(err)
	}

	s.logger.Info("binary uploaded", "ownerId", ownerID, "secretId", secretID)

	return stream.SendAndClose(
		&pb.UploadBinaryResponse{},
	)
}

// DownloadBinary получает бинарный файл и передаёт его клиенту
// через server-streaming RPC.
//
// Файл отправляется клиенту последовательностью chunks фиксированного
// размера. Доступ к файлу проверяется с учётом владельца секрета.
func (s *BinaryServer) DownloadBinary(req *pb.DownloadBinaryRequest, stream pb.BinaryService_DownloadBinaryServer) error {
	ctx := stream.Context()

	ownerID, err := getUserID(ctx)
	if err != nil {
		s.logger.Info("download binary: authentication failed", "error", err)

		return err
	}

	secretID, err := uuid.Parse(
		req.GetSecretId(),
	)
	if err != nil {
		s.logger.Info("binary download: invalid secret id", "ownerId", ownerID, "secretId", req.GetSecretId(), "error", err)

		return status.Error(
			codes.InvalidArgument,
			"invalid secret id",
		)
	}

	data, err := s.service.Download(ctx, ownerID, secretID)
	if err != nil {
		s.logger.Error(
			"binary download failed",
			"ownerId", ownerID,
			"secretId", secretID,
			"error", err,
		)

		return mapBinaryError(err)
	}

	const chunkSize = 32 * 1024

	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize

		if end > len(data) {
			end = len(data)
		}

		err := stream.Send(
			pb.DownloadBinaryChunk_builder{
				Chunk: data[offset:end],
			}.Build(),
		)
		if err != nil {
			return status.Errorf(
				codes.Internal,
				"send binary chunk: %v",
				err,
			)
		}
	}

	s.logger.Info("binary downloaded", "ownerId", ownerID, "secretId", secretID)

	return nil
}

// mapBinaryError преобразует внутренние ошибки бинарного сервиса
// в соответствующие gRPC-коды.
//
// Ошибки отсутствующего секрета или файла преобразуются в NotFound,
// ошибки некорректного типа секрета — в InvalidArgument.
// Неизвестные ошибки преобразуются в Internal.
func mapBinaryError(err error) error {
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
			"invalid binary secret",
		)

	case errors.Is(err, service.ErrBinaryNotUploaded):
		return status.Error(
			codes.NotFound,
			"binary file not found",
		)

	default:
		return status.Error(
			codes.Internal,
			"internal server error",
		)
	}
}
