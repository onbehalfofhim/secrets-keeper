package grpc

import (
	"errors"
	"io"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BinaryServer struct {
	pb.UnimplementedBinaryServiceServer

	service *service.BinaryService
}

func NewBinaryServer(service *service.BinaryService) *BinaryServer {
	return &BinaryServer{
		service: service,
	}
}

func (s *BinaryServer) UploadBinary(stream pb.BinaryService_UploadBinaryServer) error {
	ctx := stream.Context()

	ownerID, err := getUserID(ctx)
	if err != nil {
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
			return status.Error(
				codes.InvalidArgument,
				"secret id is required",
			)
		}

		currentSecretID, err := uuid.Parse(
			req.GetSecretId(),
		)
		if err != nil {
			return status.Error(
				codes.InvalidArgument,
				"invalid secret id",
			)
		}

		// Первый chunk определяет secret ID.
		if secretID == uuid.Nil {
			secretID = currentSecretID
		} else if secretID != currentSecretID {
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
	if err := s.service.Upload(
		ctx,
		ownerID,
		secretID,
		data,
	); err != nil {
		return mapBinaryError(err)
	}

	return stream.SendAndClose(
		&pb.UploadBinaryResponse{},
	)
}

func (s *BinaryServer) DownloadBinary(req *pb.DownloadBinaryRequest, stream pb.BinaryService_DownloadBinaryServer) error {
	ctx := stream.Context()

	ownerID, err := getUserID(ctx)
	if err != nil {
		return err
	}

	secretID, err := uuid.Parse(
		req.GetSecretId(),
	)
	if err != nil {
		return status.Error(
			codes.InvalidArgument,
			"invalid secret id",
		)
	}

	data, err := s.service.Download(
		ctx,
		ownerID,
		secretID,
	)
	if err != nil {
		return mapBinaryError(err)
	}

	const chunkSize = 32 * 1024

	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize

		if end > len(data) {
			end = len(data)
		}

		err := stream.Send(
			&pb.DownloadBinaryChunk{
				Chunk: data[offset:end],
			},
		)
		if err != nil {
			return status.Errorf(
				codes.Internal,
				"send binary chunk: %v",
				err,
			)
		}
	}

	return nil
}

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
