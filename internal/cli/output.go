package cli

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FormatGRPCError преобразует gRPC error
// в понятное сообщение для CLI.
func FormatGRPCError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, ErrTokenNotFound) {
		return errors.New(
			"authentication required: please login first",
		)
	}

	code := status.Code(err)
	message := status.Convert(err).Message()

	switch code {
	case codes.InvalidArgument:
		return fmt.Errorf(
			"invalid argument: %s",
			message,
		)

	case codes.Unauthenticated:
		return errors.New(
			"authentication failed",
		)

	case codes.PermissionDenied:
		return errors.New(
			"permission denied",
		)

	case codes.NotFound:
		return errors.New(
			"resource not found",
		)

	case codes.AlreadyExists:
		return errors.New(
			"resource already exists",
		)

	case codes.FailedPrecondition:
		return fmt.Errorf(
			"operation failed: %s",
			message,
		)

	case codes.Unavailable:
		return errors.New(
			"server is unavailable",
		)

	case codes.DeadlineExceeded:
		return errors.New(
			"request timed out",
		)

	default:
		return errors.New(
			"internal server error",
		)
	}
}
