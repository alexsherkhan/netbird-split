package api

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

// ErrorDomain scopes structured split tunnel API error reasons.
const ErrorDomain = "splittunnel.netbird.io"

// Structured error reasons. Clients match on these instead of message text.
const (
	ReasonUnauthenticated    = "CALLER_IDENTITY_UNAVAILABLE"
	ReasonMutationDenied     = "MUTATION_DENIED"
	ReasonRevisionConflict   = "REVISION_CONFLICT"
	ReasonInvalidConfig      = "INVALID_CONFIG"
	ReasonInvalidRequest     = "INVALID_REQUEST"
	ReasonUnsupportedVersion = "UNSUPPORTED_API_VERSION"
	ReasonNotImplemented     = "NOT_IMPLEMENTED"
	ReasonBackendUnavailable = "BACKEND_UNAVAILABLE"
	ReasonRateLimited        = "RATE_LIMITED"
	ReasonInternal           = "INTERNAL"
)

func errorWithReason(code codes.Code, reason, message string, metadata map[string]string) error {
	base := status.New(code, message)
	withDetails, err := base.WithDetails(&errdetails.ErrorInfo{
		Reason:   reason,
		Domain:   ErrorDomain,
		Metadata: metadata,
	})
	if err != nil {
		return base.Err()
	}
	return withDetails.Err()
}

func notImplemented(operation string) error {
	return errorWithReason(codes.Unimplemented, ReasonNotImplemented,
		fmt.Sprintf("split tunnel %s is not implemented", operation), nil)
}

func invalidRequest(message string) error {
	return errorWithReason(codes.InvalidArgument, ReasonInvalidRequest, message, nil)
}

func invalidConfig(err error) error {
	metadata := map[string]string{}
	var fieldErr *config.FieldError
	if errors.As(err, &fieldErr) {
		metadata["field"] = fieldErr.Path
	}
	return errorWithReason(codes.InvalidArgument, ReasonInvalidConfig, err.Error(), metadata)
}

func revisionConflict() error {
	return errorWithReason(codes.Aborted, ReasonRevisionConflict,
		"split tunnel configuration revision is stale", nil)
}

func unsupportedVersion(requested uint32) error {
	return errorWithReason(codes.FailedPrecondition, ReasonUnsupportedVersion,
		fmt.Sprintf("split tunnel API version %d is not supported", requested),
		map[string]string{
			"requested": strconv.FormatUint(uint64(requested), 10),
			"supported": strconv.FormatUint(uint64(APIVersion), 10),
		})
}

// mapBackendError converts backend failures into the API's structured errors.
func mapBackendError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrNotImplemented):
		return errorWithReason(codes.Unimplemented, ReasonNotImplemented,
			"split tunnel operation is not implemented", nil)
	case errors.Is(err, ErrRevisionConflict):
		return revisionConflict()
	case errors.Is(err, ErrBackendUnavailable):
		return errorWithReason(codes.Unavailable, ReasonBackendUnavailable,
			"split tunnel backend is unavailable", nil)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	}

	if _, ok := status.FromError(err); ok {
		return err
	}

	var fieldErr *config.FieldError
	if errors.As(err, &fieldErr) {
		return invalidConfig(err)
	}
	return errorWithReason(codes.Internal, ReasonInternal, "split tunnel backend failed", nil)
}
