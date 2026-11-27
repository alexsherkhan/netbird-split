package cli

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
)

// Exit codes returned by the split tunnel commands.
const (
	// ExitSuccess reports that the command completed.
	ExitSuccess = 0
	// ExitInternal reports an unexpected local or daemon failure.
	ExitInternal = 1
	// ExitUsage reports invalid arguments or an invalid configuration.
	ExitUsage = 2
	// ExitDenied reports an unauthenticated or unauthorized caller.
	ExitDenied = 3
	// ExitUnavailable reports that the daemon or split tunnel service is
	// unavailable or does not implement the operation.
	ExitUnavailable = 4
	// ExitRevisionConflict reports that the caller's configuration revision was
	// stale.
	ExitRevisionConflict = 5
)

// ExitError carries the process exit code for a command error.
type ExitError struct {
	// Code is the process exit code.
	Code int
	// Err is the underlying failure.
	Err error
}

// Error implements the error interface.
func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit code %d", e.Code)
	}
	return e.Err.Error()
}

// Unwrap returns the underlying failure.
func (e *ExitError) Unwrap() error {
	return e.Err
}

// WithExitCode wraps err with an exit code. An error that already carries a
// code is returned unchanged so the innermost classification wins.
func WithExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	var existing *ExitError
	if errors.As(err, &existing) {
		return err
	}
	return &ExitError{Code: code, Err: err}
}

// Usagef returns a usage or configuration error.
func Usagef(format string, args ...any) error {
	return WithExitCode(ExitUsage, fmt.Errorf(format, args...))
}

// Deniedf returns an authentication or authorization error.
func Deniedf(format string, args ...any) error {
	return WithExitCode(ExitDenied, fmt.Errorf(format, args...))
}

// Unavailablef returns a daemon or service availability error.
func Unavailablef(format string, args ...any) error {
	return WithExitCode(ExitUnavailable, fmt.Errorf(format, args...))
}

// Conflictf returns a configuration revision conflict.
func Conflictf(format string, args ...any) error {
	return WithExitCode(ExitRevisionConflict, fmt.Errorf(format, args...))
}

// Internalf returns an unexpected failure.
func Internalf(format string, args ...any) error {
	return WithExitCode(ExitInternal, fmt.Errorf(format, args...))
}

// ExitCode returns the process exit code for err. Errors without an explicit
// classification are internal failures.
func ExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	return ExitInternal
}

// ClassifyCommand maps an error returned by a split tunnel command to an
// ExitError. Explicit exit codes and gRPC statuses are preserved; any other
// error comes from cobra argument or flag parsing and is a usage error.
func ClassifyCommand(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return err
	}
	if _, ok := status.FromError(err); ok {
		return Classify(err)
	}
	return WithExitCode(ExitUsage, err)
}

// Classify maps a gRPC error to an ExitError. An already classified error is
// returned unchanged.
func Classify(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return err
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return WithExitCode(ExitUnavailable, err)
	}
	if errors.Is(err, context.Canceled) {
		return WithExitCode(ExitInternal, err)
	}

	st, ok := status.FromError(err)
	if !ok {
		return WithExitCode(ExitInternal, err)
	}
	return WithExitCode(codeForStatus(st), err)
}

func codeForStatus(st *status.Status) int {
	switch st.Code() {
	case codes.OK:
		return ExitSuccess
	case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound:
		return ExitUsage
	case codes.Unauthenticated, codes.PermissionDenied:
		return ExitDenied
	case codes.Unavailable, codes.Unimplemented, codes.DeadlineExceeded:
		return ExitUnavailable
	case codes.Aborted:
		if hasReason(st, api.ReasonRevisionConflict) {
			return ExitRevisionConflict
		}
		return ExitInternal
	default:
		return ExitInternal
	}
}

func hasReason(st *status.Status, reason string) bool {
	for _, detail := range st.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}
		if info.GetDomain() != api.ErrorDomain {
			continue
		}
		if info.GetReason() == reason {
			return true
		}
	}
	return false
}
