package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/amanthanvi/heimdall/internal/ssh"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

const (
	ExitCodeSuccess           = 0
	ExitCodeGeneric           = 1
	ExitCodeUsage             = 2
	ExitCodeNotFound          = 3
	ExitCodePermission        = 4
	ExitCodeAuthFailed        = 5
	ExitCodeDependencyMissing = 6
	ExitCodeIO                = 7
)

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *ExitError) ExitCode() int {
	if e == nil {
		return ExitCodeGeneric
	}
	return e.Code
}

func asExitError(code int, err error) error {
	if err == nil {
		return nil
	}
	var withExit interface{ ExitCode() int }
	if errors.As(err, &withExit) {
		return err
	}
	return &ExitError{Code: code, Err: err}
}

func mapCommandError(err error) error {
	if err == nil {
		return nil
	}
	var withExit interface{ ExitCode() int }
	if errors.As(err, &withExit) {
		return err
	}

	var pathErr *fs.PathError
	if errors.As(err, &pathErr) || errors.Is(err, os.ErrNotExist) {
		return asExitError(ExitCodeIO, err)
	}
	if errors.Is(err, ssh.ErrDependencyUnavailable) {
		return asExitError(ExitCodeDependencyMissing, err)
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "requires libfido2") ||
		strings.Contains(lower, "dependency unavailable") {
		return asExitError(ExitCodeDependencyMissing, err)
	}

	if st, ok := grpcstatus.FromError(err); ok {
		switch st.Code() {
		case codes.InvalidArgument:
			return asExitError(ExitCodeUsage, err)
		case codes.NotFound:
			return asExitError(ExitCodeNotFound, err)
		case codes.PermissionDenied:
			message := strings.ToLower(st.Message())
			if strings.Contains(message, "auth") || strings.Contains(message, "unlock") || strings.Contains(message, "reauth") {
				return asExitError(ExitCodeAuthFailed, err)
			}
			return asExitError(ExitCodePermission, err)
		case codes.Unauthenticated:
			return asExitError(ExitCodeAuthFailed, err)
		case codes.FailedPrecondition:
			if strings.Contains(strings.ToLower(st.Message()), "not configured") ||
				strings.Contains(strings.ToLower(st.Message()), "dependency") {
				return asExitError(ExitCodeDependencyMissing, err)
			}
			return asExitError(ExitCodePermission, err)
		default:
			return asExitError(ExitCodeGeneric, err)
		}
	}

	return asExitError(ExitCodeGeneric, err)
}

func usageErrorf(format string, args ...any) error {
	return &ExitError{
		Code: ExitCodeUsage,
		Err:  fmt.Errorf(format, args...),
	}
}
