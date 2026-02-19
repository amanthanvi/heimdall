package ssh

import (
	"errors"
	"fmt"
)

const ExitCodeDependencyUnavailable = 6

var (
	ErrDependencyUnavailable = errors.New("ssh: dependency unavailable")
)

type ExitError struct {
	Code    int
	Message string
	Err     error
}

func (e *ExitError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return e.Message
	}
	if e.Message == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Message, e.Err)
}

func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *ExitError) ExitCode() int {
	if e == nil {
		return 0
	}
	return e.Code
}

func IsExitCode(err error, code int) bool {
	var exitErr interface{ ExitCode() int }
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode() == code
	}
	return false
}
