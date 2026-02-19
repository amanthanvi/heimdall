package fido2

import (
	"errors"
	"fmt"
)

const (
	ExitCodeAuthFailed            = 5
	ExitCodeDependencyUnavailable = 6
)

var (
	ErrAuthFailed            = errors.New("fido2: authentication failed")
	ErrDependencyUnavailable = errors.New("fido2: dependency unavailable")
	ErrDuplicateLabel        = errors.New("fido2: duplicate passkey label")
	ErrHMACSecretUnsupported = errors.New("fido2: hmac-secret extension not supported")
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

func dependencyUnavailableError(command string) error {
	return &ExitError{
		Code:    ExitCodeDependencyUnavailable,
		Message: fmt.Sprintf("%s requires libfido2; install libfido2 or use passphrase unlock", command),
		Err:     ErrDependencyUnavailable,
	}
}

func authFailedError(message string, wrapped error) error {
	if message == "" {
		message = "passkey authentication failed"
	}
	if wrapped == nil {
		wrapped = ErrAuthFailed
	}
	return &ExitError{
		Code:    ExitCodeAuthFailed,
		Message: message,
		Err:     wrapped,
	}
}
