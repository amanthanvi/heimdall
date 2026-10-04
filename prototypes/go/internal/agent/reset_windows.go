//go:build windows

package agent

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// isReset reports a connection reset or a named-pipe server that went away
// (K3a "or equivalent"). COMPILE-CHECKED ONLY (no native Windows host).
// go-winio already maps ERROR_BROKEN_PIPE on read to io.EOF.
func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, windows.WSAECONNRESET) ||
		errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) ||
		errors.Is(err, windows.ERROR_NO_DATA)
}
