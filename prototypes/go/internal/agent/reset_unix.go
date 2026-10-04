//go:build !windows

package agent

import (
	"errors"
	"syscall"
)

// isReset reports a connection reset by the peer (K3a).
func isReset(err error) bool { return errors.Is(err, syscall.ECONNRESET) }
