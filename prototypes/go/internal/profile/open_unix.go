//go:build !windows

package profile

import (
	"os"
	"syscall"
)

// openNoBlock opens read-only without blocking: O_NONBLOCK keeps open(2) of
// a FIFO without a writer from waiting (K14). It has no effect on reads of
// the regular file Load accepts.
func openNoBlock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
