//go:build !windows

package main

import (
	"os"
	"syscall"
)

// openMeta opens the --meta-file for writing without blocking: open(2) of a
// FIFO that has no reader fails (ENXIO) instead of waiting forever. For a
// FIFO or pipe with a reader, blocking mode is restored before the write.
func openMeta(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	rc, err := f.SyscallConn()
	if err == nil {
		_ = rc.Control(func(fd uintptr) { _ = syscall.SetNonblock(int(fd), false) })
	}
	return f, nil
}
