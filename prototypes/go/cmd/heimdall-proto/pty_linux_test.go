package main

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const ioctlGetTermios = unix.TCGETS

// openPTY returns a (master, slave) pair using /dev/ptmx.
func openPTY() (*os.File, *os.File, error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	// Use SyscallConn, not Fd(): Fd() switches the master to blocking mode,
	// and Close() of a blocking *os.File with a pending Read is deferred until
	// the Read returns, so the pty would never hang up.
	rc, err := m.SyscallConn()
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	var fd int
	_ = rc.Control(func(u uintptr) { fd = int(u) })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	s, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}
