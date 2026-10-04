package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const ioctlGetTermios = unix.TIOCGETA

// openPTY returns a (master, slave) pair using the macOS ptmx ioctls.
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
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		m.Close()
		return nil, nil, err
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		m.Close()
		return nil, nil, err
	}
	var name [128]byte
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&name[0]))); e != 0 {
		m.Close()
		return nil, nil, e
	}
	n := 0
	for n < len(name) && name[n] != 0 {
		n++
	}
	s, err := os.OpenFile(string(name[:n]), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}
