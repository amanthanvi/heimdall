//go:build linux

package daemon

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerPIDFromConn(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("peer pid: connection is not unix")
	}

	file, err := unixConn.File()
	if err != nil {
		return 0, fmt.Errorf("peer pid: unix socket file: %w", err)
	}
	defer file.Close()

	cred, err := unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("peer pid: getsockopt ucred: %w", err)
	}
	return int(cred.Pid), nil
}
