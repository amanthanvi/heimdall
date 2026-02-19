//go:build !unix

package daemon

import (
	"fmt"
	"net"
)

func peerPIDFromConn(_ net.Conn) (int, error) {
	return 0, fmt.Errorf("peer pid: unsupported platform")
}
