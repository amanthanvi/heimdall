//go:build !windows

package agent

import (
	"context"
	"net"
)

// dial connects to a Unix-domain socket.
func dial(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}
