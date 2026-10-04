//go:build windows

package agent

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
)

// dial connects to a Windows named pipe (\\.\pipe\...). COMPILE-CHECKED ONLY:
// no native Windows host was available for this prototype.
func dial(ctx context.Context, path string) (net.Conn, error) {
	if !strings.HasPrefix(strings.ToLower(path), `\\.\pipe\`) {
		return nil, errors.New("agent path is not a named pipe")
	}
	return winio.DialPipeContext(ctx, path)
}
