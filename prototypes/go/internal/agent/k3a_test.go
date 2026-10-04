//go:build !windows

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// resetReader yields data and then fails with ECONNRESET, as Linux does for
// an AF_UNIX peer that closed with unread data in its receive queue.
type resetReader struct{ data []byte }

func (r *resetReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, &net.OpError{Op: "read", Net: "unix", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// K3a (slice-contract §9): a reset is classified like EOF in the same
// position. Deterministic on every platform.
func TestK3aResetClassificationReadFrame(t *testing.T) {
	if _, err := ReadFrame(&resetReader{}); !errors.Is(err, ErrNoResponse) || errors.Is(err, ErrProtocol) {
		t.Fatalf("reset before any byte: %v", err)
	}
	for _, partial := range [][]byte{{0}, {0, 0, 0}, {0, 0, 0, 100, 12, 0}} {
		if _, err := ReadFrame(&resetReader{data: partial}); !errors.Is(err, ErrProtocol) {
			t.Fatalf("reset after %x: %v", partial, err)
		}
	}
}

// resetAgent accepts one connection, peeks at (does not consume) the
// request, sends send, and closes. On Linux the unread request makes the
// kernel deliver ECONNRESET to the client after the sent bytes; Darwin
// delivers EOF instead (slice-contract §9.1 K13).
func resetAgent(t *testing.T, send []byte) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "hpa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			rc, _ := c.(*net.UnixConn).SyscallConn()
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				var n int
				_ = rc.Read(func(fd uintptr) bool {
					buf := make([]byte, 8)
					n, _, _ = syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
					return true
				})
				if n >= len(RequestIdentitiesFrame) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if len(send) > 0 {
				c.Write(send)
				time.Sleep(100 * time.Millisecond)
			}
			c.Close()
		}
	}()
	return path
}

// rawError performs the exchange without the probe and returns the read
// error that ended it, to show which kernel behavior the case exercised.
func rawError(t *testing.T, path string) error {
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(RequestIdentitiesFrame)
	_, err = io.ReadAll(c)
	if err == nil {
		err = io.EOF
	}
	return err
}

// K3a end to end through a real AF_UNIX socket. On Linux the test requires
// that the kernel really delivered ECONNRESET, so it cannot pass vacuously.
func TestK3aResetEndToEnd(t *testing.T) {
	cases := []struct {
		name string
		send []byte
		want Outcome
	}{
		{"before any byte", nil, OutcomeUnavailable},
		{"after 1 byte", []byte{0}, OutcomeProtocolError},
		{"after 3 header bytes", []byte{0, 0, 0}, OutcomeProtocolError},
		{"mid body", append(binary.BigEndian.AppendUint32(nil, 100), 12, 0), OutcomeProtocolError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := resetAgent(t, tc.send)
			raw := rawError(t, path)
			reset := errors.Is(raw, syscall.ECONNRESET)
			t.Logf("kernel delivered: %v (reset=%v)", raw, reset)
			if runtime.GOOS == "linux" && !reset {
				t.Fatalf("expected ECONNRESET from the Linux kernel, got %v", raw)
			}
			r := Probe(context.Background(), path, 2*time.Second)
			if r.Outcome != tc.want {
				t.Fatalf("got %+v want outcome %d", r, tc.want)
			}
			if bytes.Contains([]byte(r.Detail), []byte{0}) {
				t.Fatal("detail carries response bytes")
			}
		})
	}
}
