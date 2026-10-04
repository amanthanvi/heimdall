//go:build !windows

package profile

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/heimdall-g02/proto-go/internal/result"
)

// K14 (slice-contract §9.1): a --file that is not a regular file is exit 2
// USAGE_ERROR within 2 s, and Load never blocks waiting on it.
func TestK14NonRegularFiles(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "hpk14")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	fifo := filepath.Join(dir, "fifo ü.toml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "sock.toml")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	link := filepath.Join(dir, "link-to-fifo.toml")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"fifo": fifo, "symlink to fifo": link, "unix socket": sock, "directory": dir, "char device": "/dev/null",
	} {
		done := make(chan *Error, 1)
		start := time.Now()
		go func() { _, e := Load(path); done <- e }()
		select {
		case e := <-done:
			if e == nil || e.Code != result.UsageError {
				t.Errorf("%s: got %+v, want USAGE_ERROR", name, e)
			}
			if el := time.Since(start); el > 2*time.Second {
				t.Errorf("%s: took %v", name, el)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s: Load still blocked after 2 s", name)
		}
	}
	// A symlink to a regular file is still accepted.
	reg := filepath.Join(dir, "ok.toml")
	if err := os.WriteFile(reg, []byte("schema_version = 1\nname = \"x\"\nrevision = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rl := filepath.Join(dir, "ok-link.toml")
	if err := os.Symlink(reg, rl); err != nil {
		t.Fatal(err)
	}
	if _, e := Load(rl); e != nil {
		t.Fatalf("symlink to regular file: %+v", e)
	}
}
