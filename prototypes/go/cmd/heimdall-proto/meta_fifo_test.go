//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A --meta-file that is a FIFO without a reader must not block run forever:
// the child's status is still returned and the lost side channel is
// reported on stderr. With a reader, the JSON result is delivered.
func TestRunMetaFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "meta fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	type res struct {
		code   int
		stderr string
	}
	runOnce := func() (res, bool) {
		ch := make(chan res, 1)
		go func() {
			var e bytes.Buffer
			c := cmdRun([]string{"--meta-file", fifo, "--", "sh", "-c", "exit 4"}, &e)
			ch <- res{c, e.String()}
		}()
		select {
		case r := <-ch:
			return r, true
		case <-time.After(3 * time.Second):
			return res{}, false
		}
	}
	r, ok := runOnce()
	if !ok {
		t.Fatal("run blocked on a --meta-file FIFO without a reader")
	}
	if r.code != 4 || !strings.Contains(r.stderr, "cannot write --meta-file") {
		t.Fatalf("no reader: %+v", r)
	}
	// With a reader.
	rd, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	r, ok = runOnce()
	if !ok || r.code != 4 || r.stderr != "" {
		t.Fatalf("with reader: ok=%v %+v", ok, r)
	}
	_ = syscall.SetNonblock(int(rd.Fd()), false)
	b, _ := io.ReadAll(io.LimitReader(rd, 4096))
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m["code"] != "CHILD_EXITED" {
		t.Fatalf("meta via FIFO: %q %v", b, err)
	}
}
