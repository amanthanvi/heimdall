//go:build darwin || linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/heimdall-g02/proto-go/internal/testfix"
)

// closedStdoutStatus runs this test binary as heimdall-proto (HP_AS_MAIN=1)
// with stdout the write end of a pipe whose read end is already closed, so
// the first stdout write fails at once (EPIPE, or SIGPIPE at its default
// disposition). It returns the wait status as "exit N" or "signal NAME".
func closedStdoutStatus(t *testing.T, args ...string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "HP_AS_MAIN=1")
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = 10 * time.Second
	err = cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("%v: %v", args, err)
	}
	ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if ws.Signaled() {
		return "signal " + ws.Signal().String()
	}
	return fmt.Sprintf("exit %d", ws.ExitStatus())
}

// K12 closed stdout (slice-contract §9.4, Q17): with stdout a pipe whose
// reader has gone, the wait status is the same with and without --json, for
// success and error results alike. Error results keep their contract exit
// code (2 or 5) in both modes: a --json error must neither die of SIGPIPE nor
// turn the lost write into another code.
func TestK12ClosedStdoutExitParity(t *testing.T) {
	fix := testfix.Dir(t)
	d := t.TempDir()
	cases := []struct {
		label string
		args  []string
		want  string // "" = parity only (status not specified)
	}{
		{"version", []string{"version"}, ""},
		{"profile-show-homelab", []string{"profile", "show", "--file", filepath.Join(fix, "homelab.toml")}, ""},
		{"profile-missing", []string{"profile", "show", "--file", filepath.Join(d, "missing.toml")}, "exit 2"},
		{"profile-schema-invalid", []string{"profile", "show", "--file", filepath.Join(fix, "invalid-forbidden-key.toml")}, "exit 2"},
		{"agent-unavailable", []string{"agent", "list", "--socket", filepath.Join(d, "none.sock")}, "exit 5"},
		{"usage-unknown-flag", []string{"version", "--no-such-flag"}, "exit 2"},
	}
	for _, c := range cases {
		plain := closedStdoutStatus(t, c.args...)
		js := closedStdoutStatus(t, append(append([]string{}, c.args...), "--json")...)
		if plain != js {
			t.Errorf("[%s] closed stdout: plain %q, --json %q (must be equal)", c.label, plain, js)
		}
		if c.want != "" && (plain != c.want || js != c.want) {
			t.Errorf("[%s] closed stdout: plain %q, --json %q, want %q for both", c.label, plain, js, c.want)
		}
		t.Logf("[%s] plain=%s json=%s", c.label, plain, js)
	}
}
