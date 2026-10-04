//go:build darwin || linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/heimdall-g02/proto-go/internal/testfix"
)

// terminfoCrash is a 50-byte terminfo entry found by the round-2 reviewer's
// fuzzer (tests/evidence/artifacts/g02-go/review2/probes/terminfo-crash.bin):
// xo/terminfo's decoder panics on it with "slice bounds out of range".
var terminfoCrash = "\x1a\x01 \x000\x9d0\xc40\xf5" + strings.Repeat("0", 33) + "\x00" + strings.Repeat("0", 6)

// tuiEnvRun is one TUI process (this test binary as heimdall-proto) in a
// fresh pty session with a controlled environment.
type tuiEnvRun struct {
	code     int // exit status; -1 if killed by the watchdog
	drew     bool
	firstMs  float64
	peakMiB  float64
	killed   string
	stderrOK bool
}

func runTUIEnv(t *testing.T, env []string) tuiEnvRun {
	t.Helper()
	r := startPTY(t)
	defer r.master.Close()
	cmd := exec.Command(os.Args[0], "tui", "--file", filepath.Join(testfix.Dir(t), "homelab.toml"))
	cmd.Env = append([]string{"HP_AS_MAIN=1"}, env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = r.slave, r.slave, r.slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r.slave.Close()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	res := tuiEnvRun{code: -1}
	quitSent := false
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
loop:
	for {
		select {
		case <-done:
			break loop
		case <-tick.C:
			if m := rssMiB(cmd.Process.Pid); m > res.peakMiB {
				res.peakMiB = m
			}
			if !res.drew && bytes.Contains(r.output(), []byte("\x1b[?1049h")) {
				res.drew, res.firstMs = true, float64(time.Since(start).Microseconds())/1000
			}
			if res.drew && !quitSent && time.Since(start) > 300*time.Millisecond {
				_, _ = r.master.Write([]byte("q"))
				quitSent = true
			}
			if res.peakMiB > watchRSSMiB {
				res.killed = "rss"
			} else if time.Since(start) > watchTime {
				res.killed = "time"
			}
			if res.killed != "" {
				_ = cmd.Process.Kill() // exactly the child this test started
				<-done
				break loop
			}
		}
	}
	if res.killed == "" {
		res.code = cmd.ProcessState.ExitCode()
	}
	res.stderrOK = !bytes.Contains(r.output(), []byte("goroutine "))
	return res
}

// The TUI must not read terminfo files chosen by the environment without
// bounds: a TERM that walks out of the terminfo directory to /dev/zero, a FIFO
// named after TERM, and a malformed (fuzzer-found) entry must neither grow
// memory without bound, hang before the first frame, nor panic. Round 2
// (colorprofile.Detect -> xo/terminfo.Load): /dev/zero grew to many GiB, the
// FIFO hung, the malformed entry exited 2 with a Go panic before Run.
func TestTUIEnvironmentSelectedTerminfo(t *testing.T) {
	dir := t.TempDir()
	ti := filepath.Join(dir, "ti")
	if err := os.MkdirAll(filepath.Join(ti, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if len(terminfoCrash) != 50 {
		t.Fatalf("crash entry is %d bytes, want 50", len(terminfoCrash))
	}
	if err := os.WriteFile(filepath.Join(ti, "x", "xterm-hmcrash"), []byte(terminfoCrash), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(ti, "x", "xterm-hmfifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	// USER: without a passwd entry for the uid (a container user), a
	// cgo-less os/user.Current fails unless USER is set, and xo/terminfo
	// then gave up before reading anything; with USER set the round-2 read
	// happens in every environment.
	base := []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "USER=hp-test"}
	cases := map[string][]string{
		"TERM path traversal to /dev/zero": {"TERM=" + strings.Repeat("../", 12) + "dev/zero"},
		"TERMINFO FIFO named after TERM":   {"TERM=xterm-hmfifo", "TERMINFO=" + ti},
		"TERMINFO_DIRS FIFO":               {"TERM=xterm-hmfifo", "TERMINFO_DIRS=" + ti},
		"malformed terminfo entry":         {"TERM=xterm-hmcrash", "TERMINFO=" + ti},
		"control: TERM=xterm-256color":     {"TERM=xterm-256color"},
	}
	for name, extra := range cases {
		res := runTUIEnv(t, append(append([]string(nil), base...), extra...))
		t.Logf("%-34s exit=%d drew=%v first=%.1fms peak=%.1fMiB killed=%q", name, res.code, res.drew, res.firstMs, res.peakMiB, res.killed)
		if res.killed != "" || !res.drew || res.code != 0 || res.peakMiB >= 256 || !res.stderrOK {
			t.Errorf("%s: exit=%d drew=%v peak=%.1f MiB killed=%q no_panic_trace=%v", name, res.code, res.drew, res.peakMiB, res.killed, res.stderrOK)
		}
	}
}

// K10: a panic before tea.Program.Run (here injected through the test-only
// hook; in round 2 the malformed terminfo entry did this) exits 1, writes
// nothing to stdout, and leaves termios unchanged. Run as a separate process
// because an unrecovered panic ends the whole process.
func TestK10PanicBeforeRunExits1(t *testing.T) {
	r := startPTY(t)
	defer r.master.Close()
	stdoutFile := filepath.Join(t.TempDir(), "stdout")
	so, err := os.Create(stdoutFile)
	if err != nil {
		t.Fatal(err)
	}
	defer so.Close()
	// stdin is the pty; stdout must be a terminal too, so the panic happens
	// on the TUI path: stdout is the pty and the K10 "no stdout" part is
	// judged on the text after the program started (nothing but stderr).
	cmd := exec.Command(os.Args[0], "tui", "--file", filepath.Join(testfix.Dir(t), "homelab.toml"))
	cmd.Env = []string{"HP_AS_MAIN=1", "HP_TEST_PANIC_BEFORE_RUN=1", "PATH=/usr/bin:/bin", "TERM=xterm-256color"}
	var stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = r.slave, r.slave, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatal(err)
		}
	}
	code := cmd.ProcessState.ExitCode()
	time.Sleep(100 * time.Millisecond)
	after, terr := unix.IoctlGetTermios(int(r.master.Fd()), ioctlGetTermios)
	out := r.output()
	t.Logf("exit=%d stderr=%q tty_output=%q", code, stderr.String(), out)
	if code != 1 || len(out) != 0 || !strings.Contains(stderr.String(), "internal error (panic)") ||
		strings.Contains(stderr.String(), "goroutine ") {
		t.Fatalf("exit=%d (want 1) tty_output=%q stderr=%q", code, out, stderr.String())
	}
	if terr == nil && *after != *r.before {
		t.Fatal("termios changed")
	}
}
