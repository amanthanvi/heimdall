//go:build darwin || linux

package main

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"golang.org/x/sys/unix"

	"github.com/heimdall-g02/proto-go/internal/profile"
	"github.com/heimdall-g02/proto-go/internal/tui"
)

// panicky wraps the real model and panics on '!' (test-only; the shipped
// binary has no panic trigger).
type panicky struct{ *tui.Model }

func (p panicky) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyPressMsg); ok && k.Text == "!" {
		panic("K10 test panic")
	}
	_, cmd := p.Model.Update(msg)
	return p, cmd
}

type ptyRun struct {
	master, slave *os.File
	before        *unix.Termios
	mu            sync.Mutex
	out           bytes.Buffer
	done          chan struct{}
}

func startPTY(t *testing.T) *ptyRun {
	t.Helper()
	m, s, err := openPTY()
	if err != nil {
		t.Fatalf("openpty: %v", err)
	}
	_ = unix.IoctlSetWinsize(int(s.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80})
	before, err := unix.IoctlGetTermios(int(s.Fd()), ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	r := &ptyRun{master: m, slave: s, before: before, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		buf := make([]byte, 4096)
		for {
			n, err := m.Read(buf)
			r.mu.Lock()
			r.out.Write(buf[:n])
			r.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return r
}

func (r *ptyRun) output() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.out.Bytes()...)
}

func newModel() *tui.Model {
	return tui.New([]profile.Destination{{ID: "d", Alias: "lab", Host: "h", Account: "u", Port: 22}}, true)
}

func teaOpts(r *ptyRun) []tea.ProgramOption {
	return []tea.ProgramOption{tea.WithOutput(r.slave),
		tea.WithEnvironment([]string{"TERM=xterm-256color", "NO_COLOR=1"})}
}

// K10 (slice-contract §9): an internal panic restores the terminal (alt
// screen left, cursor shown, termios identical) and exits 1 with no stdout.
func TestK10PanicRestoresAndExits1(t *testing.T) {
	r := startPTY(t)
	defer r.master.Close()
	defer r.slave.Close()
	m := newModel()
	go func() {
		time.Sleep(400 * time.Millisecond)
		_, _ = r.master.Write([]byte("!"))
	}()
	var stdout, stderr bytes.Buffer
	code := runTUI(panicky{m}, m, r.slave, &stdout, &stderr, teaOpts(r)...)
	time.Sleep(200 * time.Millisecond)
	after, err := unix.IoctlGetTermios(int(r.slave.Fd()), ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	out := r.output()
	enter := bytes.Index(out, []byte("\x1b[?1049h"))
	leave := bytes.LastIndex(out, []byte("\x1b[?1049l"))
	if code != 1 || stdout.Len() != 0 || enter < 0 || leave < enter ||
		!bytes.Contains(out[enter:], []byte("\x1b[?25h")) {
		t.Fatalf("exit=%d stdout=%q enter=%d leave=%d out=%q", code, stdout.String(), enter, leave, out)
	}
	if *after != *r.before {
		t.Fatal("termios not restored after panic")
	}
	if !strings.Contains(stderr.String(), "panic") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

// K10: SIGHUP restores the terminal and exits 129 with no stdout.
func TestK10SIGHUPRestoresAndExits129(t *testing.T) {
	r := startPTY(t)
	defer r.master.Close()
	defer r.slave.Close()
	m := newModel()
	go func() {
		time.Sleep(400 * time.Millisecond)
		_ = unix.Kill(os.Getpid(), unix.SIGHUP) // caught by runTUI's handler
	}()
	var stdout, stderr bytes.Buffer
	code := runTUI(m, m, r.slave, &stdout, &stderr, teaOpts(r)...)
	time.Sleep(200 * time.Millisecond)
	after, err := unix.IoctlGetTermios(int(r.slave.Fd()), ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	out := r.output()
	enter := bytes.Index(out, []byte("\x1b[?1049h"))
	leave := bytes.LastIndex(out, []byte("\x1b[?1049l"))
	if code != 129 || stdout.Len() != 0 || enter < 0 || leave < enter || *after != *r.before {
		t.Fatalf("exit=%d stdout=%q enter=%d leave=%d termios_same=%v", code, stdout.String(), enter, leave, *after == *r.before)
	}
}

// K10: terminal hangup without a signal (pty master closed; this test
// process has no controlling tty, so the kernel sends no SIGHUP). The tty
// read then fails with EIO (Linux) or returns EOF (macOS); hangupInput maps
// both to 129. The kernel-SIGHUP path is covered black-box in selftest.py
// (tui.k10_hangup_master_close_129).
func TestK10TerminalHangupNoSignalExits129(t *testing.T) {
	r := startPTY(t)
	defer r.slave.Close()
	m := newModel()
	go func() {
		time.Sleep(400 * time.Millisecond)
		_ = r.master.Close()
	}()
	var stdout, stderr bytes.Buffer
	res := make(chan int, 1)
	go func() { res <- runTUI(m, m, r.slave, &stdout, &stderr, teaOpts(r)...) }()
	select {
	case code := <-res:
		if code != 129 || stdout.Len() != 0 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tui did not exit after terminal hangup")
	}
}
