//go:build darwin || linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

// K16 (slice-contract §9.1): apart from the `run` child, heimdall-proto never
// executes another program, whatever TMUX, TERM or TERM_PROGRAM say. Fake
// tmux/tput/infocmp/stty first on PATH record any execution. The program
// output is a real pty, so terminal capability detection is live.
func TestK16TUINoHelperProcesses(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "EXECUTED")
	bin := filepath.Join(dir, "fakebin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tmux", "tput", "infocmp", "stty", "screen"} {
		script := "#!/bin/sh\necho \"" + name + " $*\" >> '" + marker + "'\necho 'Tc: (flag) true'\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TMUX", "/tmp/hp-fake-tmux,1,0")
	t.Setenv("TERM", "tmux-256color")
	t.Setenv("TERM_PROGRAM", "tmux")
	t.Setenv("NO_COLOR", "")
	t.Setenv("COLORTERM", "")

	r := startPTY(t)
	defer r.master.Close()
	defer r.slave.Close()
	m := newModel()
	go func() {
		time.Sleep(500 * time.Millisecond)
		_, _ = r.master.Write([]byte("q"))
	}()
	var stdout, stderr bytes.Buffer
	res := make(chan int, 1)
	go func() { res <- runTUI(m, m, r.slave, &stdout, &stderr, tea.WithOutput(r.slave)) }()
	select {
	case code := <-res:
		if code != 0 {
			t.Fatalf("exit=%d stderr=%q", code, stderr.String())
		}
	case <-time.After(8 * time.Second):
		t.Fatal("tui did not exit")
	}
	if !bytes.Contains(r.output(), []byte("\x1b[?1049h")) {
		t.Fatal("tui never drew")
	}
	if b, err := os.ReadFile(marker); err == nil {
		t.Fatalf("heimdall-proto executed helper programs: %q", b)
	}
}
