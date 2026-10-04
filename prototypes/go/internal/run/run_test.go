//go:build !windows

package run

import (
	"encoding/json"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Helper child mode: the test binary re-executes itself as the child.
func TestMain(m *testing.M) {
	switch os.Getenv("HP_HELPER") {
	case "":
		os.Exit(m.Run())
	case "argv":
		b, _ := json.Marshal(os.Args)
		_ = os.WriteFile(os.Getenv("HP_OUT"), b, 0o600)
		os.Exit(7)
	case "selfkill":
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		time.Sleep(time.Second)
	case "trap":
		// Count each forwarded signal; exit when SIGTERM arrives.
		ch := make(chan os.Signal, 8)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGWINCH)
		_ = os.WriteFile(os.Getenv("HP_OUT")+".pid", []byte(strconv.Itoa(os.Getpid())), 0o600)
		got := ""
		for s := range ch {
			got += strconv.Itoa(int(s.(syscall.Signal))) + ";"
			if s == syscall.SIGTERM {
				_ = os.WriteFile(os.Getenv("HP_OUT"), []byte(got), 0o600)
				os.Exit(3)
			}
		}
	}
	os.Exit(99)
}

func self(t *testing.T) string {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestArgvPassthroughAndExitCode(t *testing.T) {
	out := filepath.Join(t.TempDir(), "argv ü.json")
	t.Setenv("HP_HELPER", "argv")
	t.Setenv("HP_OUT", out)
	argv := []string{self(t), "a b", `q"uo'te`, "$HOME", "x;y", "*", "line1\nline2", "ünï 東京", "", `back\slash\`, "\xff\xfeinvalid"}
	st := Run(argv)
	if !st.Launched || st.ExitCode == nil || *st.ExitCode != 7 || st.Exit != 7 || st.Signal != nil {
		t.Fatalf("%+v", st)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	_ = json.Unmarshal(b, &got)
	if len(got) != len(argv) {
		t.Fatalf("argc %d want %d", len(got), len(argv))
	}
	for i := 1; i < len(argv); i++ {
		// JSON round-trip replaces invalid UTF-8; compare that arg separately.
		if i == len(argv)-1 {
			continue
		}
		if got[i] != argv[i] {
			t.Errorf("arg %d: %q want %q", i, got[i], argv[i])
		}
	}
}

func TestInvalidUTF8ArgBytes(t *testing.T) {
	// Byte-exact check without JSON: child writes its raw last arg.
	dir := t.TempDir()
	out := filepath.Join(dir, "raw")
	st := Run([]string{"/bin/sh", "-c", `printf '%s' "$1" > "$2"`, "sh", "\xff\xfe\x00"[:2] + "z", out})
	if st.Exit != 0 {
		t.Fatalf("%+v", st)
	}
	b, _ := os.ReadFile(out)
	if string(b) != "\xff\xfez" {
		t.Fatalf("%q", b)
	}
}

func TestSignalDeath(t *testing.T) {
	t.Setenv("HP_HELPER", "selfkill")
	st := Run([]string{self(t)})
	if !st.Launched || st.Signal == nil || *st.Signal != 9 || st.Exit != 137 || st.ExitCode != nil {
		t.Fatalf("%+v", st)
	}
}

func TestLaunchFailure(t *testing.T) {
	st := Run([]string{"heimdall-proto-definitely-missing-cmd"})
	if st.Launched || st.Exit != 127 {
		t.Fatalf("%+v", st)
	}
	f := filepath.Join(t.TempDir(), "notexec")
	_ = os.WriteFile(f, []byte("#!/bin/sh\n"), 0o600)
	st = Run([]string{f})
	if st.Launched || st.Exit != 127 {
		t.Fatalf("not executable: %+v", st)
	}
}

// Signals sent to heimdall-proto (this process) are forwarded exactly once,
// heimdall-proto outlives the child, and the child is reaped (no zombie).
func TestForwardSignalsAndReap(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sigs")
	t.Setenv("HP_HELPER", "trap")
	t.Setenv("HP_OUT", out)
	go func() {
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(out + ".pid"); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		me := os.Getpid()
		for _, s := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGWINCH} {
			_ = syscall.Kill(me, s)
			time.Sleep(50 * time.Millisecond)
		}
		_ = syscall.Kill(me, syscall.SIGTERM)
	}()
	st := Run([]string{self(t)})
	if st.Exit != 3 {
		t.Fatalf("%+v", st)
	}
	b, _ := os.ReadFile(out)
	want := ""
	for _, s := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGWINCH, syscall.SIGTERM} {
		want += strconv.Itoa(int(s)) + ";"
	}
	if string(b) != want {
		t.Fatalf("child saw %q", b)
	}
	pb, _ := os.ReadFile(out + ".pid")
	pid, _ := strconv.Atoi(string(pb))
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("child %d still exists (zombie?): %v", pid, err)
	}
}
