//go:build darwin || linux

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() { helperChildren["hp-child-sigrec"] = sigrecChild }

// sigrecChild is the helper child (this test binary, argv[1] ==
// "hp-child-sigrec"): it reports its identity, records every SIGINT,
// SIGTERM, SIGHUP, SIGQUIT and SIGWINCH it receives, one name per line, and
// exits 7 once the test writes the stop file.
func sigrecChild(dir string) {
	ch := make(chan os.Signal, 32)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGWINCH)
	put := func(name string, b []byte) {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p+".part", b, 0o600)
		_ = os.Rename(p+".part", p)
	}
	id, _ := json.Marshal(map[string]int{"pid": os.Getpid(), "ppid": os.Getppid(), "pgrp": unix.Getpgrp()})
	put("ready", id)
	var got []string
	tick := time.NewTicker(10 * time.Millisecond)
	end := time.Now().Add(30 * time.Second)
	for time.Now().Before(end) {
		select {
		case s := <-ch:
			got = append(got, unix.SignalName(s.(syscall.Signal)))
			put("signals", []byte(strings.Join(got, "\n")+"\n"))
		case <-tick.C:
			if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
				time.Sleep(50 * time.Millisecond)
				for len(ch) > 0 {
					got = append(got, unix.SignalName((<-ch).(syscall.Signal)))
				}
				put("signals", []byte(strings.Join(got, "\n")+"\n"))
				os.Exit(7)
			}
		}
	}
	os.Exit(9)
}

func readLines(p string) []string {
	b, err := os.ReadFile(p)
	if err != nil || len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func waitFile(p string, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if _, err := os.Stat(p); err == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// K6d (slice-contract §9.3): when heimdall-proto shares its process group
// with the terminal's foreground job (a child of a foreground non-job-control
// `sh -c`, or a member of a pipeline of such a script), a SIGINT, SIGTERM,
// SIGHUP, SIGQUIT or SIGWINCH sent explicitly to the heimdall-proto PID
// reaches the child at least once (duplicates allowed by K6b; loss fails).
// The shell is a session leader on a fresh pty, so its process group (which
// heimdall-proto shares) holds the terminal foreground. Round 2 forwarded
// SIGINT, SIGHUP, SIGQUIT and SIGWINCH only while that group was not in the
// foreground, so the child got nothing.
func TestK6dSharedModeExplicitSignals(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	layouts := map[string]string{
		"sh-c":           `"$P" run -- "$P" hp-child-sigrec "$D"; echo "RC=$?" > "$D/rc"`,
		"pipeline-first": `"$P" run -- "$P" hp-child-sigrec "$D" | cat; echo "RC=$?" > "$D/rc"`,
		"pipeline-last":  `while [ ! -e "$D/stop" ]; do sleep 0.05; done | "$P" run -- "$P" hp-child-sigrec "$D"; echo "RC=$?" > "$D/rc"`,
	}
	sigs := []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGWINCH}
	for name, script := range layouts {
		for _, sig := range sigs {
			tag := name + "/" + unix.SignalName(sig)
			d := t.TempDir()
			r := startPTY(t)
			cmd := exec.Command("/bin/sh", "-c", script)
			cmd.Env = []string{"HP_AS_MAIN=1", "PATH=/usr/bin:/bin", "P=" + self, "D=" + d}
			cmd.Stdin, cmd.Stdout, cmd.Stderr = r.slave, r.slave, r.slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			var id struct{ Pid, Ppid, Pgrp int }
			ok := waitFile(filepath.Join(d, "ready"), 10*time.Second)
			if ok {
				b, _ := os.ReadFile(filepath.Join(d, "ready"))
				_ = json.Unmarshal(b, &id)
			}
			fg := ttyForeground(r.master)
			shared := ok && id.Pgrp == cmd.Process.Pid && fg == cmd.Process.Pid
			if ok && id.Ppid > 1 {
				time.Sleep(100 * time.Millisecond)
				_ = unix.Kill(id.Ppid, sig) // explicit: heimdall-proto's PID, never the group
				end := time.Now().Add(3 * time.Second)
				for time.Now().Before(end) && len(readLines(filepath.Join(d, "signals"))) == 0 {
					time.Sleep(10 * time.Millisecond)
				}
				time.Sleep(300 * time.Millisecond) // late duplicates are counted too
			}
			_ = os.WriteFile(filepath.Join(d, "stop"), []byte("1"), 0o600)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill() // the shell this test started
				<-done
			}
			r.master.Close()
			r.slave.Close()
			got := readLines(filepath.Join(d, "signals"))
			rc := strings.TrimSpace(string(must(os.ReadFile(filepath.Join(d, "rc")))))
			want := unix.SignalName(sig)
			allSame := len(got) >= 1
			for _, g := range got {
				allSame = allSame && g == want
			}
			t.Logf("%-24s shared=%v child_got=%v heimdall_rc=%s", tag, shared, got, rc)
			if !shared {
				t.Errorf("%s: precondition: heimdall-proto's child is not in the shell's foreground group (ready=%v pgrp=%d sh=%d fg=%d)", tag, ok, id.Pgrp, cmd.Process.Pid, fg)
			}
			if !allSame {
				t.Errorf("%s: child received %v, want at least one %s and nothing else", tag, got, want)
			}
			if name != "pipeline-first" && rc != "RC=7" {
				t.Errorf("%s: heimdall-proto status %q, want RC=7 (the child's)", tag, rc)
			}
		}
	}
}

// ttyForeground is tcgetpgrp through the pty master (the test process has
// no controlling terminal, so the slave answers only on Linux). SyscallConn,
// not Fd(): Fd() would switch the master to blocking mode.
func ttyForeground(m *os.File) int {
	fg := -1
	if rc, err := m.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			if v, err := unix.IoctlGetInt(int(fd), unix.TIOCGPGRP); err == nil {
				fg = v
			}
		})
	}
	return fg
}

func must(b []byte, _ error) []byte { return b }
