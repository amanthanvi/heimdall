//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	k15Time   = 2 * time.Second
	k15RSSMiB = 256
	// The watchdog stops the exact child it started well above the bound so a
	// failing (pre-fix) run cannot exhaust the machine.
	watchRSSMiB = 768
	watchTime   = 6 * time.Second
)

func rssMiB(pid int) float64 {
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
		if err != nil {
			return 0
		}
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "VmRSS:" {
				kb, _ := strconv.Atoi(f[1])
				return float64(kb) / 1024
			}
		}
		return 0
	}
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0
	}
	kb, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return float64(kb) / 1024
}

type k15Run struct {
	code    string
	elapsed time.Duration
	peakMiB float64
	killed  string
}

// profileShowProcess runs `profile show --file path --json` as a separate
// process (this test binary as heimdall-proto) under a watchdog.
func profileShowProcess(t *testing.T, path string) k15Run {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "profile", "show", "--file", path, "--json")
	cmd.Env = append(os.Environ(), "HP_AS_MAIN=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	r := k15Run{}
	go func() {
		defer close(done)
		_ = cmd.Wait()
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
loop:
	for {
		select {
		case <-done:
			break loop
		case <-tick.C:
			if m := rssMiB(cmd.Process.Pid); m > r.peakMiB {
				r.peakMiB = m
			}
			if r.peakMiB > watchRSSMiB {
				r.killed = "rss"
			} else if time.Since(start) > watchTime {
				r.killed = "time"
			}
			if r.killed != "" {
				cancel() // SIGKILL to exactly this child (exec.CommandContext)
				<-done
				break loop
			}
		}
	}
	r.elapsed = time.Since(start)
	if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok && ru != nil {
		m := float64(ru.Maxrss) / 1024 // Linux: KiB
		if runtime.GOOS == "darwin" {
			m = float64(ru.Maxrss) / (1024 * 1024) // Darwin: bytes
		}
		if m > r.peakMiB {
			r.peakMiB = m
		}
	}
	var env struct{ Code string }
	if json.Unmarshal(out.Bytes(), &env) == nil {
		r.code = env.Code
	}
	return r
}

// K15 (slice-contract §9.1): parsing any input up to 1 MiB, including deep
// nesting inside [meta], finishes within 2 s and below 256 MiB peak RSS, and
// is either accepted or rejected with SCHEMA_INVALID. The shapes include the
// ones that broke round 1 and worst cases just inside the guard's bounds.
func TestK15ParserResourceBound(t *testing.T) {
	head := "schema_version = 1\nname = \"x\"\nrevision = 1\n"
	meta := head + "[meta]\n"
	lines := func(n int, f func(i int) string) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(f(i))
		}
		return b.String()
	}
	fill := func(prefix, unit, suffix string) string { // repeat unit up to 1 MiB
		n := (1<<20 - len(prefix) - len(suffix)) / len(unit)
		return prefix + strings.Repeat(unit, n) + suffix
	}
	shapes := map[string]string{
		"inline nest depth 4000 (16 KB)": meta + "a = " + strings.Repeat("{b = ", 4000) + "1" + strings.Repeat("}", 4000) + "\n",
		"array of inline nest 1 MiB":     meta + "a = " + strings.Repeat("[{b = ", 87000) + "1" + strings.Repeat("}]", 87000) + "\n",
		"dotted keys depth 8, 1 MiB": meta + lines(39000, func(i int) string {
			return "k" + strconv.Itoa(i) + strings.Repeat(".a", 8) + " = 1\n"
		}),
		"long header components, many keys": head + "[meta." + strings.Repeat("h", 2000) + "." + strings.Repeat("i", 2000) + "]\n" +
			lines(39000, func(i int) string { return "k" + strconv.Itoa(i) + " = 1\n" }),
		"many keys 1 MiB":   meta + lines(90000, func(i int) string { return "k" + strconv.Itoa(i) + " = 1\n" }),
		"wide array 1 MiB":  fill(meta+"a = [", "1,", "]\n"),
		"long string 1 MiB": fill(meta+"a = \"", "x", "\"\n"),
		// Worst cases just inside the guard (accepted).
		"at limit: inline nest 30 x1049": meta + lines(1049, func(i int) string {
			return "k" + strconv.Itoa(i) + " = " + strings.Repeat("{b = ", 30) + "1" + strings.Repeat("}", 30) + "\n"
		}),
		"at limit: deep header 28000 keys": head + "[meta" + strings.Repeat(".a", 30) + "]\n" +
			lines(28000, func(i int) string { return "k" + strconv.Itoa(i) + " = 1\n" }),
		"at limit: 10000 destinations": head + lines(10000, func(i int) string {
			n := strconv.Itoa(i)
			return "[[destinations]]\nid = \"d" + n + "\"\nalias = \"a" + n + "\"\nhost = \"h\"\naccount = \"u\"\n"
		}),
	}
	dir := t.TempDir()
	for name, text := range shapes {
		if len(text) > 1<<20 {
			t.Fatalf("%s: test input is %d bytes, over 1 MiB", name, len(text))
		}
		p := filepath.Join(dir, strings.NewReplacer(" ", "_", ":", "", ",", "").Replace(name)+".toml")
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		r := profileShowProcess(t, p)
		t.Logf("%-36s %8d B  %-14s %6.3fs  peak %6.1f MiB  killed=%q", name, len(text), r.code, r.elapsed.Seconds(), r.peakMiB, r.killed)
		if r.killed != "" || r.elapsed > k15Time || r.peakMiB >= k15RSSMiB || (r.code != "PROFILE_OK" && r.code != "SCHEMA_INVALID") {
			t.Errorf("%s: outside K15 bounds (code %q, %v, %.1f MiB, killed %q)", name, r.code, r.elapsed, r.peakMiB, r.killed)
		}
		if strings.HasPrefix(name, "at limit") && r.code != "PROFILE_OK" {
			t.Errorf("%s: expected PROFILE_OK just inside the bounds, got %q", name, r.code)
		}
	}
}
