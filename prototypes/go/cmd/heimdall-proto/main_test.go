package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heimdall-g02/proto-go/internal/testfix"
)

func call(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	code := realMain(args, &o, &e)
	return code, o.String(), e.String()
}

func envelope(t *testing.T, s string) map[string]any {
	t.Helper()
	if !strings.HasSuffix(s, "\n") || strings.Count(s, "\n") != 1 {
		t.Fatalf("not one JSON line: %q", s)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema_version", "state", "code", "data", "warnings", "next"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing %s", k)
		}
	}
	return m
}

func TestUsageErrors(t *testing.T) {
	code, out, _ := call("nope", "--json")
	if code != 2 || envelope(t, out)["code"] != "USAGE_ERROR" {
		t.Fatal(code, out)
	}
	code, out, errS := call("nope")
	if code != 2 || out != "" || errS == "" {
		t.Fatal("no-json usage must be stderr only")
	}
	code, out, _ = call("profile", "show", "--bogus", "--json")
	if code != 2 || envelope(t, out)["code"] != "USAGE_ERROR" {
		t.Fatal(code, out)
	}
	for _, a := range [][]string{{"run"}, {"run", "--"}, {"run", "true"}} {
		if code, out, _ := call(a...); code != 2 || out != "" {
			t.Fatal(a, code, out)
		}
	}
	code, out, _ = call("agent", "list", "--socket", "x", "--timeout-ms", "abc", "--json")
	if code != 2 || envelope(t, out)["code"] != "USAGE_ERROR" {
		t.Fatal(code, out)
	}
}

func TestProfileShowOversizeAndMissing(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "oversize ü.toml")
	_ = os.WriteFile(f, bytes.Repeat([]byte("a"), 1<<20+1), 0o600)
	code, out, _ := call("profile", "show", "--file", f, "--json")
	if code != 2 || envelope(t, out)["code"] != "INPUT_TOO_LARGE" {
		t.Fatal(code, out)
	}
	code, out, _ = call("profile", "show", "--file", filepath.Join(dir, "missing"), "--json")
	if code != 2 || envelope(t, out)["code"] != "USAGE_ERROR" {
		t.Fatal(code, out)
	}
}

func TestCanaryNeverEmitted(t *testing.T) {
	for _, f := range []string{"invalid-forbidden-key.toml", "invalid-unknown-dest-key.toml"} {
		code, out, errS := call("profile", "show", "--file", filepath.Join(testfix.Dir(t), f), "--json")
		if code != 2 || strings.Contains(out+errS, "HEIMDALL_CANARY_") {
			t.Fatal(f, code, out, errS)
		}
	}
}

func TestRunMetaFile(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, "meta ü.json")
	code, out, _ := call("run", "--meta-file", meta, "--", "/bin/sh", "-c", "exit 4")
	if code != 4 || out != "" {
		t.Fatal(code, out)
	}
	b, _ := os.ReadFile(meta)
	m := envelope(t, string(b))
	d := m["data"].(map[string]any)
	if m["code"] != "CHILD_EXITED" || d["launched"] != true || d["exit_code"].(float64) != 4 || d["signal"] != nil {
		t.Fatal(string(b))
	}
	code, _, _ = call("run", "--meta-file="+meta, "--", "no-such-command-heimdall")
	b, _ = os.ReadFile(meta)
	m = envelope(t, string(b))
	if code != 127 || m["code"] != "CHILD_LAUNCH_FAILED" || m["data"].(map[string]any)["launched"] != false {
		t.Fatal(code, string(b))
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := call("version", "--json")
	m := envelope(t, out)
	d := m["data"].(map[string]any)
	if code != 0 || d["candidate"] != "go" || d["version"] != "0.0.0-g02" {
		t.Fatal(out)
	}
}

func TestTUIRequiresTTY(t *testing.T) {
	// go test runs with stdout not a terminal.
	code, out, _ := call("tui", "--file", filepath.Join(testfix.Dir(t), "homelab.toml"))
	if code != 2 || out != "" {
		t.Fatal(code, out)
	}
}

// K5 (slice-contract §9): CHILD_EXITED uses state "succeeded" whatever the
// child's exit status (including nonzero and death by signal);
// CHILD_LAUNCH_FAILED uses state "failed".
func TestK5MetaState(t *testing.T) {
	meta := filepath.Join(t.TempDir(), "meta ü.json")
	cases := []struct {
		argv          []string
		exit          int
		code, state   string
		exitCode, sig any
	}{
		{[]string{"/bin/sh", "-c", "exit 0"}, 0, "CHILD_EXITED", "succeeded", float64(0), nil},
		{[]string{"/bin/sh", "-c", "exit 4"}, 4, "CHILD_EXITED", "succeeded", float64(4), nil},
		{[]string{"/bin/sh", "-c", "kill -TERM $$"}, 143, "CHILD_EXITED", "succeeded", nil, float64(15)},
		{[]string{"no-such-command-heimdall-k5"}, 127, "CHILD_LAUNCH_FAILED", "failed", nil, nil},
	}
	for _, c := range cases {
		code, out, _ := call(append([]string{"run", "--meta-file", meta, "--"}, c.argv...)...)
		b, _ := os.ReadFile(meta)
		m := envelope(t, string(b))
		d := m["data"].(map[string]any)
		if code != c.exit || out != "" || m["code"] != c.code || m["state"] != c.state ||
			d["exit_code"] != c.exitCode || d["signal"] != c.sig {
			t.Fatalf("%v: exit=%d meta=%s", c.argv, code, b)
		}
	}
}
