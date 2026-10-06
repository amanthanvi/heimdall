//go:build windows

package run

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Native Windows tests for docs/g02/slice-contract.md §9.6 (batch targets).
// Build on any host with GOOS=windows go test -c; run the binary on Windows.

// Helper child mode: the test binary re-executes itself as the child.
func TestMain(m *testing.M) {
	if os.Getenv("HP_HELPER") == "argv" {
		b, _ := json.Marshal(os.Args)
		_ = os.WriteFile(os.Getenv("HP_OUT"), b, 0o600)
		os.Exit(7)
	}
	os.Exit(m.Run())
}

// A batch file that, if cmd.exe ever runs it, leaves RAN next to itself.
const markerBatch = "@echo off\r\nbreak>\"%~dp0RAN\"\r\nexit /b 0\r\n"

// injArg runs `break>hpinj.txt` in the working directory if cmd.exe re-parses it.
const injArg = "a&break>hpinj.txt"

func assertRefusedNotRun(t *testing.T, label string, st Status, dir, cwd string) {
	t.Helper()
	if st.Launched || st.Exit != ExitLaunchFailed || st.LaunchErr == "" || st.ExitCode != nil {
		t.Errorf("%s: want refusal (127, not launched, message), got %+v", label, st)
	}
	for _, p := range []string{filepath.Join(dir, "RAN"), filepath.Join(cwd, "hpinj.txt"), filepath.Join(dir, "hpinj.txt")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s: cmd.exe ran (%s exists)", label, filepath.Base(p))
			_ = os.Remove(p)
		}
	}
}

// §9.6: a target that resolves to a .bat or .cmd file is refused with exit
// 127 and a message; cmd.exe never runs, so no argument byte is executed.
// Covers paths with and without a space, extension case, the spellings that
// Windows normalizes to the same file (trailing dots or spaces, the ::$DATA
// stream) and a bare name resolved through PATH + PATHEXT.
func TestBatchTargetRefused(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	for _, dirName := range []string{"bat dir ü", "batdir"} {
		dir := filepath.Join(t.TempDir(), dirName)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"lower.cmd", "lower.bat", "upper.CMD", "mixed.BaT"} {
			full := filepath.Join(dir, name)
			if err := os.WriteFile(full, []byte(markerBatch), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{"", ".", " ", "..", ". .", "::$DATA"} {
				target := full + suffix
				for _, args := range [][]string{nil, {"plain"}, {injArg}} {
					st := Run(append([]string{target}, args...))
					assertRefusedNotRun(t, dirName+"/"+name+"|"+suffix+"|"+filepath.Base(target), st, dir, cwd)
				}
			}
		}
	}
	// Bare name resolved through PATH and PATHEXT.
	pdir := filepath.Join(t.TempDir(), "path dir")
	if err := os.Mkdir(pdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "hpbatname.cmd"), []byte(markerBatch), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pdir)
	t.Setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
	assertRefusedNotRun(t, "PATHEXT bare name", Run([]string{"hpbatname", injArg}), pdir, cwd)
}

// Names whose extension only starts with .bat/.cmd: if CreateProcess hands a
// non-PE file with such a name to cmd.exe, it must be refused too.
func TestBatchPrefixExtensionNotRun(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	dir := filepath.Join(t.TempDir(), "prefix dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p.batx", "p.cmdfoo", "p.bat_"} {
		full := filepath.Join(dir, name)
		if err := os.WriteFile(full, []byte(markerBatch), 0o600); err != nil {
			t.Fatal(err)
		}
		st := Run([]string{full, injArg})
		for _, p := range []string{filepath.Join(dir, "RAN"), filepath.Join(cwd, "hpinj.txt")} {
			if _, err := os.Stat(p); err == nil {
				t.Errorf("%s: cmd.exe ran (%s exists); %+v", name, filepath.Base(p), st)
				_ = os.Remove(p)
			}
		}
		if st.Launched || st.Exit != ExitLaunchFailed {
			t.Errorf("%s: want 127 not launched, got %+v", name, st)
		}
	}
}

// Control: ordinary executables still launch, with arguments delivered
// exactly, also from a directory whose name ends in .bat (only the target's
// own name decides).
func TestExeTargetStillLaunches(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "d.bat")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	copyExe := filepath.Join(dir, "child prog.exe")
	if err := os.WriteFile(copyExe, b, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HP_HELPER", "argv")
	for _, exe := range []string{self, copyExe} {
		out := filepath.Join(t.TempDir(), "argv.json")
		t.Setenv("HP_OUT", out)
		argv := []string{exe, injArg, `a"b c`, "%PATH%", "x^y", "", `back\slash\`}
		st := Run(argv)
		if !st.Launched || st.ExitCode == nil || *st.ExitCode != 7 || st.Exit != 7 {
			t.Fatalf("%s: %+v", exe, st)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got[1:], argv[1:]) {
			t.Fatalf("%s: argv %q, want %q", exe, got[1:], argv[1:])
		}
	}
}
