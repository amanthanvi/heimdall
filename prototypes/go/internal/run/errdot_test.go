//go:build !windows

package run

import (
	"os"
	"path/filepath"
	"testing"
)

// The refusal of a PATH match found through "." or an empty PATH entry (K7)
// is pinned in code: GODEBUG=execerrdot=0 in the environment must not turn it
// back into execvp behavior.
func TestDotPathRefusalNotEnvironmentControlled(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "RAN")
	script := "#!/bin/sh\n: > '" + marker + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "hpdotcmd"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	for _, godebug := range []string{"", "execerrdot=0", "execerrdot=1"} {
		for _, path := range []string{".", ":/usr/bin", "/usr/bin::/bin"} {
			t.Setenv("GODEBUG", godebug)
			t.Setenv("PATH", path)
			st := Run([]string{"hpdotcmd"})
			if st.Launched || st.Exit != ExitLaunchFailed {
				t.Errorf("GODEBUG=%q PATH=%q: %+v", godebug, path, st)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatalf("GODEBUG=%q PATH=%q: the command found through the current directory ran", godebug, path)
			}
		}
	}
	// An explicit relative path is still allowed.
	t.Setenv("GODEBUG", "")
	if st := Run([]string{"./hpdotcmd"}); !st.Launched || st.Exit != 0 {
		t.Fatalf("./hpdotcmd: %+v", st)
	}
}
