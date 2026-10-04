// Package testfix locates the shared G02 fixture profiles for tests. It is
// imported only by _test files.
package testfix

import (
	"os"
	"path/filepath"
	"testing"
)

// Env names the fixture directory explicitly (for a relocated module copy or
// a container run).
const Env = "HEIMDALL_G02_FIXTURES"

// Dir returns the shared fixture directory: $HEIMDALL_G02_FIXTURES, else
// tests/fixtures/g02/profiles in the nearest ancestor of the working
// directory that has it. The shared fixtures are the single source of truth
// (not copied into the module), so when neither is found the test fails with
// that instruction instead of being skipped.
func Dir(t testing.TB) string {
	t.Helper()
	if d := os.Getenv(Env); d != "" {
		return d
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for d := wd; ; d = filepath.Dir(d) {
		p := filepath.Join(d, "tests", "fixtures", "g02", "profiles")
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
		if filepath.Dir(d) == d {
			t.Fatalf("G02 fixture profiles not found above %s; set %s to tests/fixtures/g02/profiles", wd, Env)
		}
	}
}
