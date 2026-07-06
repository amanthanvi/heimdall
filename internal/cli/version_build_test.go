package cli

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuiltBinaryEmbedsVersionMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	binary := filepath.Join(t.TempDir(), "heimdall-smoke")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}

	ldflags := strings.Join([]string{
		"-X github.com/athanvi/heimdall/internal/cli.Version=1.2.3",
		"-X github.com/athanvi/heimdall/internal/cli.Commit=abcdef1234567890",
		"-X github.com/athanvi/heimdall/internal/cli.Date=2026-06-27T12:34:56Z",
	}, " ")
	build := exec.Command("go", "build", "-ldflags", ldflags, "-o", binary, "./cmd/heimdall")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	run := exec.Command(binary, "version", "--format", "json")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("heimdall version failed: %v\n%s", err, out)
	}

	var got versionInfo
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("version output is not JSON: %v\n%s", err, out)
	}
	if got.Version != "1.2.3" || got.Commit != "abcdef1234567890" || got.Date != "2026-06-27T12:34:56Z" {
		t.Fatalf("unexpected version metadata: %#v", got)
	}
}
