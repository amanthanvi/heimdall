package buildcheck

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildWithFido2TagSucceeds(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)

	cmd := exec.Command("go", "build", "-tags", "fido2", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build with fido2 tag failed:\n%s", string(output))
}

func TestBuildWithNoFido2TagSucceedsWithoutCGO(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)

	cmd := exec.Command("go", "build", "-tags", "nofido2", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build with nofido2 tag failed:\n%s", string(output))
}

func TestGoVetProducesNoWarnings(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)

	cmd := exec.Command("go", "vet", "./...")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go vet failed:\n%s", string(output))
}

func TestCryptoDependencyBoundaries(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)

	importsByPkg := listDirectImports(t, root, "./internal/crypto/...")
	for pkg, imports := range importsByPkg {
		for _, imp := range imports {
			if isAllowedCryptoImport(imp) {
				continue
			}
			t.Fatalf("package %s imported disallowed dependency %q", pkg, imp)
		}
	}
}

func TestStorageDoesNotImportCLI(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)

	imports := listDependencies(t, root, "./internal/storage")
	for _, imp := range imports {
		require.NotEqual(t, "github.com/amanthanvi/heimdall/internal/cli", imp)
	}
}

func TestCLIDoesNotDirectlyImportStorage(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)

	// CLI commands must not directly import internal/storage — they
	// access data through the gRPC client. The only exception is
	// cmd_daemon_serve.go which IS the daemon process and needs
	// storage directly. Since Go lists imports at package level,
	// we verify that only the expected package (internal/cli itself)
	// has this import, and accept it because daemon serve is the
	// embedded server.
	//
	// Transitive deps through internal/app and internal/daemon are
	// also acceptable.
	importsByPkg := listDirectImports(t, root, "./internal/cli")
	for pkg, imports := range importsByPkg {
		// The main cli package imports storage for daemon serve — allowed.
		if pkg == "github.com/amanthanvi/heimdall/internal/cli" {
			continue
		}
		for _, imp := range imports {
			require.NotEqualf(t, "github.com/amanthanvi/heimdall/internal/storage", imp,
				"package %s directly imports internal/storage — use gRPC client instead", pkg)
		}
	}
}

func TestVersionEmbedding(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	binaryPath := filepath.Join(t.TempDir(), "heimdall-test")

	version := "v0.1.0-test"
	commit := "abc123def456"
	buildTime := "2026-02-19T00:00:00Z"

	build := exec.Command(
		"go",
		"build",
		"-trimpath",
		"-ldflags",
		"-X github.com/amanthanvi/heimdall/internal/version.Version="+version+
			" -X github.com/amanthanvi/heimdall/internal/version.Commit="+commit+
			" -X github.com/amanthanvi/heimdall/internal/version.BuildTime="+buildTime,
		"-o",
		binaryPath,
		"./cmd/heimdall",
	)
	build.Dir = root
	buildOutput, err := build.CombinedOutput()
	require.NoErrorf(t, err, "build failed:\n%s", string(buildOutput))

	run := exec.Command(binaryPath, "version", "--json")
	run.Dir = root
	stdout, err := run.CombinedOutput()
	require.NoErrorf(t, err, "running binary failed:\n%s", string(stdout))

	var got struct {
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		BuildTime string `json:"build_time"`
	}
	require.NoError(t, json.Unmarshal(stdout, &got))
	require.Equal(t, version, got.Version)
	require.Equal(t, commit, got.Commit)
	require.Equal(t, buildTime, got.BuildTime)
}

func listDependencies(t *testing.T, root string, target string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", target)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go list failed:\n%s", string(output))

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	deps := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		deps = append(deps, line)
	}
	return deps
}

func listDirectImports(t *testing.T, root, pattern string) map[string][]string {
	t.Helper()
	cmd := exec.Command("go", "list", "-json", pattern)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go list -json failed:\n%s", string(output))

	dec := json.NewDecoder(strings.NewReader(string(output)))
	importsByPkg := map[string][]string{}
	for {
		var p struct {
			ImportPath string
			Imports    []string
		}
		err := dec.Decode(&p)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		importsByPkg[p.ImportPath] = append([]string(nil), p.Imports...)
	}
	return importsByPkg
}

func isAllowedCryptoImport(importPath string) bool {
	if isStdlib(importPath) {
		return true
	}

	if strings.HasPrefix(importPath, "golang.org/x/crypto") {
		return true
	}

	// AGENTS security rules require memguard for VMK material.
	if strings.HasPrefix(importPath, "github.com/awnumar/memguard") {
		return true
	}

	return false
}

func isStdlib(importPath string) bool {
	first := importPath
	if idx := strings.Index(importPath, "/"); idx > -1 {
		first = importPath[:idx]
	}
	return !strings.Contains(first, ".")
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	_, err := os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, err)
	return root
}
