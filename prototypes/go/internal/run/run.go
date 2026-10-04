// Package run launches a child without a shell (docs/g02/slice-contract.md §4).
package run

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Status is the observed child outcome.
type Status struct {
	Launched bool
	ExitCode *int // nil when the child died by signal or never launched
	Signal   *int // Unix signal number when the child died by signal
	// Exit is the status heimdall-proto itself should exit with.
	Exit int
	// LaunchErr is a stderr diagnostic when Launched is false.
	LaunchErr string
}

// ExitLaunchFailed is the contract exit status when the child cannot launch.
const ExitLaunchFailed = 127

// Run resolves argv[0] via PATH (no shell), starts it with inherited
// stdio/cwd/environment, forwards signals, and waits. argv must be non-empty.
func Run(argv []string) Status {
	path, err := exec.LookPath(argv[0])
	// K7 refusal pinned in code: a bare name resolved through "." or an empty
	// PATH entry yields a relative path. exec.LookPath reports that as
	// exec.ErrDot unless GODEBUG=execerrdot=0 is set in the environment, which
	// must not be able to switch the refusal off.
	if err == nil && !strings.ContainsAny(argv[0], "/"+string(os.PathSeparator)) && !filepath.IsAbs(path) {
		err = exec.ErrDot
	}
	if err != nil {
		msg := "command not found"
		if errors.Is(err, exec.ErrDot) {
			msg = "command resolved to the current directory via PATH; refused (use ./name)"
		} else if errors.Is(err, os.ErrPermission) {
			msg = "command is not executable"
		}
		return Status{Exit: ExitLaunchFailed, LaunchErr: msg}
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Args[0] = argv[0] // preserve argv[0] exactly as given
	// *os.File stdio is passed as raw descriptors: no copy goroutines, so
	// bytes (NUL, invalid UTF-8) pass through unmodified in both directions.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return startAndWait(cmd)
}

func intp(v int) *int { return &v }
