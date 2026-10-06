//go:build windows

package run

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
)

// refuseTarget refuses .bat/.cmd targets (docs/g02/slice-contract.md §9.6).
// CreateProcess runs such a file as `cmd.exe /c <command line>`, and cmd.exe
// re-parses the line, so Go's CommandLineToArgvW quoting cannot stop argument
// bytes from running as commands. Win32 path normalization drops trailing
// dots and spaces from the last component, so "x.bat." and "x.bat " run the
// same file; they are trimmed before the extension check. Observed natively
// in batch_windows_test.go.
func refuseTarget(path string) string {
	switch strings.ToLower(filepath.Ext(strings.TrimRight(filepath.Base(path), ". "))) {
	case ".bat", ".cmd":
		return "batch-file target (.bat/.cmd) refused: cmd.exe would re-parse its arguments as commands"
	}
	return ""
}

// startAndWait on Windows (run natively in round 4, X1/X1b).
//
//   - Command line: os/exec builds it with syscall.EscapeArg/makeCmdLine,
//     which follows CommandLineToArgvW rules for ordinary executables.
//     .bat/.cmd targets never get here (refuseTarget).
//   - Console Ctrl-C: the console delivers CTRL_C_EVENT to every process
//     attached to the console, including the child. heimdall-proto therefore
//     swallows os.Interrupt (so it does not exit before the child) and does
//     not forward it, avoiding a second delivery. Console resize is native to
//     the shared console; no forwarding exists or is needed.
func startAndWait(cmd *exec.Cmd) Status {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt)
	defer signal.Stop(sigs)
	go func() {
		for range sigs {
		}
	}()
	if err := cmd.Start(); err != nil {
		return Status{Exit: ExitLaunchFailed, LaunchErr: "command could not be started"}
	}
	st, err := cmd.Process.Wait()
	if err != nil {
		return Status{Launched: true, Exit: 1}
	}
	code := st.ExitCode()
	return Status{Launched: true, ExitCode: intp(code), Exit: code}
}
