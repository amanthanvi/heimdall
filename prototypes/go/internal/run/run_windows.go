//go:build windows

package run

import (
	"os"
	"os/exec"
	"os/signal"
)

// startAndWait on Windows. COMPILE-CHECKED ONLY (no native Windows host).
//
//   - Command line: os/exec builds it with syscall.EscapeArg/makeCmdLine,
//     which follows CommandLineToArgvW rules for ordinary executables. It is
//     NOT safe for .bat/.cmd targets (cmd.exe re-parses the line); see
//     REPORT.md.
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
