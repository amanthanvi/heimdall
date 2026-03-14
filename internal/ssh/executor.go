package ssh

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

const signalGracePeriod = 2 * time.Second

type Executor struct {
	commandFactory  func(ctx context.Context, binary string, args ...string) *exec.Cmd
	signalCh        <-chan os.Signal
	useProcessGroup *bool
}

func NewExecutor() *Executor {
	return &Executor{}
}

func (e *Executor) Run(ctx context.Context, command *SSHCommand) (int, error) {
	if command == nil {
		return 1, fmt.Errorf("run ssh command: command is nil")
	}
	if command.Binary == "" {
		return 1, fmt.Errorf("run ssh command: binary is required")
	}

	for _, path := range command.TempFiles {
		path := path
		defer func() { _ = os.Remove(path) }()
	}

	factory := e.commandFactory
	if factory == nil {
		factory = exec.CommandContext
	}
	cmd := factory(ctx, command.Binary, command.Args...)
	cmd.Env = append(os.Environ(), command.Env...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	useProcessGroup := !hasInteractiveStdin(os.Stdin)
	if e.useProcessGroup != nil {
		useProcessGroup = *e.useProcessGroup
	}
	if useProcessGroup {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("run ssh command: start: %w", err)
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	sigCh := e.signalCh
	var ownedSigCh chan os.Signal
	if sigCh == nil {
		ownedSigCh = make(chan os.Signal, 1)
		signal.Notify(ownedSigCh, os.Interrupt)
		sigCh = ownedSigCh
	}
	if ownedSigCh != nil {
		defer func() {
			signal.Stop(ownedSigCh)
			close(ownedSigCh)
		}()
	}

	var killTimer <-chan time.Time
	interruptSent := false

	for {
		select {
		case <-ctx.Done():
			if !interruptSent {
				sendSignalToProcess(cmd.Process.Pid, syscall.SIGINT, useProcessGroup)
				interruptSent = true
				killTimer = time.After(signalGracePeriod)
				continue
			}
			sendSignalToProcess(cmd.Process.Pid, syscall.SIGKILL, useProcessGroup)
		case <-sigCh:
			if !interruptSent {
				sendSignalToProcess(cmd.Process.Pid, syscall.SIGINT, useProcessGroup)
				interruptSent = true
				killTimer = time.After(signalGracePeriod)
				continue
			}
			sendSignalToProcess(cmd.Process.Pid, syscall.SIGKILL, useProcessGroup)
		case <-killTimer:
			sendSignalToProcess(cmd.Process.Pid, syscall.SIGKILL, useProcessGroup)
			killTimer = nil
		case err := <-waitCh:
			if err == nil {
				return 0, nil
			}
			if exitErr, ok := err.(*exec.ExitError); ok {
				return exitCodeFromExitError(exitErr), nil
			}
			return 1, fmt.Errorf("run ssh command: wait: %w", err)
		}
	}
}

func sendSignalToProcess(pid int, sig syscall.Signal, useProcessGroup bool) {
	if pid <= 0 {
		return
	}
	if useProcessGroup {
		_ = syscall.Kill(-pid, sig)
		return
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = process.Signal(sig)
}

func exitCodeFromExitError(exitErr *exec.ExitError) int {
	if exitErr == nil {
		return 1
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return exitErr.ExitCode()
}

func hasInteractiveStdin(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
