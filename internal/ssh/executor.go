package ssh

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

type Executor struct {
	commandFactory func(ctx context.Context, binary string, args ...string) *exec.Cmd
	signalCh       <-chan os.Signal
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

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

	for {
		select {
		case <-ctx.Done():
			sendSignalToProcessGroup(cmd.Process.Pid, syscall.SIGINT)
			err := <-waitCh
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					return exitErr.ExitCode(), nil
				}
				return 1, fmt.Errorf("run ssh command: wait after cancel: %w", err)
			}
			return 0, nil
		case <-sigCh:
			sendSignalToProcessGroup(cmd.Process.Pid, syscall.SIGINT)
		case err := <-waitCh:
			if err == nil {
				return 0, nil
			}
			if exitErr, ok := err.(*exec.ExitError); ok {
				return exitErr.ExitCode(), nil
			}
			return 1, fmt.Errorf("run ssh command: wait: %w", err)
		}
	}
}

func sendSignalToProcessGroup(pid int, sig syscall.Signal) {
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(-pid, sig)
}
