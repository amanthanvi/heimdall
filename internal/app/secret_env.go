package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const LinuxProcEnvironRisk = "On Linux, environment variables are visible to same-user processes via /proc/<pid>/environ; keep injected secret env usage short-lived."

func InjectSecretIntoProcessEnv(
	ctx context.Context,
	getter SecretValueGetter,
	secretName string,
	envVar string,
	cmd []string,
	baseEnv []string,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	if getter == nil {
		return -1, fmt.Errorf("%w: secret getter is nil", ErrValidation)
	}
	if strings.TrimSpace(secretName) == "" {
		return -1, fmt.Errorf("%w: secret name is required", ErrValidation)
	}
	if strings.TrimSpace(envVar) == "" {
		return -1, fmt.Errorf("%w: env var name is required", ErrValidation)
	}
	if len(cmd) == 0 {
		return -1, fmt.Errorf("%w: command is required", ErrValidation)
	}

	value, err := getter.GetValue(ctx, secretName)
	if err != nil {
		return -1, fmt.Errorf("inject secret env: get value: %w", err)
	}
	defer wipeBytes(value)

	command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	command.Stdout = stdout
	command.Stderr = stderr

	if len(baseEnv) > 0 {
		command.Env = append([]string(nil), baseEnv...)
	} else {
		command.Env = append([]string(nil), os.Environ()...)
	}
	command.Env = append(command.Env, envVar+"="+string(value))

	if err := command.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return -1, fmt.Errorf("inject secret env: run command: %w", err)
	}
	return 0, nil
}

func wipeBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
