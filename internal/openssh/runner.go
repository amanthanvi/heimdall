package openssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

var ErrActiveProbeRequired = errors.New("active probe consent required")

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type Runner interface {
	Run(ctx context.Context, name string, args []string) (Result, error)
}

type ExecRunner struct {
	Timeout time.Duration
}

func (r ExecRunner) Run(ctx context.Context, name string, args []string) (Result, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if exitErr := new(exec.ExitError); errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, err
	}
	if err != nil {
		res.ExitCode = -1
		return res, err
	}
	return res, nil
}

type FakeRunner struct {
	Results map[string]Result
	Errors  map[string]error
	Calls   []string
}

func (r *FakeRunner) Run(_ context.Context, name string, args []string) (Result, error) {
	key := CommandKey(name, args)
	r.Calls = append(r.Calls, key)
	if r.Errors != nil && r.Errors[key] != nil {
		return r.Results[key], r.Errors[key]
	}
	if r.Results != nil {
		if res, ok := r.Results[key]; ok {
			return res, nil
		}
	}
	return Result{ExitCode: 127, Stderr: "fake command not found"}, fmt.Errorf("fake command not found: %s", key)
}

func CommandKey(name string, args []string) string {
	out := name
	for _, arg := range args {
		out += "\x00" + arg
	}
	return out
}
