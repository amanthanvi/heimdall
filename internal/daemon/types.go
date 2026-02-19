package daemon

import (
	"context"
	"errors"
	"os"
	"time"
)

var (
	ErrDaemonAlreadyRunning   = errors.New("daemon: already running")
	ErrDaemonStartUnsupported = errors.New("daemon: auto-start is not configured")
)

type Info struct {
	PID        int       `json:"pid"`
	SocketPath string    `json:"socket_path"`
	AgentPath  string    `json:"agent_path"`
	StartedAt  time.Time `json:"started_at"`
}

type ProcessInspector interface {
	IsRunning(pid int) bool
	StartTime(pid int) (time.Time, error)
}

type Options struct {
	HomeDir    string
	RuntimeDir string
	Inspector  ProcessInspector
	SignalCh   <-chan os.Signal
	ReloadHook func(context.Context) error
	Now        func() time.Time
}

type EnsureOptions struct {
	HomeDir     string
	RuntimeDir  string
	Starter     func(context.Context) error
	DialTimeout time.Duration
}
