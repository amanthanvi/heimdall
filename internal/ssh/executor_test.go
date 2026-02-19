package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExecutorPropagatesChildExitCode(t *testing.T) {
	t.Parallel()

	exec := NewExecutor()
	code, err := exec.Run(t.Context(), &SSHCommand{Binary: "sh", Args: []string{"-c", "exit 17"}})
	require.NoError(t, err)
	require.Equal(t, 17, code)
}

func TestExecutorRemovesTempFilesAfterExit(t *testing.T) {
	t.Parallel()

	tempFile := filepath.Join(t.TempDir(), "temp.key")
	require.NoError(t, os.WriteFile(tempFile, []byte("sensitive"), 0o600))

	exec := NewExecutor()
	code, err := exec.Run(t.Context(), &SSHCommand{
		Binary:    "sh",
		Args:      []string{"-c", "exit 0"},
		TempFiles: []string{tempFile},
	})
	require.NoError(t, err)
	require.Equal(t, 0, code)
	_, statErr := os.Stat(tempFile)
	require.True(t, os.IsNotExist(statErr))
}

func TestExecutorRemovesTempFilesOnSignal(t *testing.T) {
	t.Parallel()

	tempFile := filepath.Join(t.TempDir(), "temp.key")
	require.NoError(t, os.WriteFile(tempFile, []byte("sensitive"), 0o600))

	sigCh := make(chan os.Signal, 1)
	exec := &Executor{signalCh: sigCh}

	done := make(chan int, 1)
	go func() {
		code, _ := exec.Run(t.Context(), &SSHCommand{
			Binary:    "sh",
			Args:      []string{"-c", "trap 'exit 130' INT; sleep 5"},
			TempFiles: []string{tempFile},
		})
		done <- code
	}()

	time.Sleep(120 * time.Millisecond)
	sigCh <- os.Interrupt

	select {
	case code := <-done:
		require.Equal(t, 130, code)
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not terminate after signal")
	}

	_, statErr := os.Stat(tempFile)
	require.True(t, os.IsNotExist(statErr))
}

func TestExecutorReapsChildProcessToPreventZombie(t *testing.T) {
	t.Parallel()

	pidFile := filepath.Join(t.TempDir(), "pid.txt")
	exec := NewExecutor()
	code, err := exec.Run(t.Context(), &SSHCommand{
		Binary: "sh",
		Args:   []string{"-c", "echo $$ > " + pidFile + "; exit 0"},
	})
	require.NoError(t, err)
	require.Equal(t, 0, code)

	data, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	pid := 0
	_, scanErr := fmt.Sscanf(string(data), "%d", &pid)
	require.NoError(t, scanErr)
	require.Greater(t, pid, 0)

	killErr := syscall.Kill(pid, 0)
	require.Error(t, killErr)
	require.Equal(t, syscall.ESRCH, killErr)
}
