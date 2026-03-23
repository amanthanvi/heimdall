package log

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"log/slog"
)

func TestRedactionSecretField(t *testing.T) {
	t.Parallel()
	out := logSingleField(t, "secret", "abc123")
	require.Equal(t, "[REDACTED]", out["secret"])
}

func TestRedactionPassphraseField(t *testing.T) {
	t.Parallel()
	out := logSingleField(t, "passphrase", "hunter2")
	require.Equal(t, "[REDACTED]", out["passphrase"])
}

func TestRedactionPrivateKeyField(t *testing.T) {
	t.Parallel()
	out := logSingleField(t, "private_key", "super-secret-key")
	require.Equal(t, "[REDACTED]", out["private_key"])
}

func TestRedactionTokenField(t *testing.T) {
	t.Parallel()
	out := logSingleField(t, "token", "abc.token.xyz")
	require.Equal(t, "[REDACTED]", out["token"])
}

func TestRedactionPasswordField(t *testing.T) {
	t.Parallel()
	out := logSingleField(t, "password", "not-safe")
	require.Equal(t, "[REDACTED]", out["password"])
}

func TestRedactionVMKField(t *testing.T) {
	t.Parallel()
	out := logSingleField(t, "vmk", "deadbeef")
	require.Equal(t, "[REDACTED]", out["vmk"])
}

func TestRedactionKEKField(t *testing.T) {
	t.Parallel()
	out := logSingleField(t, "kek", "deadbeef")
	require.Equal(t, "[REDACTED]", out["kek"])
}

func TestRedactionDEKField(t *testing.T) {
	t.Parallel()
	out := logSingleField(t, "dek", "deadbeef")
	require.Equal(t, "[REDACTED]", out["dek"])
}

func TestNonSensitiveFieldsPassThrough(t *testing.T) {
	t.Parallel()
	out := logSingleField(t, "host", "db.internal")
	require.Equal(t, "db.internal", out["host"])
}

func TestLogRotationCreatesNewFileAfterTenMiB(t *testing.T) {
	logDir := t.TempDir()
	logPath := filepath.Join(logDir, "heimdall.log")

	writer, err := NewRotatingWriter(RotationConfig{
		File:      logPath,
		MaxSizeMB: 10,
		MaxFiles:  5,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Close() })

	chunk := bytes.Repeat([]byte("a"), 1024*1024)
	for i := 0; i < 11; i++ {
		_, err = writer.Write(chunk)
		require.NoError(t, err)
	}

	files, err := filepath.Glob(filepath.Join(logDir, "heimdall*"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(files), 2)
}

func TestLogRotationRetainsMaxFiveFiles(t *testing.T) {
	logDir := t.TempDir()
	logPath := filepath.Join(logDir, "heimdall.log")

	writer, err := NewRotatingWriter(RotationConfig{
		File:      logPath,
		MaxSizeMB: 10,
		MaxFiles:  5,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Close() })

	chunk := bytes.Repeat([]byte("b"), 1024*1024)
	for i := 0; i < 80; i++ {
		_, err := writer.Write(chunk)
		require.NoError(t, err)
	}

	require.NoError(t, writer.Close())

	var lastBackupCount int
	require.Eventually(t, func() bool {
		files, err := filepath.Glob(filepath.Join(logDir, "heimdall*"))
		require.NoError(t, err)

		lastBackupCount = 0
		for _, fileName := range files {
			if fileName == logPath {
				continue
			}
			if _, statErr := os.Stat(fileName); statErr == nil {
				lastBackupCount++
			}
		}
		return lastBackupCount <= 5
	}, 2*time.Second, 20*time.Millisecond, "expected at most 5 backup logs, saw %d", lastBackupCount)
}

func logSingleField(t *testing.T, key, value string) map[string]any {
	t.Helper()

	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(NewRedactingHandler(base))
	logger.Info("test", key, value)

	line := bytes.TrimSpace(buf.Bytes())
	out := map[string]any{}
	require.NoError(t, json.Unmarshal(line, &out))
	return out
}
