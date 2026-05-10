package bridge

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestBridgeRelaysUnixSocketAndCleansUp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket bridge relay is not available on Windows")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	upstreamPath := filepath.Join(dir, "upstream.sock")
	listener, err := net.Listen("unix", upstreamPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 32)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(append([]byte("echo:"), buf[:n]...))
	}()

	server, state, err := Start(context.Background(), StartRequest{
		Name:           "test",
		RuntimeDir:     dir,
		UpstreamSocket: upstreamPath,
		TTL:            time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", state.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "echo:hello" {
		t.Fatalf("unexpected relay response %q", got)
	}
	_ = conn.Close()
	if err := server.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state.SocketPath); !os.IsNotExist(err) {
		t.Fatalf("socket was not cleaned up: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "heimdall-bridge.cleanup")); !os.IsNotExist(err) {
		t.Fatalf("cleanup marker was not removed: %v", err)
	}
}

func TestBridgeCommandModeValidatesBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket bridge relay is not available on Windows")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err := Start(context.Background(), StartRequest{
		Name:            "bad",
		RuntimeDir:      dir,
		UpstreamCommand: []string{"definitely-not-present-heimdall-test"},
		TTL:             time.Minute,
	})
	if err == nil {
		t.Fatal("expected missing command refusal")
	}
}

func TestDoctorRuntimeDirRejectsBroadPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := DoctorRuntimeDir(dir); err == nil {
		t.Fatal("expected broad permission refusal")
	}
}

func TestCleanupExpiredRefusesOutsideRuntimeDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "heimdall-bridge.cleanup"), []byte("/tmp/outside.sock\n2000-01-01T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CleanupExpired(dir, time.Now()); err == nil {
		t.Fatal("expected outside runtime dir refusal")
	}
}
