package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestAgentProtocolIdentitiesEmptyWhenNoKeysLoaded(t *testing.T) {
	t.Parallel()

	server, _, client := newAgentProtocolHarness(t)

	keys, err := client.List()
	require.NoError(t, err)
	require.Empty(t, keys)
	require.NotNil(t, server)
}

func TestAgentProtocolAddKeyAndIdentitiesList(t *testing.T) {
	t.Parallel()

	server, _, client := newAgentProtocolHarness(t)
	privatePEM, signer := generateEd25519KeyPEM(t)
	require.NoError(t, server.AddKey(&Identity{Name: "ed", PrivateKey: privatePEM, SessionID: "s1"}, time.Hour))

	keys, err := client.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, signer.PublicKey().Type(), keys[0].Format)
}

func TestAgentProtocolSignRequestProducesValidSignature(t *testing.T) {
	t.Parallel()

	server, _, client := newAgentProtocolHarness(t)
	privatePEM, signer := generateEd25519KeyPEM(t)
	require.NoError(t, server.AddKey(&Identity{Name: "ed", PrivateKey: privatePEM, SessionID: "s1"}, time.Hour))

	payload := []byte("payload")
	sig, err := client.Sign(signer.PublicKey(), payload)
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify(payload, sig))
}

func TestAgentProtocolRemoveKeyRemovesSpecificKey(t *testing.T) {
	t.Parallel()

	server, _, client := newAgentProtocolHarness(t)
	edPEM, edSigner := generateEd25519KeyPEM(t)
	rsaPEM, _ := generateRSAKeyPEM(t)

	require.NoError(t, server.AddKey(&Identity{Name: "ed", PrivateKey: edPEM, SessionID: "s1"}, time.Hour))
	require.NoError(t, server.AddKey(&Identity{Name: "rsa", PrivateKey: rsaPEM, SessionID: "s1"}, time.Hour))
	require.NoError(t, server.RemoveKey(ssh.FingerprintSHA256(edSigner.PublicKey())))

	keys, err := client.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.NotEqual(t, edSigner.PublicKey().Marshal(), keys[0].Blob)
}

func TestAgentProtocolRemoveAllClearsAllKeys(t *testing.T) {
	t.Parallel()

	server, _, client := newAgentProtocolHarness(t)
	edPEM, _ := generateEd25519KeyPEM(t)
	rsaPEM, _ := generateRSAKeyPEM(t)

	require.NoError(t, server.AddKey(&Identity{Name: "ed", PrivateKey: edPEM, SessionID: "s1"}, time.Hour))
	require.NoError(t, server.AddKey(&Identity{Name: "rsa", PrivateKey: rsaPEM, SessionID: "s1"}, time.Hour))
	require.NoError(t, server.RemoveAll())

	keys, err := client.List()
	require.NoError(t, err)
	require.Empty(t, keys)
}

func TestAgentTTLExpiryRemovesKeyAfterDuration(t *testing.T) {
	t.Parallel()

	server, _, client := newAgentProtocolHarness(t)
	edPEM, _ := generateEd25519KeyPEM(t)
	require.NoError(t, server.AddKey(&Identity{Name: "ed", PrivateKey: edPEM, SessionID: "s1"}, 80*time.Millisecond))

	require.Eventually(t, func() bool {
		keys, err := client.List()
		if err != nil {
			return false
		}
		return len(keys) == 0
	}, 2*time.Second, 25*time.Millisecond)
}

func TestAgentAutoLockClearsAllKeys(t *testing.T) {
	t.Parallel()

	server, daemon, client := newAgentProtocolHarness(t)
	edPEM, _ := generateEd25519KeyPEM(t)
	require.NoError(t, server.AddKey(&Identity{Name: "ed", PrivateKey: edPEM, SessionID: "s1"}, time.Hour))

	daemon.setLocked(true)

	require.Eventually(t, func() bool {
		keys, err := client.List()
		if err != nil {
			return false
		}
		return len(keys) == 0
	}, 2*time.Second, 25*time.Millisecond)
}

func TestAgentAutoLockRejectsSigningRequests(t *testing.T) {
	t.Parallel()

	server, daemon, client := newAgentProtocolHarness(t)
	edPEM, signer := generateEd25519KeyPEM(t)
	require.NoError(t, server.AddKey(&Identity{Name: "ed", PrivateKey: edPEM, SessionID: "s1"}, time.Hour))

	daemon.setLocked(true)
	_, err := client.Sign(signer.PublicKey(), []byte("payload"))
	require.Error(t, err)
}

func TestAgentSocketUsesRuntimePathAnd0600Permissions(t *testing.T) {
	t.Parallel()

	_, _, socketPath := newAgentSocketHarness(t)
	require.True(t, strings.HasSuffix(socketPath, filepath.Join("heimdall", "agent.sock")))
	info, err := os.Stat(socketPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestExternalAgentFallbackCallsSSHAddWithTempKeyFile(t *testing.T) {
	t.Parallel()

	server, _, _ := newAgentProtocolHarness(t)
	scriptDir := t.TempDir()
	argsPath := filepath.Join(scriptDir, "args.txt")
	scriptPath := writeScript(t, scriptDir, fmt.Sprintf("#!/bin/sh\nprintf '%%s\n' \"$@\" > %s\n", argsPath))

	var calledName string
	server.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calledName = name
		return exec.CommandContext(ctx, scriptPath, args...)
	}

	privatePEM, _ := generateEd25519KeyPEM(t)
	err := server.AddToExternalAgent(context.Background(), &Identity{PrivateKey: privatePEM}, time.Hour)
	require.NoError(t, err)
	require.Equal(t, "ssh-add", calledName)

	data, err := os.ReadFile(argsPath)
	require.NoError(t, err)
	args := strings.Fields(string(data))
	require.Contains(t, args, "-t")
	require.NotEmpty(t, args[len(args)-1])
}

func TestExternalAgentFallbackDeletesTempKeyFileImmediately(t *testing.T) {
	t.Parallel()

	server, _, _ := newAgentProtocolHarness(t)
	scriptDir := t.TempDir()
	argsPath := filepath.Join(scriptDir, "args.txt")
	scriptPath := writeScript(t, scriptDir, fmt.Sprintf("#!/bin/sh\nprintf '%%s\n' \"$@\" > %s\n", argsPath))

	server.execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, scriptPath, args...)
	}

	privatePEM, _ := generateEd25519KeyPEM(t)
	err := server.AddToExternalAgent(context.Background(), &Identity{PrivateKey: privatePEM}, time.Hour)
	require.NoError(t, err)

	data, err := os.ReadFile(argsPath)
	require.NoError(t, err)
	args := strings.Fields(string(data))
	tempPath := args[len(args)-1]
	_, statErr := os.Stat(tempPath)
	require.True(t, os.IsNotExist(statErr))
}

func TestEd25519KeySigningProducesValidSSHSig(t *testing.T) {
	t.Parallel()

	server, _, client := newAgentProtocolHarness(t)
	privatePEM, signer := generateEd25519KeyPEM(t)
	require.NoError(t, server.AddKey(&Identity{Name: "ed", PrivateKey: privatePEM, SessionID: "s1"}, time.Hour))

	msg := []byte("ed25519")
	sig, err := client.Sign(signer.PublicKey(), msg)
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify(msg, sig))
}

func TestRSAKeySigningProducesValidSSHSig(t *testing.T) {
	t.Parallel()

	server, _, client := newAgentProtocolHarness(t)
	privatePEM, signer := generateRSAKeyPEM(t)
	require.NoError(t, server.AddKey(&Identity{Name: "rsa", PrivateKey: privatePEM, SessionID: "s1"}, time.Hour))

	msg := []byte("rsa")
	sig, err := client.Sign(signer.PublicKey(), msg)
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify(msg, sig))
}

func newAgentSocketHarness(t *testing.T) (*AgentServer, *testDaemon, string) {
	t.Helper()

	runtimeDir, err := os.MkdirTemp("/tmp", "hd-agent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	socketPath := filepath.Join(runtimeDir, "heimdall", "agent.sock")
	daemon := &testDaemon{}
	server := NewServer(daemon)
	startErr := server.Start(socketPath)
	if startErr != nil {
		if strings.Contains(startErr.Error(), "operation not permitted") {
			t.Skipf("unix socket bind unavailable in sandbox: %v", startErr)
		}
		require.NoError(t, startErr)
	}
	t.Cleanup(func() {
		require.NoError(t, server.Stop())
	})
	return server, daemon, socketPath
}

func newAgentProtocolHarness(t *testing.T) (*AgentServer, *testDaemon, sshagent.ExtendedAgent) {
	t.Helper()

	daemon := &testDaemon{}
	server := NewServer(daemon)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sshagent.ServeAgent(server, serverConn)
	}()

	client := sshagent.NewClient(clientConn)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("protocol harness did not stop")
		}
	})
	return server, daemon, client
}

func generateEd25519KeyPEM(t *testing.T) ([]byte, ssh.Signer) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(private, "ed-test")
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	return pem.EncodeToMemory(block), signer
}

func generateRSAKeyPEM(t *testing.T) ([]byte, ssh.Signer) {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(private, "rsa-test")
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	return pem.EncodeToMemory(block), signer
}

func writeScript(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "script.sh")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o700))
	return path
}

type testDaemon struct {
	mu       sync.RWMutex
	locked   bool
	allowSig bool
}

func (d *testDaemon) IsLocked() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.locked
}

func (d *testDaemon) CanSign(string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.allowSig {
		return true
	}
	return d.allowSig
}

func (d *testDaemon) setLocked(locked bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.locked = locked
}
