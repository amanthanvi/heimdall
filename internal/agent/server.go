package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type DaemonState interface {
	IsLocked() bool
	CanSign(sessionID string) bool
}

type Identity struct {
	Name       string
	PrivateKey []byte
	SessionID  string
}

type AgentServer struct {
	daemon DaemonState

	mu       sync.RWMutex
	keys     map[string]*agentKey
	listener net.Listener

	socketPath string
	stopCh     chan struct{}
	wg         sync.WaitGroup
	now        func() time.Time

	execCommand func(ctx context.Context, name string, args ...string) *exec.Cmd
}

type agentKey struct {
	fingerprint string
	signer      ssh.Signer
	comment     string
	expiresAt   time.Time
	sessionID   string
	buffer      *memguard.LockedBuffer
}

func NewServer(daemon DaemonState) *AgentServer {
	return &AgentServer{
		daemon: daemon,
		keys:   map[string]*agentKey{},
		stopCh: make(chan struct{}),
		now:    func() time.Time { return time.Now().UTC() },
		execCommand: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, name, args...)
		},
	}
}

func (a *AgentServer) Start(socketPath string) error {
	if a == nil {
		return fmt.Errorf("start agent server: nil server")
	}
	if socketPath == "" {
		return fmt.Errorf("start agent server: empty socket path")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("start agent server: create socket dir: %w", err)
	}
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("start agent server: listen: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("start agent server: chmod socket: %w", err)
	}

	a.mu.Lock()
	a.listener = listener
	a.socketPath = socketPath
	a.mu.Unlock()

	a.wg.Add(2)
	go a.acceptLoop()
	go a.maintenanceLoop()
	return nil
}

func (a *AgentServer) Stop() error {
	if a == nil {
		return nil
	}
	select {
	case <-a.stopCh:
	default:
		close(a.stopCh)
	}

	a.mu.Lock()
	listener := a.listener
	socketPath := a.socketPath
	a.listener = nil
	a.mu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	a.wg.Wait()
	if socketPath != "" {
		_ = os.Remove(socketPath)
	}
	return a.RemoveAll()
}

func (a *AgentServer) AddKey(identity *Identity, ttl time.Duration) error {
	if identity == nil {
		return fmt.Errorf("add key: identity is nil")
	}
	if len(identity.PrivateKey) == 0 {
		return fmt.Errorf("add key: private key is empty")
	}

	raw := append([]byte(nil), identity.PrivateKey...)
	buffer := memguard.NewBufferFromBytes(raw)
	memguard.WipeBytes(raw)

	privateKey, err := ssh.ParseRawPrivateKey(identity.PrivateKey)
	if err != nil {
		buffer.Destroy()
		return fmt.Errorf("add key: parse private key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		buffer.Destroy()
		return fmt.Errorf("add key: create signer: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	entry := &agentKey{
		fingerprint: fingerprint,
		signer:      signer,
		comment:     identity.Name,
		sessionID:   identity.SessionID,
		buffer:      buffer,
	}
	if ttl > 0 {
		entry.expiresAt = a.now().Add(ttl)
	}

	a.mu.Lock()
	if existing, ok := a.keys[fingerprint]; ok {
		existing.destroy()
	}
	a.keys[fingerprint] = entry
	a.mu.Unlock()
	return nil
}

func (a *AgentServer) RemoveKey(fingerprint string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.keys[fingerprint]
	if !ok {
		return fmt.Errorf("remove key: %s not found", fingerprint)
	}
	entry.destroy()
	delete(a.keys, fingerprint)
	return nil
}

func (a *AgentServer) AddToExternalAgent(ctx context.Context, identity *Identity, ttl time.Duration) error {
	if identity == nil {
		return fmt.Errorf("external agent add: identity is nil")
	}
	if len(identity.PrivateKey) == 0 {
		return fmt.Errorf("external agent add: private key is empty")
	}

	tmpFile, err := os.CreateTemp("", "heimdall-agent-key-*")
	if err != nil {
		return fmt.Errorf("external agent add: create temp file: %w", err)
	}
	tempPath := tmpFile.Name()
	defer func() { _ = os.Remove(tempPath) }()

	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("external agent add: chmod temp file: %w", err)
	}
	if _, err := tmpFile.Write(identity.PrivateKey); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("external agent add: write temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("external agent add: close temp file: %w", err)
	}

	args := []string{}
	if ttl > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", int(ttl.Seconds())))
	}
	args = append(args, tempPath)

	cmd := a.execCommand(ctx, "ssh-add", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("external agent add: ssh-add: %w: %s", err, string(output))
	}
	return nil
}

func (a *AgentServer) List() ([]*sshagent.Key, error) {
	a.expireAndClearIfLocked()

	a.mu.RLock()
	defer a.mu.RUnlock()
	keys := make([]*sshagent.Key, 0, len(a.keys))
	for _, entry := range a.keys {
		pub := entry.signer.PublicKey()
		keys = append(keys, &sshagent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: entry.comment,
		})
	}
	return keys, nil
}

func (a *AgentServer) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	a.expireAndClearIfLocked()

	if key == nil {
		return nil, fmt.Errorf("sign: public key is nil")
	}

	fingerprint := ssh.FingerprintSHA256(key)
	a.mu.RLock()
	entry, ok := a.keys[fingerprint]
	a.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("sign: key not found")
	}

	if a.daemon != nil {
		if a.daemon.IsLocked() {
			return nil, fmt.Errorf("sign: vault is locked")
		}
		if !a.daemon.CanSign(entry.sessionID) {
			return nil, fmt.Errorf("sign: signing session expired")
		}
	}
	return entry.signer.Sign(rand.Reader, data)
}

func (a *AgentServer) Add(added sshagent.AddedKey) error {
	if added.PrivateKey == nil {
		return fmt.Errorf("add: private key is nil")
	}
	signer, err := ssh.NewSignerFromKey(added.PrivateKey)
	if err != nil {
		return fmt.Errorf("add: signer: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	entry := &agentKey{
		fingerprint: fingerprint,
		signer:      signer,
		comment:     added.Comment,
	}
	if added.LifetimeSecs > 0 {
		entry.expiresAt = a.now().Add(time.Duration(added.LifetimeSecs) * time.Second)
	}

	a.mu.Lock()
	if existing, ok := a.keys[fingerprint]; ok {
		existing.destroy()
	}
	a.keys[fingerprint] = entry
	a.mu.Unlock()
	return nil
}

func (a *AgentServer) Remove(key ssh.PublicKey) error {
	if key == nil {
		return fmt.Errorf("remove: key is nil")
	}
	return a.RemoveKey(ssh.FingerprintSHA256(key))
}

func (a *AgentServer) RemoveAll() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for fingerprint, entry := range a.keys {
		entry.destroy()
		delete(a.keys, fingerprint)
	}
	return nil
}

func (a *AgentServer) Lock(_ []byte) error {
	return a.RemoveAll()
}

func (a *AgentServer) Unlock(_ []byte) error {
	return nil
}

func (a *AgentServer) Signers() ([]ssh.Signer, error) {
	a.expireAndClearIfLocked()

	a.mu.RLock()
	defer a.mu.RUnlock()
	signers := make([]ssh.Signer, 0, len(a.keys))
	for _, entry := range a.keys {
		signers = append(signers, entry.signer)
	}
	return signers, nil
}

func (a *AgentServer) Extension(_ string, _ []byte) ([]byte, error) {
	return nil, sshagent.ErrExtensionUnsupported
}

func (a *AgentServer) acceptLoop() {
	defer a.wg.Done()

	for {
		select {
		case <-a.stopCh:
			return
		default:
		}

		a.mu.RLock()
		listener := a.listener
		a.mu.RUnlock()
		if listener == nil {
			return
		}

		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-a.stopCh:
				return
			default:
				continue
			}
		}

		a.wg.Add(1)
		go func(c net.Conn) {
			defer a.wg.Done()
			defer c.Close()
			_ = sshagent.ServeAgent(a, c)
		}(conn)
	}
}

func (a *AgentServer) maintenanceLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.expireAndClearIfLocked()
		}
	}
}

func (a *AgentServer) expireAndClearIfLocked() {
	if a.daemon != nil && a.daemon.IsLocked() {
		_ = a.RemoveAll()
		return
	}

	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for fingerprint, entry := range a.keys {
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			entry.destroy()
			delete(a.keys, fingerprint)
		}
	}
}

func (k *agentKey) destroy() {
	if k == nil {
		return
	}
	if k.buffer != nil && k.buffer.IsAlive() {
		k.buffer.Destroy()
	}
	k.signer = nil
}
