package inventory

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/athanvi/heimdall/internal/certs"
	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/openssh"
)

type FileSystem interface {
	ReadPublicFile(path string) ([]byte, error)
	Stat(path string) (fs.FileInfo, error)
	Glob(pattern string) ([]string, error)
}

type OSFileSystem struct{}

func (OSFileSystem) ReadPublicFile(path string) ([]byte, error) {
	if LooksPrivateKeyPath(path) {
		return nil, fmt.Errorf("refusing to read private key-looking path %q", path)
	}
	return os.ReadFile(path)
}

func (OSFileSystem) Stat(path string) (fs.FileInfo, error) {
	return os.Stat(path)
}

func (OSFileSystem) Glob(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}

type Scanner struct {
	FS     FileSystem
	Runner openssh.Runner
	Now    func() time.Time
}

func (s Scanner) Scan(ctx context.Context, cfg model.Config) (model.Inventory, error) {
	fs := s.FS
	if fs == nil {
		fs = OSFileSystem{}
	}
	runner := s.Runner
	if runner == nil {
		runner = openssh.ExecRunner{}
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	inv := model.Inventory{SSHAuthSock: os.Getenv("SSH_AUTH_SOCK")}
	for name, identity := range cfg.Identities {
		inv.Identities = append(inv.Identities, scanConfiguredIdentity(ctx, fs, runner, name, identity))
		if identity.CertificatePath != "" {
			inv.Certificates = append(inv.Certificates, certs.Inspect(ctx, runner, identity.CertificatePath, now()))
		}
	}
	for name, certRef := range cfg.Certificates {
		cert := certs.Inspect(ctx, runner, certRef.Path, now())
		if cert.KeyID == "" {
			cert.KeyID = name
		}
		inv.Certificates = append(inv.Certificates, cert)
	}
	for name, selector := range cfg.Agents.Selectors {
		inv.Agents = append(inv.Agents, scanAgent(ctx, runner, name, selector, now()))
	}
	return inv, nil
}

func ScanPublicKeys(ctx context.Context, fsys FileSystem, runner openssh.Runner, dir string) []model.IdentitySource {
	if fsys == nil {
		fsys = OSFileSystem{}
	}
	if runner == nil {
		runner = openssh.ExecRunner{}
	}
	matches, err := fsys.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return []model.IdentitySource{{Error: err.Error()}}
	}
	out := []model.IdentitySource{}
	for _, path := range matches {
		if strings.HasSuffix(path, "-cert.pub") {
			continue
		}
		out = append(out, inspectPublicKey(ctx, fsys, runner, filepath.Base(strings.TrimSuffix(path, ".pub")), path))
	}
	return out
}

func scanConfiguredIdentity(ctx context.Context, fsys FileSystem, runner openssh.Runner, name string, identity model.Identity) model.IdentitySource {
	if identity.PublicKeyPath == "" {
		return model.IdentitySource{Name: name, Error: "missing public_key_path"}
	}
	path := ExpandPath(identity.PublicKeyPath)
	return inspectPublicKey(ctx, fsys, runner, name, path)
}

func inspectPublicKey(ctx context.Context, fsys FileSystem, runner openssh.Runner, name, path string) model.IdentitySource {
	src := model.IdentitySource{Name: name, PublicKeyPath: path}
	if _, err := fsys.ReadPublicFile(path); err != nil {
		src.Error = err.Error()
		return src
	}
	res, err := runner.Run(ctx, "ssh-keygen", []string{"-l", "-f", path})
	if err != nil {
		src.Error = strings.TrimSpace(res.Stderr)
		if src.Error == "" {
			src.Error = err.Error()
		}
		return src
	}
	fp, typ, comment := ParseKeygenFingerprint(res.Stdout)
	src.Fingerprint = fp
	src.KeyType = typ
	src.Comment = comment
	return src
}

func scanAgent(ctx context.Context, runner openssh.Runner, name string, selector model.AgentSelector, now time.Time) model.Agent {
	agent := model.Agent{Name: name, Kind: selector.Kind, Endpoint: ResolveEndpoint(selector), ObservedAt: now}
	if selector.Kind == "windows_openssh" {
		agent.Live = selector.Pipe != ""
		agent.Error = "windows agent identity listing requires Windows OpenSSH environment"
		return agent
	}
	if selector.Kind == "bridge" {
		agent.Error = "bridge agent endpoints are session-scoped and not inventoried passively"
		return agent
	}
	res, err := runner.Run(ctx, "ssh-add", []string{"-l"})
	if err != nil {
		agent.Error = firstNonEmpty(strings.TrimSpace(res.Stderr), err.Error())
		return agent
	}
	agent.Live = true
	agent.Identities = ParseSSHAddList(res.Stdout)
	if len(agent.Identities) == 0 && strings.Contains(strings.ToLower(res.Stdout+res.Stderr), "no identities") {
		agent.Live = true
	}
	return agent
}

func ResolveEndpoint(selector model.AgentSelector) string {
	switch {
	case strings.HasPrefix(selector.Socket, "env:"):
		return os.Getenv(strings.TrimPrefix(selector.Socket, "env:"))
	case selector.Socket != "":
		return ExpandPath(selector.Socket)
	case selector.Pipe != "":
		return selector.Pipe
	default:
		return ""
	}
}

func ParseKeygenFingerprint(line string) (fingerprint, keyType, comment string) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) >= 2 {
		fingerprint = fields[1]
	}
	if len(fields) >= 4 {
		keyType = strings.Trim(fields[len(fields)-1], "()")
		comment = strings.Join(fields[2:len(fields)-1], " ")
	} else if len(fields) >= 3 {
		comment = fields[2]
	}
	return fingerprint, keyType, strings.Trim(comment, "()")
}

func ParseSSHAddList(output string) []model.AgentIdentity {
	scanner := bufio.NewScanner(strings.NewReader(output))
	var out []model.AgentIdentity
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(strings.ToLower(line), "no identities") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		id := model.AgentIdentity{Fingerprint: fields[1]}
		if len(fields) >= 4 {
			id.Type = strings.Trim(fields[len(fields)-1], "()")
			id.Comment = strings.Join(fields[2:len(fields)-1], " ")
		}
		out = append(out, id)
	}
	return out
}

func LooksPrivateKeyPath(path string) bool {
	base := filepath.Base(path)
	if strings.HasSuffix(base, ".pub") || strings.HasSuffix(base, "-cert.pub") {
		return false
	}
	privateNames := []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity"}
	for _, name := range privateNames {
		if base == name || strings.HasPrefix(base, name+"_") {
			return true
		}
	}
	return false
}

func CheckPrivateKeyReference(fsys FileSystem, path string) error {
	if path == "" {
		return nil
	}
	if fsys == nil {
		fsys = OSFileSystem{}
	}
	info, err := fsys.Stat(ExpandPath(path))
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key reference has broad permissions %s", info.Mode().Perm())
	}
	return nil
}

func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return os.ExpandEnv(path)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

var ErrPrivateKeyRead = errors.New("private key content read refused")
