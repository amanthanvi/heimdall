package inventory

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/openssh"
)

type guardFS struct {
	files map[string][]byte
	stats map[string]fs.FileInfo
	reads []string
}

func (g *guardFS) ReadPublicFile(path string) ([]byte, error) {
	g.reads = append(g.reads, filepath.Base(path))
	if LooksPrivateKeyPath(path) {
		return nil, ErrPrivateKeyRead
	}
	data, ok := g.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func (g *guardFS) Stat(path string) (fs.FileInfo, error) {
	info, ok := g.stats[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return info, nil
}

func (g *guardFS) Glob(pattern string) ([]string, error) { return nil, nil }

func TestInventoryDoesNotReadPrivateKeyRef(t *testing.T) {
	pub := filepath.Join(t.TempDir(), "id_ed25519.pub")
	priv := filepath.Join(filepath.Dir(pub), "id_ed25519")
	fs := &guardFS{files: map[string][]byte{pub: []byte("ssh-ed25519 AAA test\n")}}
	runner := &openssh.FakeRunner{Results: map[string]openssh.Result{
		openssh.CommandKey("ssh-keygen", []string{"-l", "-f", pub}): {Stdout: "256 SHA256:abc test (ED25519)\n"},
		openssh.CommandKey("ssh-add", []string{"-l"}):               {Stdout: "256 SHA256:abc test (ED25519)\n"},
	}}
	cfg := model.Config{
		Version:    model.ConfigVersion,
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"personal": {Kind: "openssh", Socket: "env:SSH_AUTH_SOCK"}}},
		Identities: map[string]model.Identity{"id": {PublicKeyPath: pub, PrivateKeyPathRef: priv, AgentSelector: "personal"}},
	}
	_, err := Scanner{FS: fs, Runner: runner, Now: func() time.Time { return time.Unix(0, 0) }}.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, read := range fs.reads {
		if read == "id_ed25519" {
			t.Fatal("private key reference was read")
		}
	}
}

func TestParseSSHAddList(t *testing.T) {
	got := ParseSSHAddList("256 SHA256:abc user@example (ED25519)\n")
	if len(got) != 1 || got[0].Fingerprint != "SHA256:abc" || got[0].Type != "ED25519" {
		t.Fatalf("unexpected parse: %#v", got)
	}
}

func TestLooksPrivateKeyPath(t *testing.T) {
	if !LooksPrivateKeyPath("/tmp/id_ed25519") {
		t.Fatal("expected private-looking key path")
	}
	if LooksPrivateKeyPath("/tmp/id_ed25519.pub") {
		t.Fatal("public key path classified private")
	}
}

func ExampleParseKeygenFingerprint() {
	fp, typ, comment := ParseKeygenFingerprint("256 SHA256:abc user@example (ED25519)")
	fmt.Println(fp, typ, comment)
	// Output: SHA256:abc ED25519 user@example
}
