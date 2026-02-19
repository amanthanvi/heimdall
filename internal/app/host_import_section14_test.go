package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSSHConfigImportBasicHostBlock(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	configPath := writeSSHConfigFixture(t, `
Host prod
  HostName 10.0.0.10
  User ubuntu
  Port 2222
`)

	svc := NewHostService(store.Hosts, store.Sessions)
	imported, warnings, err := svc.Import(context.Background(), configPath)
	require.NoError(t, err)
	require.Empty(t, warnings)
	require.Len(t, imported, 1)
	require.Equal(t, "prod", imported[0].Name)
	require.Equal(t, "10.0.0.10", imported[0].Address)
	require.Equal(t, "ubuntu", imported[0].User)
	require.Equal(t, 2222, imported[0].Port)
}

func TestSSHConfigImportProxyJumpDirectiveMapped(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	configPath := writeSSHConfigFixture(t, `
Host app
  HostName app.internal
  User deploy
  ProxyJump bastion.internal
`)

	svc := NewHostService(store.Hosts, store.Sessions)
	imported, warnings, err := svc.Import(context.Background(), configPath)
	require.NoError(t, err)
	require.Empty(t, warnings)
	require.Len(t, imported, 1)
	require.Equal(t, "bastion.internal", imported[0].EnvRefs["proxy_jump"])
}

func TestSSHConfigImportIdentityFileDirectiveMappedToIdentityRef(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	configPath := writeSSHConfigFixture(t, `
Host db
  HostName db.internal
  IdentityFile ~/.ssh/id_db
`)

	svc := NewHostService(store.Hosts, store.Sessions)
	imported, warnings, err := svc.Import(context.Background(), configPath)
	require.NoError(t, err)
	require.Empty(t, warnings)
	require.Len(t, imported, 1)
	require.Equal(t, "~/.ssh/id_db", imported[0].EnvRefs["identity_ref"])
}

func TestSSHConfigImportMultipleHostBlocks(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	configPath := writeSSHConfigFixture(t, `
Host web
  HostName web.internal
  User ubuntu

Host cache
  HostName cache.internal
  User redis
`)

	svc := NewHostService(store.Hosts, store.Sessions)
	imported, warnings, err := svc.Import(context.Background(), configPath)
	require.NoError(t, err)
	require.Empty(t, warnings)
	require.Len(t, imported, 2)
	require.Equal(t, "web", imported[0].Name)
	require.Equal(t, "cache", imported[1].Name)
}

func TestSSHConfigImportMatchDirectiveWarning(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	configPath := writeSSHConfigFixture(t, `
Match exec "test -f /etc/hosts"
Host api
  HostName api.internal
`)

	svc := NewHostService(store.Hosts, store.Sessions)
	_, warnings, err := svc.Import(context.Background(), configPath)
	require.NoError(t, err)
	require.NotEmpty(t, warnings)
	require.Contains(t, strings.ToLower(warnings[0].Message), "match")
	require.Contains(t, strings.ToLower(warnings[0].Message), "skipped")
}

func TestSSHConfigImportIncludeDirectiveWarning(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	configPath := writeSSHConfigFixture(t, `
Include ~/.ssh/config.d/*
Host worker
  HostName worker.internal
`)

	svc := NewHostService(store.Hosts, store.Sessions)
	_, warnings, err := svc.Import(context.Background(), configPath)
	require.NoError(t, err)
	require.NotEmpty(t, warnings)
	require.Contains(t, strings.ToLower(warnings[0].Message), "include")
	require.Contains(t, strings.ToLower(warnings[0].Message), "skipped")
}

func TestSSHConfigImportWildcardHostSkippedWithInfo(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	configPath := writeSSHConfigFixture(t, `
Host *
  ForwardAgent yes
Host jump
  HostName jump.internal
`)

	svc := NewHostService(store.Hosts, store.Sessions)
	imported, warnings, err := svc.Import(context.Background(), configPath)
	require.NoError(t, err)
	require.Len(t, imported, 1)
	require.Equal(t, "jump", imported[0].Name)
	require.NotEmpty(t, warnings)
	require.Contains(t, strings.ToLower(warnings[0].Message), "wildcard")
}

func writeSSHConfigFixture(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ssh_config")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}
