package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostCreateAfterSoftDeleteReusesName(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	original := &Host{
		Name:    "prod",
		Address: "10.0.0.10",
		Port:    22,
		User:    "root",
		Tags:    []string{"old"},
	}
	require.NoError(t, store.Hosts.Create(ctx, original))
	require.NoError(t, store.Hosts.Delete(ctx, original.Name))

	recreated := &Host{
		Name:    "prod",
		Address: "10.0.0.11",
		Port:    2222,
		User:    "ubuntu",
		Tags:    []string{"new", "audit"},
	}
	require.NoError(t, store.Hosts.Create(ctx, recreated))

	loaded, err := store.Hosts.Get(ctx, "prod")
	require.NoError(t, err)
	require.Equal(t, recreated.Address, loaded.Address)
	require.Equal(t, recreated.Port, loaded.Port)
	require.Equal(t, recreated.User, loaded.User)
	require.ElementsMatch(t, recreated.Tags, loaded.Tags)
	require.Nil(t, loaded.DeletedAt)
}

func TestIdentityCreateAfterSoftDeleteReusesName(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	original := &Identity{
		Name:       "deploy",
		Kind:       "ed25519",
		PublicKey:  "ssh-ed25519 AAA-original",
		PrivateKey: []byte("private-original"),
		Status:     IdentityStatusActive,
	}
	require.NoError(t, store.Identities.Create(ctx, original))
	require.NoError(t, store.Identities.Delete(ctx, original.Name))

	recreated := &Identity{
		Name:       "deploy",
		Kind:       "ed25519",
		PublicKey:  "ssh-ed25519 AAA-recreated",
		PrivateKey: []byte("private-recreated"),
		Status:     IdentityStatusActive,
	}
	require.NoError(t, store.Identities.Create(ctx, recreated))

	loaded, err := store.Identities.Get(ctx, "deploy")
	require.NoError(t, err)
	require.Equal(t, recreated.PublicKey, loaded.PublicKey)
	require.Equal(t, recreated.PrivateKey, loaded.PrivateKey)
	require.Equal(t, recreated.Status, loaded.Status)
	require.Nil(t, loaded.DeletedAt)
}

func TestSecretCreateAfterSoftDeleteReusesName(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	original := &Secret{Name: "api-token", Value: []byte("old-secret")}
	require.NoError(t, store.Secrets.Create(ctx, original))
	require.NoError(t, store.Secrets.Delete(ctx, original.Name))

	recreated := &Secret{Name: "api-token", Value: []byte("new-secret")}
	require.NoError(t, store.Secrets.Create(ctx, recreated))

	loaded, err := store.Secrets.Get(ctx, "api-token")
	require.NoError(t, err)
	require.Equal(t, []byte("new-secret"), loaded.Value)
	require.Nil(t, loaded.DeletedAt)
}

func TestPasskeyCreateAfterSoftDeleteReusesLabel(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	original := &PasskeyEnrollment{
		Label:              "token",
		CredentialID:       []byte{0x01},
		PublicKeyCOSE:      []byte{0x02},
		AAGUID:             []byte{0x03},
		SupportsHMACSecret: true,
	}
	require.NoError(t, store.Passkeys.Create(ctx, original))
	require.NoError(t, store.Passkeys.Delete(ctx, original.Label))

	recreated := &PasskeyEnrollment{
		Label:              "token",
		CredentialID:       []byte{0x11},
		PublicKeyCOSE:      []byte{0x12},
		AAGUID:             []byte{0x13},
		SupportsHMACSecret: false,
	}
	require.NoError(t, store.Passkeys.Create(ctx, recreated))

	loaded, err := store.Passkeys.GetByLabel(ctx, "token")
	require.NoError(t, err)
	require.Equal(t, recreated.CredentialID, loaded.CredentialID)
	require.Equal(t, recreated.PublicKeyCOSE, loaded.PublicKeyCOSE)
	require.Equal(t, recreated.SupportsHMACSecret, loaded.SupportsHMACSecret)
	require.Nil(t, loaded.DeletedAt)
}
