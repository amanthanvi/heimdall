package app

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/stretchr/testify/require"
)

func TestJSONExportVersionedFormatIncludesMetadataCollections(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()
	seedTransferFixture(t, store)

	svc := NewTransferService(store)
	payload, err := svc.ExportJSON(context.Background())
	require.NoError(t, err)

	var bundle ExportBundle
	require.NoError(t, json.Unmarshal(payload, &bundle))
	require.Equal(t, 1, bundle.Version)
	require.NotEmpty(t, bundle.Hosts)
	require.NotEmpty(t, bundle.Identities)
	require.NotEmpty(t, bundle.Secrets)
}

func TestJSONExportOmitsEncryptedValues(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()
	seedTransferFixture(t, store)

	svc := NewTransferService(store)
	payload, err := svc.ExportJSON(context.Background())
	require.NoError(t, err)
	require.NotContains(t, string(payload), "ultra-secret-value")
	require.NotContains(t, string(payload), "value_ciphertext")
}

func TestJSONImportValidFormatCreatesEntities(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	bundle := ExportBundle{
		Version: 1,
		Hosts: []ExportHost{{
			Name:    "prod",
			Address: "10.0.0.20",
			Port:    22,
			User:    "ubuntu",
		}},
		Identities: []ExportIdentity{{
			Name:      "deploy-key",
			Kind:      "ed25519",
			PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyComment",
		}},
		Secrets: []ExportSecret{{
			Name:      "api-token",
			SizeBytes: 16,
		}},
	}
	data, err := json.Marshal(bundle)
	require.NoError(t, err)

	svc := NewTransferService(store)
	result, err := svc.ImportJSON(context.Background(), data, ConflictModeSkip)
	require.NoError(t, err)
	require.Equal(t, 1, result.Hosts.Created)
	require.Equal(t, 1, result.Identities.Created)
	require.Equal(t, 1, result.Secrets.Created)

	host, err := store.Hosts.Get(context.Background(), "prod")
	require.NoError(t, err)
	require.Equal(t, "10.0.0.20", host.Address)

	_, err = store.Identities.Get(context.Background(), "deploy-key")
	require.NoError(t, err)

	secret, err := store.Secrets.Get(context.Background(), "api-token")
	require.NoError(t, err)
	require.Len(t, secret.Value, 16)
}

func TestJSONImportConflictResolutionSkipOverwriteRename(t *testing.T) {
	t.Parallel()

	t.Run("skip", func(t *testing.T) {
		t.Parallel()

		store, vmk := newAppTestStore(t)
		defer vmk.Destroy()

		hostSvc := NewHostService(store.Hosts, store.Sessions)
		_, err := hostSvc.Create(context.Background(), CreateHostRequest{
			Name:    "prod",
			Address: "10.0.0.1",
		})
		require.NoError(t, err)

		data := mustMarshalBundle(t, ExportBundle{
			Version: 1,
			Hosts: []ExportHost{{
				Name:    "prod",
				Address: "10.0.0.99",
				Port:    22,
			}},
		})
		svc := NewTransferService(store)
		result, err := svc.ImportJSON(context.Background(), data, ConflictModeSkip)
		require.NoError(t, err)
		require.Equal(t, 1, result.Hosts.Skipped)

		host, err := store.Hosts.Get(context.Background(), "prod")
		require.NoError(t, err)
		require.Equal(t, "10.0.0.1", host.Address)
	})

	t.Run("overwrite", func(t *testing.T) {
		t.Parallel()

		store, vmk := newAppTestStore(t)
		defer vmk.Destroy()

		hostSvc := NewHostService(store.Hosts, store.Sessions)
		_, err := hostSvc.Create(context.Background(), CreateHostRequest{
			Name:    "prod",
			Address: "10.0.0.1",
		})
		require.NoError(t, err)

		data := mustMarshalBundle(t, ExportBundle{
			Version: 1,
			Hosts: []ExportHost{{
				Name:    "prod",
				Address: "10.0.0.99",
				Port:    22,
			}},
		})
		svc := NewTransferService(store)
		result, err := svc.ImportJSON(context.Background(), data, ConflictModeOverwrite)
		require.NoError(t, err)
		require.Equal(t, 1, result.Hosts.Updated)

		host, err := store.Hosts.Get(context.Background(), "prod")
		require.NoError(t, err)
		require.Equal(t, "10.0.0.99", host.Address)
	})

	t.Run("rename", func(t *testing.T) {
		t.Parallel()

		store, vmk := newAppTestStore(t)
		defer vmk.Destroy()

		hostSvc := NewHostService(store.Hosts, store.Sessions)
		_, err := hostSvc.Create(context.Background(), CreateHostRequest{
			Name:    "prod",
			Address: "10.0.0.1",
		})
		require.NoError(t, err)

		data := mustMarshalBundle(t, ExportBundle{
			Version: 1,
			Hosts: []ExportHost{{
				Name:    "prod",
				Address: "10.0.0.99",
				Port:    22,
			}},
		})
		svc := NewTransferService(store)
		result, err := svc.ImportJSON(context.Background(), data, ConflictModeRename)
		require.NoError(t, err)
		require.Equal(t, 1, result.Hosts.Created)

		_, err = store.Hosts.Get(context.Background(), "prod")
		require.NoError(t, err)

		renamed, err := store.Hosts.Get(context.Background(), "prod-imported-1")
		require.NoError(t, err)
		require.Equal(t, "10.0.0.99", renamed.Address)
	})
}

func TestJSONImportRoundTripEquivalent(t *testing.T) {
	t.Parallel()

	sourceStore, sourceVMK := newAppTestStore(t)
	defer sourceVMK.Destroy()
	seedTransferFixture(t, sourceStore)

	sourceSvc := NewTransferService(sourceStore)
	exported, err := sourceSvc.ExportJSON(context.Background())
	require.NoError(t, err)

	targetStore, targetVMK := newAppTestStore(t)
	defer targetVMK.Destroy()

	targetSvc := NewTransferService(targetStore)
	_, err = targetSvc.ImportJSON(context.Background(), exported, ConflictModeOverwrite)
	require.NoError(t, err)

	exportedAgain, err := targetSvc.ExportJSON(context.Background())
	require.NoError(t, err)

	var want ExportBundle
	var got ExportBundle
	require.NoError(t, json.Unmarshal(exported, &want))
	require.NoError(t, json.Unmarshal(exportedAgain, &got))
	require.Equal(t, want, got)
}

func seedTransferFixture(t *testing.T, store *storage.Store) {
	t.Helper()

	ctx := context.Background()
	hostSvc := NewHostService(store.Hosts, store.Sessions)
	_, err := hostSvc.Create(ctx, CreateHostRequest{
		Name:    "prod",
		Address: "10.0.0.1",
		Port:    2222,
		User:    "ubuntu",
		Tags:    []string{"prod", "api"},
		EnvRefs: map[string]string{"identity_ref": "~/.ssh/id_prod"},
	})
	require.NoError(t, err)

	keySvc := NewKeyService(store.Identities)
	_, err = keySvc.Generate(ctx, GenerateKeyRequest{Name: "deploy", Type: KeyTypeEd25519})
	require.NoError(t, err)

	secretSvc := NewSecretService(store.Secrets)
	_, err = secretSvc.Create(ctx, CreateSecretRequest{
		Name:  "token",
		Value: []byte("ultra-secret-value"),
	})
	require.NoError(t, err)
}

func mustMarshalBundle(t *testing.T, bundle ExportBundle) []byte {
	t.Helper()

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}
