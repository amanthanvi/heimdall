package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/amanthanvi/heimdall/internal/app"
	auditpkg "github.com/amanthanvi/heimdall/internal/audit"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/metadata"
)

func TestAuditInterceptorMapsKeyExportToDomainAction(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createIdentity(t, h.store, "deploy")
	ctx := callerCtx(101, "proc-a")

	_, err := h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	_, err = h.key.ExportKey(ctx, &v1.ExportKeyRequest{Name: "deploy"})
	require.NoError(t, err)

	require.Equal(t, []string{
		auditpkg.ActionPassphraseReauth,
		auditpkg.ActionKeyExport,
	}, auditActions(t, h))
}

func TestAuditInterceptorMapsKeyGenerateAndImportToDomainActions(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	ctx := callerCtx(101, "proc-a")

	_, err := h.key.GenerateKey(ctx, &v1.GenerateKeyRequest{Name: "generated"})
	require.NoError(t, err)

	imported := testPrivateKeyPEM(t)
	_, err = h.key.ImportKey(ctx, &v1.ImportKeyRequest{
		Name:       "imported",
		PrivateKey: imported,
	})
	require.NoError(t, err)

	require.Equal(t, []string{
		auditpkg.ActionKeyGenerate,
		auditpkg.ActionKeyImport,
	}, auditActions(t, h))
}

func TestAuditInterceptorMapsHostUpdateToDomainAction(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createHost(t, h.store, "prod", "10.0.0.1", "ubuntu")
	ctx := callerCtx(101, "proc-a")

	_, err := h.host.UpdateHost(ctx, &v1.UpdateHostRequest{
		Name:    "prod",
		Address: "10.0.0.2",
		Tags:    []string{"prod"},
	})
	require.NoError(t, err)

	require.Equal(t, []string{
		auditpkg.ActionHostUpdate,
	}, auditActions(t, h))
}

func TestAuditInterceptorUsesMetadataOverrideForSecretValueReads(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createSecret(t, h.store, "api-token", []byte("super-secret"), app.RevealPolicyAlwaysReauth)
	ctx := callerCtx(101, "proc-a")

	_, err := h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	ctx = metadata.AppendToOutgoingContext(ctx, auditActionMetadataKey, auditpkg.ActionSecretExport)
	resp, err := h.secret.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: "api-token"})
	require.NoError(t, err)
	require.Equal(t, []byte("super-secret"), resp.GetValue())

	require.Equal(t, []string{
		auditpkg.ActionPassphraseReauth,
		auditpkg.ActionSecretExport,
	}, auditActions(t, h))
}

func TestAuditInterceptorFallsBackWhenSecretMetadataOverrideIsInvalid(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createSecret(t, h.store, "api-token", []byte("super-secret"), app.RevealPolicyAlwaysReauth)
	ctx := callerCtx(101, "proc-a")

	_, err := h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	ctx = metadata.AppendToOutgoingContext(ctx, auditActionMetadataKey, "totally.invalid")
	_, err = h.secret.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: "api-token"})
	require.NoError(t, err)

	require.Equal(t, []string{
		auditpkg.ActionPassphraseReauth,
		"grpc.secretservice.getsecretvalue",
	}, auditActions(t, h))
}

func TestAuditInterceptorSkipsDuplicateSessionAndReauthEvents(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createHost(t, h.store, "prod", "10.0.0.1", "ubuntu")
	host, err := h.store.Hosts.Get(context.Background(), "prod")
	require.NoError(t, err)
	ctx := callerCtx(101, "proc-a")

	_, err = h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	_, err = h.session.RecordSessionStart(ctx, &v1.RecordSessionStartRequest{
		SessionId: "session-1",
		HostId:    host.ID,
		HostName:  host.Name,
		Address:   host.Address,
		User:      host.User,
		KeyName:   "deploy",
	})
	require.NoError(t, err)

	_, err = h.session.RecordSessionEnd(ctx, &v1.RecordSessionEndRequest{
		SessionId: "session-1",
		HostId:    host.ID,
		ExitCode:  0,
	})
	require.NoError(t, err)

	require.Equal(t, []string{
		auditpkg.ActionPassphraseReauth,
		auditpkg.ActionConnectStart,
		auditpkg.ActionConnectEnd,
	}, auditActions(t, h))
}

func TestAuditInterceptorSkipsReadOnlyLookupMethods(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createHost(t, h.store, "prod", "10.0.0.1", "ubuntu")
	createIdentity(t, h.store, "deploy")
	ctx := callerCtx(101, "proc-a")
	auditClient := v1.NewAuditServiceClient(h.conn)

	_, err := h.host.GetHost(ctx, &v1.GetHostRequest{Name: "prod"})
	require.NoError(t, err)

	_, err = h.host.ListHosts(ctx, &v1.ListHostsRequest{})
	require.NoError(t, err)

	_, err = h.key.ListKeys(ctx, &v1.ListKeysRequest{})
	require.NoError(t, err)

	_, err = h.key.ShowKey(ctx, &v1.ShowKeyRequest{Name: "deploy"})
	require.NoError(t, err)

	_, err = h.connect.Plan(ctx, &v1.PlanConnectRequest{HostName: "prod"})
	require.NoError(t, err)

	_, err = auditClient.VerifyChain(ctx, &v1.VerifyChainRequest{})
	require.NoError(t, err)

	_, err = auditClient.ListEvents(ctx, &v1.ListEventsRequest{})
	require.NoError(t, err)

	require.Empty(t, auditActions(t, h))
}

func auditActions(t *testing.T, h *grpcHarness) []string {
	t.Helper()

	events, err := h.audit.List(context.Background(), auditpkg.Filter{})
	require.NoError(t, err)

	actions := make([]string, 0, len(events))
	for _, event := range events {
		actions = append(actions, event.Action)
	}
	return actions
}

func testPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	block, err := ssh.MarshalPrivateKey(privateKey, "imported")
	require.NoError(t, err)
	return pemBytes(t, block)
}

func pemBytes(t *testing.T, block *pem.Block) []byte {
	t.Helper()
	return pem.EncodeToMemory(block)
}
