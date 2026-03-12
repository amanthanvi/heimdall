package grpc

import (
	"context"
	"testing"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	auditpkg "github.com/amanthanvi/heimdall/internal/audit"
	"github.com/stretchr/testify/require"
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
		auditpkg.ActionPasskeyReauth,
		auditpkg.ActionKeyExport,
	}, auditActions(t, h))
}

func TestAuditInterceptorUsesMetadataOverrideForSecretValueReads(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createSecret(t, h.store, "api-token", []byte("super-secret"))
	ctx := callerCtx(101, "proc-a")

	_, err := h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	ctx = metadata.AppendToOutgoingContext(ctx, auditActionMetadataKey, auditpkg.ActionSecretExport)
	resp, err := h.secret.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: "api-token"})
	require.NoError(t, err)
	require.Equal(t, []byte("super-secret"), resp.GetValue())

	require.Equal(t, []string{
		auditpkg.ActionPasskeyReauth,
		auditpkg.ActionSecretExport,
	}, auditActions(t, h))
}

func TestAuditInterceptorFallsBackWhenSecretMetadataOverrideIsInvalid(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createSecret(t, h.store, "api-token", []byte("super-secret"))
	ctx := callerCtx(101, "proc-a")

	_, err := h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	ctx = metadata.AppendToOutgoingContext(ctx, auditActionMetadataKey, "totally.invalid")
	_, err = h.secret.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: "api-token"})
	require.NoError(t, err)

	require.Equal(t, []string{
		auditpkg.ActionPasskeyReauth,
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
		auditpkg.ActionPasskeyReauth,
		auditpkg.ActionConnectStart,
		auditpkg.ActionConnectEnd,
	}, auditActions(t, h))
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
