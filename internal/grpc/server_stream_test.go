package grpc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	auditpkg "github.com/amanthanvi/heimdall/internal/audit"
	"github.com/stretchr/testify/require"
)

func TestSessionServiceRecordStartAndEndCreatesAuditTrail(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createHost(t, h.store, "prod", "10.0.0.1", "ubuntu")
	host, err := h.store.Hosts.Get(context.Background(), "prod")
	require.NoError(t, err)

	ctx := callerCtx(909, "proc-session")
	startResp, err := h.session.RecordSessionStart(ctx, &v1.RecordSessionStartRequest{HostId: host.ID})
	require.NoError(t, err)
	require.NotEmpty(t, startResp.GetSessionId())

	_, err = h.session.RecordSessionEnd(ctx, &v1.RecordSessionEndRequest{SessionId: startResp.GetSessionId(), ExitCode: 23})
	require.NoError(t, err)

	records, err := h.store.Sessions.ListByHostID(context.Background(), host.ID)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.NotNil(t, records[0].EndedAt)
	require.NotNil(t, records[0].ExitCode)
	require.Equal(t, 23, *records[0].ExitCode)

	events, err := h.audit.List(context.Background(), auditpkg.Filter{Action: auditpkg.ActionConnectStart, Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)

	events, err = h.audit.List(context.Background(), auditpkg.Filter{Action: auditpkg.ActionConnectEnd, Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)
}

func TestClientLibraryWrapsAllServiceClients(t *testing.T) {
	h := newGRPCHarness(t)
	baseDir, err := os.MkdirTemp("/tmp", "hd-grpc-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(baseDir) })
	tempSocket := filepath.Join(baseDir, "daemon.sock")
	lis, err := net.Listen("unix", tempSocket)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("unix socket bind unavailable in sandbox: %v", err)
		}
		require.NoError(t, err)
	}
	srv := h.server.GRPCServer()
	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})

	client, err := NewClient(tempSocket)
	require.NoError(t, err)
	require.NotNil(t, client.Vault)
	require.NotNil(t, client.Version)
	require.NotNil(t, client.Host)
	require.NotNil(t, client.Secret)
	require.NotNil(t, client.Key)
	require.NotNil(t, client.Passkey)
	require.NotNil(t, client.Connect)
	require.NotNil(t, client.Audit)
	require.NotNil(t, client.Backup)
	require.NotNil(t, client.Session)
	require.NotNil(t, client.Reauth)
	require.NoError(t, client.Close())
}
