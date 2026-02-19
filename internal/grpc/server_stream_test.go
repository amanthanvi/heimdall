package grpc

import (
	"bytes"
	"context"
	"io"
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

	events, err := h.audit.List(context.Background(), auditpkg.Filter{Action: "session.start", Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)

	events, err = h.audit.List(context.Background(), auditpkg.Filter{Action: "session.end", Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)
}

func TestStreamingUploadFileSecretHandles50MiB(t *testing.T) {
	h := newGRPCHarness(t)

	ctx := callerCtx(1001, "proc-upload")
	stream, err := h.secret.UploadFileSecret(ctx)
	require.NoError(t, err)

	payload := bytes.Repeat([]byte("a"), 50*1024*1024)
	chunkSize := 512 * 1024
	for offset := 0; offset < len(payload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		err := stream.Send(&v1.UploadChunk{
			Name: "large-secret",
			Data: payload[offset:end],
			Eof:  end == len(payload),
		})
		require.NoError(t, err)
	}
	resp, err := stream.CloseAndRecv()
	require.NoError(t, err)
	require.Equal(t, int64(len(payload)), resp.GetSecret().GetSizeBytes())

	stored, err := h.store.Secrets.Get(context.Background(), "large-secret")
	require.NoError(t, err)
	require.Equal(t, len(payload), len(stored.Value))
}

func TestStreamingDownloadFileSecretHandles50MiB(t *testing.T) {
	h := newGRPCHarness(t)
	payload := bytes.Repeat([]byte("b"), 50*1024*1024)
	createSecret(t, h.store, "large-secret", payload)

	ctx := callerCtx(1002, "proc-download")
	_, err := h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	stream, err := h.secret.DownloadFileSecret(ctx, &v1.DownloadRequest{Name: "large-secret", ChunkSize: 256 * 1024})
	require.NoError(t, err)

	var got bytes.Buffer
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		_, err = got.Write(chunk.GetData())
		require.NoError(t, err)
		if chunk.GetEof() {
			break
		}
	}
	require.Equal(t, payload, got.Bytes())
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
