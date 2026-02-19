package grpc

import (
	"context"
	"fmt"
	"net"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	grpcpkg "google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

const clientDialTimeout = 2 * time.Second

type Client struct {
	conn *grpcpkg.ClientConn

	Vault   v1.VaultServiceClient
	Version v1.VersionServiceClient
	Host    v1.HostServiceClient
	Secret  v1.SecretServiceClient
	Key     v1.KeyServiceClient
	Passkey v1.PasskeyServiceClient
	Connect v1.ConnectServiceClient
	Audit   v1.AuditServiceClient
	Backup  v1.BackupServiceClient
	Session v1.SessionServiceClient
	Reauth  v1.ReauthServiceClient
}

func NewClient(socketPath string) (*Client, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("new grpc client: socket path is required")
	}

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}

	conn, err := grpcpkg.NewClient(
		"unix:"+socketPath,
		grpcpkg.WithTransportCredentials(insecure.NewCredentials()),
		grpcpkg.WithContextDialer(dialer),
	)
	if err != nil {
		return nil, fmt.Errorf("new grpc client: create: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), clientDialTimeout)
	defer cancel()
	conn.Connect()
	for {
		s := conn.GetState()
		if s == connectivity.Ready {
			break
		}
		if !conn.WaitForStateChange(ctx, s) {
			_ = conn.Close()
			return nil, fmt.Errorf("new grpc client: dial: %w", ctx.Err())
		}
	}

	return &Client{
		conn:    conn,
		Vault:   v1.NewVaultServiceClient(conn),
		Version: v1.NewVersionServiceClient(conn),
		Host:    v1.NewHostServiceClient(conn),
		Secret:  v1.NewSecretServiceClient(conn),
		Key:     v1.NewKeyServiceClient(conn),
		Passkey: v1.NewPasskeyServiceClient(conn),
		Connect: v1.NewConnectServiceClient(conn),
		Audit:   v1.NewAuditServiceClient(conn),
		Backup:  v1.NewBackupServiceClient(conn),
		Session: v1.NewSessionServiceClient(conn),
		Reauth:  v1.NewReauthServiceClient(conn),
	}, nil
}

func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
