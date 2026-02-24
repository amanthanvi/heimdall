package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	tuipkg "github.com/amanthanvi/heimdall/internal/tui"
	"github.com/spf13/cobra"
)

const defaultTUIRevealTTL = 10 * time.Second

func newTUICommand(deps commandDeps) *cobra.Command {
	revealTTL := defaultTUIRevealTTL
	cmd := &cobra.Command{
		Use:     "tui",
		Aliases: []string{"ui"},
		Short:   "Launch interactive terminal UI",
		Example: "  heimdall tui\n" +
			"  heimdall ui --reveal-ttl 15s",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("tui does not accept positional arguments")
			}
			if deps.globals.JSON {
				return usageErrorf("tui does not support --json")
			}
			if !isTTYSession() {
				return usageErrorf("tui requires an interactive terminal (TTY)")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				timeout := 10 * time.Second
				if deps.globals != nil && deps.globals.Timeout > 0 {
					timeout = deps.globals.Timeout
				}
				return tuipkg.Run(tuipkg.Options{
					Client: &grpcTUIClient{
						clients: clients,
						timeout: timeout,
					},
					RevealTTL: revealTTL,
					IsTTY: func() bool {
						return true
					},
				})
			})
		},
	}
	cmd.Flags().DurationVar(&revealTTL, "reveal-ttl", defaultTUIRevealTTL, "How long revealed secrets remain visible")
	return cmd
}

type grpcTUIClient struct {
	clients daemonClients
	timeout time.Duration
}

func (c *grpcTUIClient) Status(ctx context.Context) (bool, error) {
	callCtx, cancel := c.rpcContext(ctx)
	defer cancel()
	resp, err := c.clients.vault.Status(callCtx, &v1.StatusRequest{})
	if err != nil {
		return false, err
	}
	return resp.GetLocked(), nil
}

func (c *grpcTUIClient) Unlock(ctx context.Context, passphrase string) error {
	callCtx, cancel := c.rpcContext(ctx)
	defer cancel()
	_, err := c.clients.vault.Unlock(callCtx, &v1.UnlockRequest{
		Passphrase: strings.TrimSpace(passphrase),
	})
	return err
}

func (c *grpcTUIClient) Reauth(ctx context.Context, passphrase string) error {
	callCtx, cancel := c.rpcContext(ctx)
	defer cancel()
	if c.clients.reauth == nil {
		return fmt.Errorf("tui: re-auth service is not available")
	}
	_, err := c.clients.reauth.VerifyPassphrase(callCtx, &v1.VerifyPassphraseRequest{
		Passphrase: strings.TrimSpace(passphrase),
	})
	return err
}

func (c *grpcTUIClient) ListHosts(ctx context.Context) ([]tuipkg.Host, error) {
	callCtx, cancel := c.rpcContext(ctx)
	defer cancel()
	resp, err := c.clients.host.ListHosts(callCtx, &v1.ListHostsRequest{})
	if err != nil {
		return nil, err
	}
	hosts := make([]tuipkg.Host, 0, len(resp.GetHosts()))
	for _, host := range resp.GetHosts() {
		hosts = append(hosts, tuipkg.Host{
			Name:    host.GetName(),
			Address: host.GetAddress(),
			User:    host.GetUser(),
			Port:    int(host.GetPort()),
			Tags:    append([]string(nil), host.GetTags()...),
		})
	}
	return hosts, nil
}

func (c *grpcTUIClient) ListSecrets(ctx context.Context) ([]tuipkg.Secret, error) {
	callCtx, cancel := c.rpcContext(ctx)
	defer cancel()
	resp, err := c.clients.secret.ListSecrets(callCtx, &v1.ListSecretsRequest{})
	if err != nil {
		return nil, err
	}
	secrets := make([]tuipkg.Secret, 0, len(resp.GetSecrets()))
	for _, secret := range resp.GetSecrets() {
		secrets = append(secrets, tuipkg.Secret{Name: secret.GetName()})
	}
	return secrets, nil
}

func (c *grpcTUIClient) ListKeys(ctx context.Context) ([]tuipkg.Key, error) {
	callCtx, cancel := c.rpcContext(ctx)
	defer cancel()
	resp, err := c.clients.key.ListKeys(callCtx, &v1.ListKeysRequest{})
	if err != nil {
		return nil, err
	}
	keys := make([]tuipkg.Key, 0, len(resp.GetKeys()))
	for _, key := range resp.GetKeys() {
		keys = append(keys, tuipkg.Key{
			Name:   key.GetName(),
			Type:   key.GetKeyType(),
			Status: key.GetStatus(),
		})
	}
	return keys, nil
}

func (c *grpcTUIClient) ListPasskeys(ctx context.Context) ([]tuipkg.Passkey, error) {
	callCtx, cancel := c.rpcContext(ctx)
	defer cancel()
	resp, err := c.clients.passkey.ListPasskeys(callCtx, &v1.ListPasskeysRequest{})
	if err != nil {
		return nil, err
	}
	passkeys := make([]tuipkg.Passkey, 0, len(resp.GetPasskeys()))
	for _, passkey := range resp.GetPasskeys() {
		passkeys = append(passkeys, tuipkg.Passkey{
			Label:              passkey.GetLabel(),
			SupportsHMACSecret: passkey.GetSupportsHmacSecret(),
		})
	}
	return passkeys, nil
}

func (c *grpcTUIClient) RevealSecret(ctx context.Context, name string) (string, error) {
	callCtx, cancel := c.rpcContext(ctx)
	defer cancel()
	resp, err := c.clients.secret.GetSecretValue(callCtx, &v1.GetSecretValueRequest{
		Name: strings.TrimSpace(name),
	})
	if err != nil {
		return "", err
	}
	return string(resp.GetValue()), nil
}

func (c *grpcTUIClient) rpcContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := ctx
	if base == nil {
		base = context.Background()
	}
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	callCtx, cancel := context.WithTimeout(base, timeout)
	return attachCallerMetadata(callCtx), cancel
}

func isTTYSession() bool {
	return isTTYFile(os.Stdin) && isTTYFile(os.Stdout)
}

func isTTYFile(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
