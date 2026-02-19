package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

type exportBundle struct {
	Version    int              `json:"version"`
	Hosts      []exportHost     `json:"hosts"`
	Identities []exportIdentity `json:"identities"`
	Secrets    []exportSecret   `json:"secrets"`
}

type exportHost struct {
	Name    string            `json:"name"`
	Address string            `json:"address"`
	Port    int               `json:"port"`
	User    string            `json:"user,omitempty"`
	Tags    []string          `json:"tags,omitempty"`
	EnvRefs map[string]string `json:"env_refs,omitempty"`
}

type exportIdentity struct {
	Name      string `json:"name"`
	Kind      string `json:"kind,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Status    string `json:"status,omitempty"`
}

type exportSecret struct {
	Name         string `json:"name"`
	RevealPolicy string `json:"reveal_policy,omitempty"`
	SizeBytes    int64  `json:"size_bytes,omitempty"`
}

func newImportCommand(deps commandDeps) *cobra.Command {
	var (
		format   string
		fromPath string
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import hosts/keys/secrets metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("import does not accept positional arguments")
			}
			if strings.TrimSpace(fromPath) == "" {
				return usageErrorf("import requires --from")
			}
			switch format {
			case "json":
				return runJSONImport(cmd.Context(), deps, fromPath)
			case "ssh-config":
				return runSSHConfigImport(cmd.Context(), deps, fromPath)
			default:
				return usageErrorf("unsupported import format %q", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "Import format: json or ssh-config")
	cmd.Flags().StringVar(&fromPath, "from", "", "Input path")
	return cmd
}

func newExportCommand(deps commandDeps) *cobra.Command {
	var (
		format     string
		outputPath string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export hosts/keys/secrets metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("export does not accept positional arguments")
			}
			if format != "json" {
				return usageErrorf("unsupported export format %q", format)
			}
			if strings.TrimSpace(outputPath) == "" {
				return usageErrorf("export requires --output")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				hostResp, err := clients.host.ListHosts(ctx, &v1.ListHostsRequest{})
				if err != nil {
					return err
				}
				keyResp, err := clients.key.ListKeys(ctx, &v1.ListKeysRequest{})
				if err != nil {
					return err
				}
				secretResp, err := clients.secret.ListSecrets(ctx, &v1.ListSecretsRequest{})
				if err != nil {
					return err
				}

				bundle := exportBundle{
					Version:    1,
					Hosts:      []exportHost{},
					Identities: []exportIdentity{},
					Secrets:    []exportSecret{},
				}
				for _, host := range hostResp.GetHosts() {
					bundle.Hosts = append(bundle.Hosts, exportHost{
						Name:    host.GetName(),
						Address: host.GetAddress(),
						Port:    int(host.GetPort()),
						User:    host.GetUser(),
						Tags:    append([]string(nil), host.GetTags()...),
						EnvRefs: cloneMap(host.GetEnvRefs()),
					})
				}
				for _, key := range keyResp.GetKeys() {
					bundle.Identities = append(bundle.Identities, exportIdentity{
						Name:      key.GetName(),
						Kind:      key.GetKeyType(),
						PublicKey: key.GetPublicKey(),
						Status:    key.GetStatus(),
					})
				}
				for _, secret := range secretResp.GetSecrets() {
					bundle.Secrets = append(bundle.Secrets, exportSecret{
						Name:         secret.GetName(),
						RevealPolicy: secret.GetRevealPolicy(),
						SizeBytes:    secret.GetSizeBytes(),
					})
				}

				payload, err := json.MarshalIndent(bundle, "", "  ")
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(outputPath, payload, 0o600); err != nil {
					return err
				}

				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{
						"output":     outputPath,
						"hosts":      len(bundle.Hosts),
						"identities": len(bundle.Identities),
						"secrets":    len(bundle.Secrets),
					})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(
					deps.out,
					"exported metadata to %s (hosts=%d identities=%d secrets=%d)\n",
					outputPath,
					len(bundle.Hosts),
					len(bundle.Identities),
					len(bundle.Secrets),
				)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "Export format")
	cmd.Flags().StringVar(&outputPath, "output", "", "Output path")
	return cmd
}

func runJSONImport(ctx context.Context, deps commandDeps, fromPath string) error {
	raw, err := os.ReadFile(fromPath)
	if err != nil {
		return mapCommandError(err)
	}
	var bundle exportBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return mapCommandError(fmt.Errorf("import json: decode bundle: %w", err))
	}
	if bundle.Version != 1 {
		return usageErrorf("import json: unsupported version %d", bundle.Version)
	}

	type summary struct {
		Hosts      int `json:"hosts"`
		Identities int `json:"identities"`
		Secrets    int `json:"secrets"`
		Skipped    int `json:"skipped"`
	}
	result := summary{}

	return withDaemonClients(ctx, deps, func(ctx context.Context, clients daemonClients) error {
		for _, host := range bundle.Hosts {
			_, err := clients.host.CreateHost(ctx, &v1.CreateHostRequest{
				Name:    host.Name,
				Address: host.Address,
				Port:    int32(host.Port),
				User:    host.User,
				Tags:    append([]string(nil), host.Tags...),
				EnvRefs: cloneMap(host.EnvRefs),
			})
			if err != nil {
				if isAlreadyExists(err) {
					result.Skipped++
					continue
				}
				return err
			}
			result.Hosts++
		}
		for _, identity := range bundle.Identities {
			if strings.TrimSpace(identity.Name) == "" {
				continue
			}
			if strings.TrimSpace(identity.PublicKey) == "" {
				result.Skipped++
				continue
			}
			result.Identities++
		}
		for _, secret := range bundle.Secrets {
			size := secret.SizeBytes
			if size <= 0 {
				size = 1
			}
			_, err := clients.secret.CreateSecret(ctx, &v1.CreateSecretRequest{
				Name:         secret.Name,
				Value:        make([]byte, size),
				RevealPolicy: secret.RevealPolicy,
			})
			if err != nil {
				if isAlreadyExists(err) {
					result.Skipped++
					continue
				}
				return err
			}
			result.Secrets++
		}

		if deps.globals.JSON {
			return printJSON(deps.out, result)
		}
		if deps.globals.Quiet {
			return nil
		}
		_, err := fmt.Fprintf(
			deps.out,
			"imported json: hosts=%d identities=%d secrets=%d skipped=%d\n",
			result.Hosts,
			result.Identities,
			result.Secrets,
			result.Skipped,
		)
		return err
	})
}

type parsedSSHHost struct {
	Name    string
	Address string
	User    string
	Port    int
	EnvRefs map[string]string
}

func runSSHConfigImport(ctx context.Context, deps commandDeps, fromPath string) error {
	hosts, err := parseSSHConfigFile(fromPath)
	if err != nil {
		return mapCommandError(err)
	}
	type summary struct {
		Imported int `json:"imported"`
		Skipped  int `json:"skipped"`
	}
	result := summary{}

	return withDaemonClients(ctx, deps, func(ctx context.Context, clients daemonClients) error {
		for _, host := range hosts {
			_, err := clients.host.CreateHost(ctx, &v1.CreateHostRequest{
				Name:    host.Name,
				Address: host.Address,
				Port:    int32(host.Port),
				User:    host.User,
				EnvRefs: cloneMap(host.EnvRefs),
			})
			if err != nil {
				if isAlreadyExists(err) {
					result.Skipped++
					continue
				}
				return err
			}
			result.Imported++
		}

		if deps.globals.JSON {
			return printJSON(deps.out, result)
		}
		if deps.globals.Quiet {
			return nil
		}
		_, err := fmt.Fprintf(deps.out, "imported ssh-config: imported=%d skipped=%d\n", result.Imported, result.Skipped)
		return err
	})
}

func parseSSHConfigFile(path string) ([]parsedSSHHost, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	current := parsedSSHHost{}
	out := []parsedSSHHost{}
	flush := func() {
		if current.Name == "" || current.Address == "" {
			current = parsedSSHHost{}
			return
		}
		if current.Port == 0 {
			current.Port = 22
		}
		out = append(out, current)
		current = parsedSSHHost{}
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")
		switch key {
		case "host":
			flush()
			if strings.ContainsAny(value, "*?") {
				continue
			}
			current.Name = value
		case "hostname":
			current.Address = value
		case "user":
			current.User = value
		case "port":
			parsed, err := strconv.Atoi(value)
			if err != nil {
				continue
			}
			current.Port = parsed
		case "proxyjump":
			if current.EnvRefs == nil {
				current.EnvRefs = map[string]string{}
			}
			current.EnvRefs["proxy_jump"] = value
		case "identityfile":
			if current.EnvRefs == nil {
				current.EnvRefs = map[string]string{}
			}
			current.EnvRefs["identity_ref"] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()
	return out, nil
}

func isAlreadyExists(err error) bool {
	st, ok := grpcstatus.FromError(err)
	return ok && st.Code() == codes.AlreadyExists
}

func cloneMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
