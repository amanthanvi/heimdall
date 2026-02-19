package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/amanthanvi/heimdall/internal/storage"
)

const exportBundleVersion = 1

type TransferService struct {
	store *storage.Store
}

func NewTransferService(store *storage.Store) *TransferService {
	return &TransferService{store: store}
}

func (s *TransferService) ExportJSON(ctx context.Context) ([]byte, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("export json: store is nil")
	}

	hosts, err := s.store.Hosts.List(ctx, storage.HostFilter{})
	if err != nil {
		return nil, fmt.Errorf("export json: list hosts: %w", err)
	}
	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })

	identities, err := s.listIdentities(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(identities, func(i, j int) bool { return identities[i].Name < identities[j].Name })

	secrets, err := s.listSecretsForExport(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(secrets, func(i, j int) bool { return secrets[i].Name < secrets[j].Name })

	bundle := ExportBundle{
		Version:    exportBundleVersion,
		Hosts:      make([]ExportHost, 0, len(hosts)),
		Identities: make([]ExportIdentity, 0, len(identities)),
		Secrets:    make([]ExportSecret, 0, len(secrets)),
	}

	for _, host := range hosts {
		bundle.Hosts = append(bundle.Hosts, ExportHost{
			Name:    host.Name,
			Address: host.Address,
			Port:    host.Port,
			User:    host.User,
			Tags:    append([]string(nil), host.Tags...),
			EnvRefs: cloneStringMap(host.EnvRefs),
		})
	}
	for _, identity := range identities {
		bundle.Identities = append(bundle.Identities, ExportIdentity{
			Name:      identity.Name,
			Kind:      identity.Kind,
			PublicKey: identity.PublicKey,
			Status:    string(identity.Status),
		})
	}
	for _, secret := range secrets {
		bundle.Secrets = append(bundle.Secrets, ExportSecret{
			Name:         secret.Name,
			RevealPolicy: RevealPolicyOncePerUnlock,
			SizeBytes:    secret.SizeBytes,
		})
	}

	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("export json: marshal: %w", err)
	}
	return payload, nil
}

func (s *TransferService) ImportJSON(ctx context.Context, payload []byte, mode ConflictMode) (ImportResult, error) {
	var result ImportResult

	if s == nil || s.store == nil {
		return result, fmt.Errorf("import json: store is nil")
	}
	mode, err := normalizeConflictMode(mode)
	if err != nil {
		return result, err
	}
	if len(payload) == 0 {
		return result, fmt.Errorf("%w: empty payload", ErrValidation)
	}

	var bundle ExportBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return result, fmt.Errorf("import json: decode payload: %w", err)
	}
	if bundle.Version != exportBundleVersion {
		return result, fmt.Errorf("%w: unsupported bundle version %d", ErrValidation, bundle.Version)
	}

	hostSvc := NewHostService(s.store.Hosts, s.store.Sessions)
	for _, host := range bundle.Hosts {
		count, importErr := s.importHost(ctx, hostSvc, host, mode)
		if importErr != nil {
			return result, importErr
		}
		applyCounts(&result.Hosts, count)
	}

	for _, identity := range bundle.Identities {
		count, importErr := s.importIdentity(ctx, identity, mode)
		if importErr != nil {
			return result, importErr
		}
		applyCounts(&result.Identities, count)
	}

	for _, secret := range bundle.Secrets {
		count, importErr := s.importSecret(ctx, secret, mode)
		if importErr != nil {
			return result, importErr
		}
		applyCounts(&result.Secrets, count)
	}

	return result, nil
}

func (s *TransferService) GenerateSSHConfig(ctx context.Context, outputPath string) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("generate ssh config: store is nil")
	}
	if strings.TrimSpace(outputPath) == "" {
		return fmt.Errorf("%w: output path is required", ErrValidation)
	}

	hosts, err := s.store.Hosts.List(ctx, storage.HostFilter{})
	if err != nil {
		return fmt.Errorf("generate ssh config: list hosts: %w", err)
	}
	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })

	var builder strings.Builder
	for i, host := range hosts {
		if i > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString("Host ")
		builder.WriteString(host.Name)
		builder.WriteByte('\n')
		builder.WriteString("  HostName ")
		builder.WriteString(host.Address)
		builder.WriteByte('\n')
		if host.User != "" {
			builder.WriteString("  User ")
			builder.WriteString(host.User)
			builder.WriteByte('\n')
		}
		port := host.Port
		if port == 0 {
			port = 22
		}
		builder.WriteString(fmt.Sprintf("  Port %d\n", port))
		if jump := strings.TrimSpace(host.EnvRefs["proxy_jump"]); jump != "" {
			builder.WriteString("  ProxyJump ")
			builder.WriteString(jump)
			builder.WriteByte('\n')
		}
		if identity := strings.TrimSpace(host.EnvRefs["identity_ref"]); identity != "" {
			builder.WriteString("  IdentityFile ")
			builder.WriteString(identity)
			builder.WriteByte('\n')
		}
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return fmt.Errorf("generate ssh config: create output directory: %w", err)
	}
	if err := os.WriteFile(outputPath, []byte(builder.String()), 0o600); err != nil {
		return fmt.Errorf("generate ssh config: write output: %w", err)
	}
	return nil
}

type secretExportRow struct {
	Name      string
	SizeBytes int64
}

func (s *TransferService) listIdentities(ctx context.Context) ([]storage.Identity, error) {
	rows, err := s.store.DB().QueryContext(ctx, `
		SELECT id, name, kind, public_key, status, created_at, updated_at, deleted_at
		FROM identities
		WHERE deleted_at IS NULL
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("export json: list identities: %w", err)
	}
	defer rows.Close()

	out := []storage.Identity{}
	for rows.Next() {
		var (
			identity  storage.Identity
			status    string
			createdAt string
			updatedAt string
			deletedAt sql.NullString
		)
		if err := rows.Scan(
			&identity.ID,
			&identity.Name,
			&identity.Kind,
			&identity.PublicKey,
			&status,
			&createdAt,
			&updatedAt,
			&deletedAt,
		); err != nil {
			return nil, fmt.Errorf("export json: scan identity: %w", err)
		}
		identity.Status = storage.IdentityStatus(status)
		out = append(out, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("export json: iterate identities: %w", err)
	}
	return out, nil
}

func (s *TransferService) listSecretsForExport(ctx context.Context) ([]secretExportRow, error) {
	rows, err := s.store.DB().QueryContext(ctx, `
		SELECT name
		FROM secrets
		WHERE deleted_at IS NULL
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("export json: list secrets: %w", err)
	}
	defer rows.Close()

	out := []secretExportRow{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("export json: scan secret name: %w", err)
		}
		secret, err := s.store.Secrets.Get(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("export json: read secret %q: %w", name, err)
		}
		out = append(out, secretExportRow{Name: name, SizeBytes: int64(len(secret.Value))})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("export json: iterate secrets: %w", err)
	}
	return out, nil
}
