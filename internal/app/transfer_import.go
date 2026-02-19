package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/amanthanvi/heimdall/internal/storage"
)

type entityImportCount struct {
	created int
	updated int
	skipped int
}

func (s *TransferService) importHost(ctx context.Context, hostSvc *HostService, host ExportHost, mode ConflictMode) (entityImportCount, error) {
	name := strings.TrimSpace(host.Name)
	if name == "" {
		return entityImportCount{}, fmt.Errorf("%w: host name is required", ErrValidation)
	}
	if err := validateImportName(name); err != nil {
		return entityImportCount{}, err
	}

	existing, err := s.store.Hosts.Get(ctx, name)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return entityImportCount{}, fmt.Errorf("import json: read host %q: %w", name, err)
	}

	if errors.Is(err, storage.ErrNotFound) {
		if _, err := hostSvc.Create(ctx, CreateHostRequest{
			Name:    name,
			Address: host.Address,
			Port:    host.Port,
			User:    host.User,
			Tags:    host.Tags,
			EnvRefs: host.EnvRefs,
		}); err != nil {
			return entityImportCount{}, fmt.Errorf("import json: create host %q: %w", name, err)
		}
		return entityImportCount{created: 1}, nil
	}

	switch mode {
	case ConflictModeSkip:
		return entityImportCount{skipped: 1}, nil
	case ConflictModeOverwrite:
		existing.Name = name
		existing.Address = host.Address
		existing.Port = host.Port
		existing.User = host.User
		existing.Tags = append([]string(nil), host.Tags...)
		existing.EnvRefs = cloneStringMap(host.EnvRefs)
		if err := s.store.Hosts.Update(ctx, existing); err != nil {
			return entityImportCount{}, fmt.Errorf("import json: overwrite host %q: %w", name, err)
		}
		return entityImportCount{updated: 1}, nil
	case ConflictModeRename:
		renamed, err := s.nextImportedName(ctx, name, func(ctx context.Context, candidate string) (bool, error) {
			_, err := s.store.Hosts.Get(ctx, candidate)
			if errors.Is(err, storage.ErrNotFound) {
				return false, nil
			}
			return err == nil, err
		})
		if err != nil {
			return entityImportCount{}, err
		}
		if _, err := hostSvc.Create(ctx, CreateHostRequest{
			Name:    renamed,
			Address: host.Address,
			Port:    host.Port,
			User:    host.User,
			Tags:    host.Tags,
			EnvRefs: host.EnvRefs,
		}); err != nil {
			return entityImportCount{}, fmt.Errorf("import json: create renamed host %q: %w", renamed, err)
		}
		return entityImportCount{created: 1}, nil
	default:
		return entityImportCount{}, fmt.Errorf("%w: unsupported conflict mode %q", ErrValidation, mode)
	}
}

func (s *TransferService) importIdentity(ctx context.Context, identity ExportIdentity, mode ConflictMode) (entityImportCount, error) {
	name := strings.TrimSpace(identity.Name)
	if name == "" {
		return entityImportCount{}, fmt.Errorf("%w: identity name is required", ErrValidation)
	}
	if err := validateImportName(name); err != nil {
		return entityImportCount{}, err
	}
	kind := strings.TrimSpace(identity.Kind)
	if kind == "" {
		kind = string(KeyTypeEd25519)
	}
	status := storage.IdentityStatus(strings.TrimSpace(identity.Status))
	if status == "" {
		status = storage.IdentityStatusActive
	}

	existing, err := s.store.Identities.Get(ctx, name)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return entityImportCount{}, fmt.Errorf("import json: read identity %q: %w", name, err)
	}

	if errors.Is(err, storage.ErrNotFound) {
		if err := s.store.Identities.Create(ctx, &storage.Identity{
			Name:      name,
			Kind:      kind,
			PublicKey: identity.PublicKey,
			Status:    status,
		}); err != nil {
			return entityImportCount{}, fmt.Errorf("import json: create identity %q: %w", name, err)
		}
		return entityImportCount{created: 1}, nil
	}

	switch mode {
	case ConflictModeSkip:
		return entityImportCount{skipped: 1}, nil
	case ConflictModeOverwrite:
		existing.Name = name
		existing.Kind = kind
		existing.PublicKey = identity.PublicKey
		existing.Status = status
		if err := s.store.Identities.Update(ctx, existing); err != nil {
			return entityImportCount{}, fmt.Errorf("import json: overwrite identity %q: %w", name, err)
		}
		return entityImportCount{updated: 1}, nil
	case ConflictModeRename:
		renamed, err := s.nextImportedName(ctx, name, func(ctx context.Context, candidate string) (bool, error) {
			_, err := s.store.Identities.Get(ctx, candidate)
			if errors.Is(err, storage.ErrNotFound) {
				return false, nil
			}
			return err == nil, err
		})
		if err != nil {
			return entityImportCount{}, err
		}
		if err := s.store.Identities.Create(ctx, &storage.Identity{
			Name:      renamed,
			Kind:      kind,
			PublicKey: identity.PublicKey,
			Status:    status,
		}); err != nil {
			return entityImportCount{}, fmt.Errorf("import json: create renamed identity %q: %w", renamed, err)
		}
		return entityImportCount{created: 1}, nil
	default:
		return entityImportCount{}, fmt.Errorf("%w: unsupported conflict mode %q", ErrValidation, mode)
	}
}

// maxImportSecretSize caps imported secret placeholder allocations
// to prevent memory exhaustion from crafted JSON with extreme size_bytes.
const maxImportSecretSize = 1 << 20 // 1 MiB

func (s *TransferService) importSecret(ctx context.Context, secret ExportSecret, mode ConflictMode) (entityImportCount, error) {
	name := strings.TrimSpace(secret.Name)
	if name == "" {
		return entityImportCount{}, fmt.Errorf("%w: secret name is required", ErrValidation)
	}
	if err := validateImportName(name); err != nil {
		return entityImportCount{}, err
	}
	size := int(secret.SizeBytes)
	if size <= 0 {
		size = 1
	}
	if size > maxImportSecretSize {
		return entityImportCount{}, fmt.Errorf("%w: secret %q size_bytes %d exceeds %d limit", ErrValidation, name, size, maxImportSecretSize)
	}
	value := make([]byte, size)

	existing, err := s.store.Secrets.Get(ctx, name)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return entityImportCount{}, fmt.Errorf("import json: read secret %q: %w", name, err)
	}

	if errors.Is(err, storage.ErrNotFound) {
		if err := s.store.Secrets.Create(ctx, &storage.Secret{
			Name:  name,
			Value: value,
		}); err != nil {
			return entityImportCount{}, fmt.Errorf("import json: create secret %q: %w", name, err)
		}
		return entityImportCount{created: 1}, nil
	}

	switch mode {
	case ConflictModeSkip:
		return entityImportCount{skipped: 1}, nil
	case ConflictModeOverwrite:
		existing.Name = name
		existing.Value = value
		if err := s.store.Secrets.Update(ctx, existing); err != nil {
			return entityImportCount{}, fmt.Errorf("import json: overwrite secret %q: %w", name, err)
		}
		return entityImportCount{updated: 1}, nil
	case ConflictModeRename:
		renamed, err := s.nextImportedName(ctx, name, func(ctx context.Context, candidate string) (bool, error) {
			_, err := s.store.Secrets.Get(ctx, candidate)
			if errors.Is(err, storage.ErrNotFound) {
				return false, nil
			}
			return err == nil, err
		})
		if err != nil {
			return entityImportCount{}, err
		}
		if err := s.store.Secrets.Create(ctx, &storage.Secret{
			Name:  renamed,
			Value: value,
		}); err != nil {
			return entityImportCount{}, fmt.Errorf("import json: create renamed secret %q: %w", renamed, err)
		}
		return entityImportCount{created: 1}, nil
	default:
		return entityImportCount{}, fmt.Errorf("%w: unsupported conflict mode %q", ErrValidation, mode)
	}
}

func (s *TransferService) nextImportedName(ctx context.Context, base string, exists func(context.Context, string) (bool, error)) (string, error) {
	for i := 1; i <= 10_000; i++ {
		candidate := fmt.Sprintf("%s-imported-%d", base, i)
		found, err := exists(ctx, candidate)
		if err != nil {
			return "", fmt.Errorf("import json: check candidate %q: %w", candidate, err)
		}
		if !found {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("import json: exhausted rename attempts for %q", base)
}

func normalizeConflictMode(mode ConflictMode) (ConflictMode, error) {
	if mode == "" {
		return ConflictModeSkip, nil
	}
	switch mode {
	case ConflictModeSkip, ConflictModeOverwrite, ConflictModeRename:
		return mode, nil
	default:
		return "", fmt.Errorf("%w: unsupported conflict mode %q", ErrValidation, mode)
	}
}

// validateImportName rejects names containing control characters to
// prevent log injection and terminal escape sequence attacks from
// crafted import files.
func validateImportName(name string) error {
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: name contains control character U+%04X", ErrValidation, r)
		}
	}
	if len(name) > 255 {
		return fmt.Errorf("%w: name exceeds 255 character limit", ErrValidation)
	}
	return nil
}

func applyCounts(dst *ImportCounts, src entityImportCount) {
	dst.Created += src.created
	dst.Updated += src.updated
	dst.Skipped += src.skipped
}
