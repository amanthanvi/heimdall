package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const backupRestorePendingSuffix = ".restore-pending"

func BackupRestorePendingPath(vaultPath string) string {
	cleanPath := strings.TrimSpace(vaultPath)
	if cleanPath == "" {
		return ""
	}
	return filepath.Clean(cleanPath) + backupRestorePendingSuffix
}

func RemoveBackupRestorePending(vaultPath string) error {
	pendingPath := BackupRestorePendingPath(vaultPath)
	if pendingPath == "" {
		return nil
	}
	if err := os.Remove(pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove pending restore: remove pending file: %w", err)
	}
	if err := removeSQLiteSidecars(pendingPath); err != nil {
		return fmt.Errorf("remove pending restore: remove pending sidecars: %w", err)
	}
	return nil
}

func ApplyBackupRestorePending(vaultPath string) (bool, error) {
	cleanVaultPath := strings.TrimSpace(vaultPath)
	if cleanVaultPath == "" {
		return false, fmt.Errorf("apply pending restore: vault path is required")
	}
	cleanVaultPath = filepath.Clean(cleanVaultPath)
	pendingPath := BackupRestorePendingPath(cleanVaultPath)

	if _, err := os.Stat(pendingPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("apply pending restore: stat pending restore: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(cleanVaultPath), 0o700); err != nil {
		return false, fmt.Errorf("apply pending restore: create vault dir: %w", err)
	}
	if err := removeSQLiteSidecars(cleanVaultPath); err != nil {
		return false, fmt.Errorf("apply pending restore: remove vault sidecars: %w", err)
	}
	if err := removeSQLiteSidecars(pendingPath); err != nil {
		return false, fmt.Errorf("apply pending restore: remove pending sidecars: %w", err)
	}

	backupPath := cleanVaultPath + ".restore-old"
	if err := os.Remove(backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("apply pending restore: remove old backup: %w", err)
	}

	renamedOriginal := false
	if _, err := os.Stat(cleanVaultPath); err == nil {
		if err := os.Rename(cleanVaultPath, backupPath); err != nil {
			return false, fmt.Errorf("apply pending restore: move current vault aside: %w", err)
		}
		renamedOriginal = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("apply pending restore: stat current vault: %w", err)
	}

	if err := os.Rename(pendingPath, cleanVaultPath); err != nil {
		if renamedOriginal {
			_ = os.Rename(backupPath, cleanVaultPath)
		}
		return false, fmt.Errorf("apply pending restore: activate pending restore: %w", err)
	}
	if err := os.Chmod(cleanVaultPath, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("apply pending restore: set vault permissions: %w", err)
	}
	if renamedOriginal {
		if err := os.Remove(backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("apply pending restore: remove previous vault backup: %w", err)
		}
	}
	return true, nil
}
