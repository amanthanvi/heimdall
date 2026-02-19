package app

import (
	"fmt"
	"path/filepath"

	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/amanthanvi/heimdall/internal/storage"
)

const defaultBootstrapVaultID = "heimdall-bootstrap-vault"

func BootstrapVault(path string) error {
	if path == "" {
		return fmt.Errorf("%w: vault path is required", ErrValidation)
	}

	vmk, err := crypto.GenerateVMK()
	if err != nil {
		return fmt.Errorf("bootstrap vault: generate vmk: %w", err)
	}
	defer vmk.Destroy()

	vc := crypto.NewVaultCrypto(vmk, defaultBootstrapVaultID)
	store, err := storage.Open(filepath.Clean(path), defaultBootstrapVaultID, vc)
	if err != nil {
		return fmt.Errorf("bootstrap vault: open store: %w", err)
	}
	if err := store.Close(); err != nil {
		return fmt.Errorf("bootstrap vault: close store: %w", err)
	}
	return nil
}
