package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/awnumar/memguard"
)

const defaultBootstrapVaultID = "heimdall-bootstrap-vault"

func BootstrapVault(path string, passphrase []byte) error {
	if path == "" {
		return fmt.Errorf("%w: vault path is required", ErrValidation)
	}
	if len(passphrase) == 0 {
		return fmt.Errorf("%w: passphrase is required", ErrValidation)
	}

	vmk, err := crypto.GenerateVMK()
	if err != nil {
		return fmt.Errorf("bootstrap vault: generate vmk: %w", err)
	}
	defer vmk.Destroy()

	params := crypto.DefaultArgon2Params()
	argon2Salt, err := crypto.GenerateSalt(params.SaltLen)
	if err != nil {
		return fmt.Errorf("bootstrap vault: generate salt: %w", err)
	}

	kek, err := crypto.DeriveKEKFromPassphrase(passphrase, argon2Salt, params)
	if err != nil {
		return fmt.Errorf("bootstrap vault: derive kek: %w", err)
	}
	defer memguard.WipeBytes(kek)

	vc := crypto.NewVaultCrypto(vmk, defaultBootstrapVaultID)
	wrapped, err := vc.WrapVMK(kek, defaultBootstrapVaultID, "passphrase")
	if err != nil {
		return fmt.Errorf("bootstrap vault: wrap vmk: %w", err)
	}
	commitmentTag := crypto.ComputeCommitmentTag(vmk.Bytes())

	store, err := storage.Open(filepath.Clean(path), defaultBootstrapVaultID, vc)
	if err != nil {
		return fmt.Errorf("bootstrap vault: open store: %w", err)
	}
	defer func() {
		_ = store.Close()
	}()

	ctx := context.Background()
	bundle := storage.WrappedVMKBundle{
		Ciphertext:    hex.EncodeToString(wrapped.Ciphertext),
		Nonce:         hex.EncodeToString(wrapped.Nonce),
		AAD:           hex.EncodeToString(wrapped.Salt),
		Argon2Salt:    hex.EncodeToString(argon2Salt),
		CommitmentTag: hex.EncodeToString(commitmentTag),
		Memory:        params.Memory,
		Iterations:    params.Iterations,
		Parallelism:   params.Parallelism,
		KeyLen:        params.KeyLen,
	}
	if err := store.StoreWrappedVMK(ctx, bundle); err != nil {
		return fmt.Errorf("bootstrap vault: store wrapped vmk: %w", err)
	}

	if err := store.SealVersionCounter(ctx, vmk); err != nil {
		return fmt.Errorf("bootstrap vault: seal version counter: %w", err)
	}

	return nil
}
