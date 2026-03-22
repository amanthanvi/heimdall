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
	vaultSalt, err := crypto.GenerateSalt(int(params.KeyLen))
	if err != nil {
		return fmt.Errorf("bootstrap vault: generate vault salt: %w", err)
	}
	hmacSecretSalt, err := crypto.GenerateSalt(int(params.KeyLen))
	if err != nil {
		return fmt.Errorf("bootstrap vault: generate hmac-secret salt: %w", err)
	}

	material := storage.VaultAuthMaterial{
		Version:       storage.VaultAuthMaterialVersion2,
		CommitmentTag: hex.EncodeToString(commitmentTag),
		Passphrase: storage.PassphraseAuthMaterial{
			Wrapped: storage.WrappedKeyMaterial{
				Ciphertext: hex.EncodeToString(wrapped.Ciphertext),
				Nonce:      hex.EncodeToString(wrapped.Nonce),
				AAD:        hex.EncodeToString(wrapped.Salt),
			},
			Argon2Salt:  hex.EncodeToString(argon2Salt),
			Memory:      params.Memory,
			Iterations:  params.Iterations,
			Parallelism: params.Parallelism,
			KeyLen:      params.KeyLen,
		},
		PasskeyUnlock: storage.PasskeyUnlockMaterial{
			VaultSalt:      hex.EncodeToString(vaultSalt),
			HMACSecretSalt: hex.EncodeToString(hmacSecretSalt),
		},
		Passkeys: map[string]storage.WrappedKeyMaterial{},
	}
	if err := store.StoreVaultAuthMaterial(ctx, material); err != nil {
		return fmt.Errorf("bootstrap vault: store vault auth material: %w", err)
	}

	if err := store.SealVersionCounter(ctx, vmk); err != nil {
		return fmt.Errorf("bootstrap vault: seal version counter: %w", err)
	}

	return nil
}
