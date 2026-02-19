package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keyCommitmentContext = "heimdall-key-commitment"
	fieldAADVersion      = "v1"
)

var (
	ErrInvalidKEK          = errors.New("invalid kek")
	ErrInvalidWrappedKey   = errors.New("invalid wrapped key")
	ErrCommitmentMismatch  = errors.New("key commitment mismatch")
	ErrVaultCryptoNotReady = errors.New("vault crypto not ready")
)

type WrappedKey struct {
	Ciphertext []byte
	Nonce      []byte
	Salt       []byte
}

type EncryptedBlob struct {
	Ciphertext []byte
	Nonce      []byte
}

type VaultCrypto struct {
	vmk     *memguard.LockedBuffer
	vaultID string
}

func NewVaultCrypto(vmk *memguard.LockedBuffer, vaultID string) *VaultCrypto {
	return &VaultCrypto{vmk: vmk, vaultID: vaultID}
}

func GenerateVMK() (*memguard.LockedBuffer, error) {
	raw := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, fmt.Errorf("generate vmk: %w", err)
	}
	defer memguard.WipeBytes(raw)

	return memguard.NewBufferFromBytes(raw), nil
}

func (vc *VaultCrypto) WrapVMK(kek []byte, vaultID string, methodType string) (WrappedKey, error) {
	if err := vc.ensureReady(); err != nil {
		return WrappedKey{}, err
	}
	if len(kek) != chacha20poly1305.KeySize {
		return WrappedKey{}, fmt.Errorf("%w: key must be %d bytes", ErrInvalidKEK, chacha20poly1305.KeySize)
	}

	nonce, err := randomNonce(chacha20poly1305.NonceSizeX)
	if err != nil {
		return WrappedKey{}, err
	}

	aad := wrapAssociatedData(vaultID, methodType)
	ciphertext, err := SealXChaCha20Poly1305(kek, nonce, vc.vmk.Bytes(), aad)
	if err != nil {
		return WrappedKey{}, fmt.Errorf("wrap vmk: %w", err)
	}

	return WrappedKey{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Salt:       aad,
	}, nil
}

func UnwrapVMK(kek []byte, wrapped WrappedKey, commitmentTag []byte) (*memguard.LockedBuffer, error) {
	if len(kek) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%w: key must be %d bytes", ErrInvalidKEK, chacha20poly1305.KeySize)
	}
	if len(wrapped.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidWrappedKey, chacha20poly1305.NonceSizeX)
	}
	if len(wrapped.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: ciphertext must not be empty", ErrInvalidWrappedKey)
	}
	if len(commitmentTag) == 0 {
		return nil, fmt.Errorf("%w: commitment tag must not be empty", ErrInvalidWrappedKey)
	}

	aad := wrapped.Salt
	plaintext, err := OpenXChaCha20Poly1305(kek, wrapped.Nonce, wrapped.Ciphertext, aad)
	if err != nil {
		if errors.Is(err, ErrAuthenticationFailed) {
			return nil, ErrInvalidKEK
		}
		return nil, fmt.Errorf("unwrap vmk: %w", err)
	}

	expectedTag := ComputeCommitmentTag(plaintext)
	if !hmac.Equal(expectedTag, commitmentTag) {
		memguard.WipeBytes(plaintext)
		return nil, ErrCommitmentMismatch
	}

	buf := memguard.NewBufferFromBytes(plaintext)
	memguard.WipeBytes(plaintext)
	return buf, nil
}

func (vc *VaultCrypto) EncryptField(entityType, entityID, fieldName string, plaintext []byte) (EncryptedBlob, error) {
	if err := vc.ensureReady(); err != nil {
		return EncryptedBlob{}, err
	}

	dek, err := vc.deriveRecordDEK(entityType, entityID, fieldName)
	if err != nil {
		return EncryptedBlob{}, fmt.Errorf("derive record key: %w", err)
	}
	defer memguard.WipeBytes(dek)

	nonce, err := randomNonce(chacha20poly1305.NonceSizeX)
	if err != nil {
		return EncryptedBlob{}, err
	}

	aad := fieldAssociatedData(vc.vaultID, entityType, entityID, fieldName)
	ciphertext, err := SealXChaCha20Poly1305(dek, nonce, plaintext, aad)
	if err != nil {
		return EncryptedBlob{}, fmt.Errorf("encrypt field: %w", err)
	}

	return EncryptedBlob{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (vc *VaultCrypto) DecryptField(entityType, entityID, fieldName string, blob EncryptedBlob) ([]byte, error) {
	if err := vc.ensureReady(); err != nil {
		return nil, err
	}

	dek, err := vc.deriveRecordDEK(entityType, entityID, fieldName)
	if err != nil {
		return nil, fmt.Errorf("derive record key: %w", err)
	}
	defer memguard.WipeBytes(dek)

	aad := fieldAssociatedData(vc.vaultID, entityType, entityID, fieldName)
	plaintext, err := OpenXChaCha20Poly1305(dek, blob.Nonce, blob.Ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (vc *VaultCrypto) SetVMK(vmk *memguard.LockedBuffer) {
	if vc.vmk != nil && vc.vmk.IsAlive() {
		vc.vmk.Destroy()
	}
	vc.vmk = vmk
}

func GenerateSalt(length int) ([]byte, error) {
	if length < 16 {
		return nil, fmt.Errorf("generate salt: length must be >= 16, got %d", length)
	}
	salt := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

func (vc *VaultCrypto) Destroy() {
	if vc == nil || vc.vmk == nil {
		return
	}
	if vc.vmk.IsAlive() {
		vc.vmk.Destroy()
	}
	vc.vmk = nil
}

func (vc *VaultCrypto) deriveRecordDEK(entityType, entityID, fieldName string) ([]byte, error) {
	if err := vc.ensureReady(); err != nil {
		return nil, err
	}

	info := []byte(fieldAADVersion + ":" + entityType + ":" + entityID + ":" + fieldName)
	dek, err := DeriveHKDFSHA256(vc.vmk.Bytes(), nil, info, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("derive hkdf subkey: %w", err)
	}
	return dek, nil
}

func (vc *VaultCrypto) ensureReady() error {
	if vc == nil || vc.vmk == nil || !vc.vmk.IsAlive() {
		return ErrVaultCryptoNotReady
	}
	return nil
}

func ComputeCommitmentTag(vmk []byte) []byte {
	mac := hmac.New(sha256.New, vmk)
	mac.Write([]byte(keyCommitmentContext))
	return mac.Sum(nil)
}

func wrapAssociatedData(vaultID, methodType string) []byte {
	return []byte("heimdall-vmk:" + vaultID + ":" + methodType)
}

func fieldAssociatedData(vaultID, entityType, entityID, fieldName string) []byte {
	return []byte("heimdall-field:" + vaultID + ":" + fieldAADVersion + ":" + entityType + ":" + entityID + ":" + fieldName)
}
