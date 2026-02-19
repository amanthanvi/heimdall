package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArgon2KAT(t *testing.T) {
	t.Parallel()

	passphrase := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef0123456789abcdef")
	params := Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 1,
		SaltLen:     32,
		KeyLen:      32,
	}

	got, err := DeriveKEKFromPassphrase(passphrase, salt, params)
	require.NoError(t, err)
	require.Equal(t, mustDecodeHex(t, "d12ac228e1566ecd9f80cf05621657ee1b5b34e40133438917d7ed334641f455"), got)
}

func TestXChaCha20Poly1305KAT(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	plaintext := []byte("heimdall-xchacha20poly1305-kat")
	aad := []byte("vault:test-vault")

	got, err := SealXChaCha20Poly1305(key, nonce, plaintext, aad)
	require.NoError(t, err)
	require.Equal(t, mustDecodeHex(t, "d49e3bf7cf7dd45f1870d4c10d13ae723ffd764166bbc9ea317919f6d4a2be3b195b27a6f1b6988e946b669b3758"), got)
}

func TestHKDFSHA256KAT(t *testing.T) {
	t.Parallel()

	ikm := []byte{
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	}
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}

	got, err := DeriveHKDFSHA256(ikm, salt, info, 42)
	require.NoError(t, err)
	require.Equal(t, mustDecodeHex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), got)
}

func TestGenerateVMK(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	require.Len(t, vmk.Bytes(), 32)
	t.Cleanup(vmk.Destroy)
}

func TestDeriveKEKAndWrapUnwrapRoundTrip(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk.Destroy)

	vc := NewVaultCrypto(vmk, "vault-test")
	t.Cleanup(vc.Destroy)

	salt := []byte("0123456789abcdef0123456789abcdef")
	kek, err := DeriveKEKFromPassphrase([]byte("correct horse battery staple"), salt, DefaultArgon2Params())
	require.NoError(t, err)

	wrapped, err := vc.WrapVMK(kek, "vault-a", "passphrase")
	require.NoError(t, err)

	expectedVMK := append([]byte(nil), vmk.Bytes()...)
	commitment := ComputeCommitmentTag(expectedVMK)

	unwrapped, err := UnwrapVMK(kek, wrapped, commitment)
	require.NoError(t, err)
	t.Cleanup(unwrapped.Destroy)
	require.Equal(t, expectedVMK, unwrapped.Bytes())
}

func TestUnwrapVMKWrongKEK(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk.Destroy)

	vc := NewVaultCrypto(vmk, "vault-test")
	t.Cleanup(vc.Destroy)

	goodKEK := bytes.Repeat([]byte{0x42}, 32)
	badKEK := bytes.Repeat([]byte{0x24}, 32)

	wrapped, err := vc.WrapVMK(goodKEK, "vault-a", "passphrase")
	require.NoError(t, err)

	_, err = UnwrapVMK(badKEK, wrapped, ComputeCommitmentTag(vmk.Bytes()))
	require.ErrorIs(t, err, ErrInvalidKEK)
}

func TestKeyCommitmentValidatesAfterUnwrap(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk.Destroy)

	vc := NewVaultCrypto(vmk, "vault-test")
	t.Cleanup(vc.Destroy)

	kek := bytes.Repeat([]byte{0x21}, 32)
	wrapped, err := vc.WrapVMK(kek, "vault-a", "passphrase")
	require.NoError(t, err)

	unwrapped, err := UnwrapVMK(kek, wrapped, ComputeCommitmentTag(vmk.Bytes()))
	require.NoError(t, err)
	t.Cleanup(unwrapped.Destroy)
}

func TestKeyCommitmentTamperFails(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk.Destroy)

	vc := NewVaultCrypto(vmk, "vault-test")
	t.Cleanup(vc.Destroy)

	kek := bytes.Repeat([]byte{0x21}, 32)
	wrapped, err := vc.WrapVMK(kek, "vault-a", "passphrase")
	require.NoError(t, err)

	tampered := ComputeCommitmentTag(vmk.Bytes())
	tampered[0] ^= 0xff

	_, err = UnwrapVMK(kek, wrapped, tampered)
	require.ErrorIs(t, err, ErrCommitmentMismatch)
}

func TestPerRecordDEKDeterministic(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk.Destroy)

	vc := NewVaultCrypto(vmk, "vault-test")
	t.Cleanup(vc.Destroy)

	dekA, err := vc.deriveRecordDEK("secret", "entity-1", "value")
	require.NoError(t, err)
	dekB, err := vc.deriveRecordDEK("secret", "entity-1", "value")
	require.NoError(t, err)
	require.Equal(t, dekA, dekB)
}

func TestPerRecordDEKDistinct(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk.Destroy)

	vc := NewVaultCrypto(vmk, "vault-test")
	t.Cleanup(vc.Destroy)

	dekA, err := vc.deriveRecordDEK("secret", "entity-1", "value")
	require.NoError(t, err)
	dekB, err := vc.deriveRecordDEK("secret", "entity-2", "value")
	require.NoError(t, err)
	require.NotEqual(t, dekA, dekB)
}

func TestEncryptDecryptFieldRoundTrip(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk.Destroy)

	vc := NewVaultCrypto(vmk, "vault-test")
	t.Cleanup(vc.Destroy)

	blob, err := vc.EncryptField("secret", "entity-1", "value", []byte("super-secret-value"))
	require.NoError(t, err)

	plaintext, err := vc.DecryptField("secret", "entity-1", "value", blob)
	require.NoError(t, err)
	require.Equal(t, []byte("super-secret-value"), plaintext)
}

func TestDecryptFieldWrongKeyFails(t *testing.T) {
	t.Parallel()

	vmk1, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk1.Destroy)

	vmk2, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk2.Destroy)

	vc1 := NewVaultCrypto(vmk1, "vault-test")
	vc2 := NewVaultCrypto(vmk2, "vault-test-2")
	t.Cleanup(vc1.Destroy)
	t.Cleanup(vc2.Destroy)

	blob, err := vc1.EncryptField("secret", "entity-1", "value", []byte("super-secret-value"))
	require.NoError(t, err)

	_, err = vc2.DecryptField("secret", "entity-1", "value", blob)
	require.ErrorIs(t, err, ErrAuthenticationFailed)
}

func TestDecryptFieldTamperedADFails(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk.Destroy)

	vc := NewVaultCrypto(vmk, "vault-test")
	t.Cleanup(vc.Destroy)

	blob, err := vc.EncryptField("secret", "entity-1", "value", []byte("super-secret-value"))
	require.NoError(t, err)

	_, err = vc.DecryptField("secret", "entity-1", "other_field", blob)
	require.ErrorIs(t, err, ErrAuthenticationFailed)
}

func TestNonceUniquenessAcrossEncryptions(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk.Destroy)

	vc := NewVaultCrypto(vmk, "vault-test")
	t.Cleanup(vc.Destroy)

	const samples = 10000
	seen := make(map[string]struct{}, samples)

	for i := 0; i < samples; i++ {
		blob, err := vc.EncryptField("secret", "entity-1", "value", []byte("nonce-check"))
		require.NoError(t, err)
		key := string(blob.Nonce)
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate nonce detected at index %d", i)
		}
		seen[key] = struct{}{}
	}
}

func TestArgon2RejectsUnsafeMemory(t *testing.T) {
	t.Parallel()

	params := DefaultArgon2Params()
	params.Memory = MinArgon2MemoryKiB - 1

	_, err := DeriveKEKFromPassphrase([]byte("pass"), []byte("0123456789abcdef0123456789abcdef"), params)
	require.ErrorIs(t, err, ErrInvalidArgon2Params)
}

func TestArgon2RejectsZeroParallelism(t *testing.T) {
	t.Parallel()

	params := DefaultArgon2Params()
	params.Parallelism = 0

	_, err := DeriveKEKFromPassphrase([]byte("pass"), []byte("0123456789abcdef0123456789abcdef"), params)
	require.ErrorIs(t, err, ErrInvalidArgon2Params)
}

func TestDestroyWipesVMKBuffer(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)

	vc := NewVaultCrypto(vmk, "vault-test")
	vc.Destroy()

	require.False(t, vmk.IsAlive())
}

func TestRecordUpdateUsesFreshNonce(t *testing.T) {
	t.Parallel()

	vmk, err := GenerateVMK()
	require.NoError(t, err)
	t.Cleanup(vmk.Destroy)

	vc := NewVaultCrypto(vmk, "vault-test")
	t.Cleanup(vc.Destroy)

	first, err := vc.EncryptField("secret", "entity-1", "value", []byte("stable-plaintext"))
	require.NoError(t, err)

	second, err := vc.EncryptField("secret", "entity-1", "value", []byte("stable-plaintext"))
	require.NoError(t, err)

	require.NotEqual(t, first.Nonce, second.Nonce)
	require.NotEqual(t, first.Ciphertext, second.Ciphertext)
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	require.NoError(t, err)
	return out
}
