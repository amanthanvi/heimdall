package fido2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/require"
)

func TestMockAuthenticatorMakeCredentialReturnsCredential(t *testing.T) {
	t.Parallel()

	mock := &mockAuthenticator{
		makeCredentialFn: func(opts MakeCredentialOpts) (*Credential, error) {
			require.Equal(t, "heimdall.cli", opts.RPID)
			return &Credential{CredentialID: []byte{0x01}, PublicKeyCOSE: []byte{0x02}}, nil
		},
	}

	cred, err := mock.MakeCredential(MakeCredentialOpts{RPID: "heimdall.cli"})
	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, cred.CredentialID)
	require.Equal(t, []byte{0x02}, cred.PublicKeyCOSE)
}

func TestMockAuthenticatorGetAssertionReturnsAssertion(t *testing.T) {
	t.Parallel()

	mock := &mockAuthenticator{
		getAssertionFn: func(opts GetAssertionOpts) (*Assertion, error) {
			require.Equal(t, "heimdall.cli", opts.RPID)
			return &Assertion{AuthData: []byte("auth"), Signature: bytes.Repeat([]byte{0x01}, ed25519.SignatureSize)}, nil
		},
	}

	assertion, err := mock.GetAssertion(GetAssertionOpts{RPID: "heimdall.cli"})
	require.NoError(t, err)
	require.Equal(t, []byte("auth"), assertion.AuthData)
	require.Len(t, assertion.Signature, ed25519.SignatureSize)
}

func TestEnrollmentStoresCredentialAndMetadata(t *testing.T) {
	t.Parallel()

	store, vmk := newFIDO2TestStore(t)
	defer vmk.Destroy()

	mock := &mockAuthenticator{
		makeCredentialFn: func(_ MakeCredentialOpts) (*Credential, error) {
			return &Credential{
				CredentialID:       []byte{0x01, 0x02, 0x03},
				PublicKeyCOSE:      []byte{0xa5, 0x01, 0x02},
				AAGUID:             []byte{0xaa, 0xbb},
				SupportsHMACSecret: true,
			}, nil
		},
	}

	svc := NewService(mock, store.Passkeys, nil)
	enrollment, err := svc.Enroll(context.Background(), "yubikey", "aman")
	require.NoError(t, err)
	require.NotEmpty(t, enrollment.ID)

	stored, err := store.Passkeys.GetByLabel(context.Background(), "yubikey")
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, stored.CredentialID)
	require.Equal(t, []byte{0xa5, 0x01, 0x02}, stored.PublicKeyCOSE)
	require.True(t, stored.SupportsHMACSecret)
	require.Equal(t, "yubikey", stored.Label)
}

func TestEnrollmentRejectsDuplicateLabel(t *testing.T) {
	t.Parallel()

	store, vmk := newFIDO2TestStore(t)
	defer vmk.Destroy()

	mock := &mockAuthenticator{
		makeCredentialFn: func(_ MakeCredentialOpts) (*Credential, error) {
			return &Credential{CredentialID: []byte{0x10}, PublicKeyCOSE: []byte{0x20}, SupportsHMACSecret: true}, nil
		},
	}

	svc := NewService(mock, store.Passkeys, nil)
	require.NoError(t, func() error {
		_, err := svc.Enroll(context.Background(), "dup", "aman")
		return err
	}())

	_, err := svc.Enroll(context.Background(), "dup", "aman")
	require.ErrorIs(t, err, ErrDuplicateLabel)
}

func TestVaultUnlockUsesHMACSecretOutputForHKDF(t *testing.T) {
	t.Parallel()

	store, vmk := newFIDO2TestStore(t)
	defer vmk.Destroy()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	enrollment := &storage.PasskeyEnrollment{
		Label:              "key-1",
		CredentialID:       []byte{0xaa, 0xbb},
		PublicKeyCOSE:      pub,
		SupportsHMACSecret: true,
	}
	require.NoError(t, store.Passkeys.Create(context.Background(), enrollment))

	hmacOutput := bytes.Repeat([]byte{0x42}, 32)
	vaultSalt := bytes.Repeat([]byte{0x24}, 32)
	hmacSalt := bytes.Repeat([]byte{0x31}, 32)

	expectedKEK, err := crypto.DeriveKEKFromHMACSecret(hmacOutput, vaultSalt)
	require.NoError(t, err)

	wrapped, commitment, expectedVMK := wrappedVMKForKEK(t, expectedKEK)
	defer expectedVMK.Destroy()

	authData := []byte("unlock-auth-data")
	sig := ed25519.Sign(priv, authData)

	var captured GetAssertionOpts
	mock := &mockAuthenticator{
		getAssertionFn: func(opts GetAssertionOpts) (*Assertion, error) {
			captured = opts
			return &Assertion{HMACSecretOutput: hmacOutput, AuthData: authData, Signature: sig}, nil
		},
	}

	svc := NewService(mock, store.Passkeys, nil)
	unwrapped, err := svc.UnlockWithPasskey(context.Background(), "key-1", wrapped, commitment, vaultSalt, hmacSalt)
	require.NoError(t, err)
	defer unwrapped.Destroy()

	require.True(t, captured.RequireHMACSecret)
	require.Equal(t, hmacSalt, captured.HMACSecretSalt)
	require.Equal(t, enrollment.CredentialID, captured.CredentialID)
}

func TestVaultUnlockDerivedKEKSuccessfullyUnwrapsVMK(t *testing.T) {
	t.Parallel()

	store, vmk := newFIDO2TestStore(t)
	defer vmk.Destroy()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	enrollment := &storage.PasskeyEnrollment{
		Label:              "key-2",
		CredentialID:       []byte{0x90, 0x91},
		PublicKeyCOSE:      pub,
		SupportsHMACSecret: true,
	}
	require.NoError(t, store.Passkeys.Create(context.Background(), enrollment))

	hmacOutput := bytes.Repeat([]byte{0x77}, 32)
	vaultSalt := bytes.Repeat([]byte{0x55}, 32)
	hmacSalt := bytes.Repeat([]byte{0x44}, 32)

	kek, err := crypto.DeriveKEKFromHMACSecret(hmacOutput, vaultSalt)
	require.NoError(t, err)

	wrapped, commitment, expectedVMK := wrappedVMKForKEK(t, kek)
	defer expectedVMK.Destroy()

	authData := []byte("unlock-vmk-auth")
	sig := ed25519.Sign(priv, authData)

	mock := &mockAuthenticator{
		getAssertionFn: func(_ GetAssertionOpts) (*Assertion, error) {
			return &Assertion{HMACSecretOutput: hmacOutput, AuthData: authData, Signature: sig}, nil
		},
	}

	svc := NewService(mock, store.Passkeys, nil)
	unwrapped, err := svc.UnlockWithPasskey(context.Background(), "key-2", wrapped, commitment, vaultSalt, hmacSalt)
	require.NoError(t, err)
	defer unwrapped.Destroy()

	require.Equal(t, expectedVMK.Bytes(), unwrapped.Bytes())
}

func TestVaultUnlockWrongCredentialIDFailsAssertion(t *testing.T) {
	t.Parallel()

	store, vmk := newFIDO2TestStore(t)
	defer vmk.Destroy()

	enrollment := &storage.PasskeyEnrollment{
		Label:              "wrong-id",
		CredentialID:       []byte{0x01, 0x02},
		PublicKeyCOSE:      bytes.Repeat([]byte{0x33}, ed25519.PublicKeySize),
		SupportsHMACSecret: true,
	}
	require.NoError(t, store.Passkeys.Create(context.Background(), enrollment))

	kek := bytes.Repeat([]byte{0x11}, 32)
	wrapped, commitment, vmkToUnlock := wrappedVMKForKEK(t, kek)
	defer vmkToUnlock.Destroy()

	mock := &mockAuthenticator{
		getAssertionFn: func(opts GetAssertionOpts) (*Assertion, error) {
			expected := []byte{0xff, 0xee}
			if !bytes.Equal(opts.CredentialID, expected) {
				return nil, fmt.Errorf("credential not in allow list")
			}
			return &Assertion{HMACSecretOutput: bytes.Repeat([]byte{0x99}, 32)}, nil
		},
	}

	svc := NewService(mock, store.Passkeys, nil)
	_, err := svc.UnlockWithPasskey(context.Background(), "wrong-id", wrapped, commitment, bytes.Repeat([]byte{0x00}, 32), bytes.Repeat([]byte{0x01}, 32))
	require.True(t, IsExitCode(err, ExitCodeAuthFailed))
}

func TestReauthVerifiesAssertionSignatureAgainstStoredPublicKey(t *testing.T) {
	t.Parallel()

	store, vmk := newFIDO2TestStore(t)
	defer vmk.Destroy()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	enrollment := &storage.PasskeyEnrollment{
		Label:              "reauth-ok",
		CredentialID:       []byte{0x44, 0x55},
		PublicKeyCOSE:      pub,
		SupportsHMACSecret: true,
	}
	require.NoError(t, store.Passkeys.Create(context.Background(), enrollment))

	authData := []byte("reauth-data")
	sig := ed25519.Sign(priv, authData)

	mock := &mockAuthenticator{
		getAssertionFn: func(_ GetAssertionOpts) (*Assertion, error) {
			return &Assertion{AuthData: authData, Signature: sig}, nil
		},
	}

	svc := NewService(mock, store.Passkeys, nil)
	require.NoError(t, svc.Reauthenticate(context.Background(), "reauth-ok", 1234))
}

func TestReauthFailedAssertionReturnsAuthError(t *testing.T) {
	t.Parallel()

	store, vmk := newFIDO2TestStore(t)
	defer vmk.Destroy()

	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	enrollment := &storage.PasskeyEnrollment{
		Label:              "reauth-fail",
		CredentialID:       []byte{0xaa, 0xbb},
		PublicKeyCOSE:      pub,
		SupportsHMACSecret: true,
	}
	require.NoError(t, store.Passkeys.Create(context.Background(), enrollment))

	mock := &mockAuthenticator{
		getAssertionFn: func(_ GetAssertionOpts) (*Assertion, error) {
			return &Assertion{AuthData: []byte("bad"), Signature: bytes.Repeat([]byte{0x01}, ed25519.SignatureSize)}, nil
		},
	}

	svc := NewService(mock, store.Passkeys, nil)
	err = svc.Reauthenticate(context.Background(), "reauth-fail", 999)
	require.True(t, IsExitCode(err, ExitCodeAuthFailed))
}

func TestReauthRecordsPIDScopedTimestamp(t *testing.T) {
	t.Parallel()

	store, vmk := newFIDO2TestStore(t)
	defer vmk.Destroy()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	enrollment := &storage.PasskeyEnrollment{
		Label:              "reauth-ts",
		CredentialID:       []byte{0x12, 0x34},
		PublicKeyCOSE:      pub,
		SupportsHMACSecret: true,
	}
	require.NoError(t, store.Passkeys.Create(context.Background(), enrollment))

	authData := []byte("timestamp")
	sig := ed25519.Sign(priv, authData)

	mock := &mockAuthenticator{
		getAssertionFn: func(_ GetAssertionOpts) (*Assertion, error) {
			return &Assertion{AuthData: authData, Signature: sig}, nil
		},
	}

	svc := NewService(mock, store.Passkeys, nil)
	pid := 4242
	require.NoError(t, svc.Reauthenticate(context.Background(), "reauth-ts", pid))

	ts, ok := svc.LastReauthForPID(pid)
	require.True(t, ok)
	require.WithinDuration(t, time.Now().UTC(), ts, time.Second)
}

func TestHMACSecretNotSupportedEnrollmentRecordedFalse(t *testing.T) {
	t.Parallel()

	store, vmk := newFIDO2TestStore(t)
	defer vmk.Destroy()

	mock := &mockAuthenticator{
		makeCredentialFn: func(_ MakeCredentialOpts) (*Credential, error) {
			return &Credential{CredentialID: []byte{0x99}, PublicKeyCOSE: []byte{0x88}, SupportsHMACSecret: false}, nil
		},
	}

	svc := NewService(mock, store.Passkeys, nil)
	_, err := svc.Enroll(context.Background(), "no-hmac", "aman")
	require.NoError(t, err)

	stored, err := store.Passkeys.GetByLabel(context.Background(), "no-hmac")
	require.NoError(t, err)
	require.False(t, stored.SupportsHMACSecret)
}

func TestHMACSecretNotSupportedUnlockFailsWithClearMessage(t *testing.T) {
	t.Parallel()

	store, vmk := newFIDO2TestStore(t)
	defer vmk.Destroy()

	enrollment := &storage.PasskeyEnrollment{
		Label:              "no-hmac-unlock",
		CredentialID:       []byte{0x70},
		PublicKeyCOSE:      bytes.Repeat([]byte{0x10}, ed25519.PublicKeySize),
		SupportsHMACSecret: false,
	}
	require.NoError(t, store.Passkeys.Create(context.Background(), enrollment))

	svc := NewService(&mockAuthenticator{}, store.Passkeys, nil)
	_, err := svc.UnlockWithPasskey(context.Background(), "no-hmac-unlock", crypto.WrappedKey{}, []byte{0x01}, []byte{0x02}, []byte{0x03})
	require.ErrorIs(t, err, ErrHMACSecretUnsupported)
	require.Contains(t, err.Error(), "hmac-secret")
}

func TestSoftFIDO2HMACSecretValidationResearchSpike(t *testing.T) {
	t.Parallel()
	if os.Getenv("HEIMDALL_RUN_SOFTFIDO2") != "1" {
		t.Skip("research spike: set HEIMDALL_RUN_SOFTFIDO2=1 and provide SoftFIDO2 device to run")
	}
	t.Skip("SoftFIDO2 integration path intentionally deferred to dedicated environment run")
}

type mockAuthenticator struct {
	makeCredentialFn func(opts MakeCredentialOpts) (*Credential, error)
	getAssertionFn   func(opts GetAssertionOpts) (*Assertion, error)
	closeFn          func() error
}

func (m *mockAuthenticator) MakeCredential(opts MakeCredentialOpts) (*Credential, error) {
	if m.makeCredentialFn == nil {
		return nil, fmt.Errorf("mock make credential not configured")
	}
	return m.makeCredentialFn(opts)
}

func (m *mockAuthenticator) GetAssertion(opts GetAssertionOpts) (*Assertion, error) {
	if m.getAssertionFn == nil {
		return nil, fmt.Errorf("mock get assertion not configured")
	}
	return m.getAssertionFn(opts)
}

func (m *mockAuthenticator) Close() error {
	if m.closeFn == nil {
		return nil
	}
	return m.closeFn()
}

func newFIDO2TestStore(t *testing.T) (*storage.Store, *memguard.LockedBuffer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	vmk, err := crypto.GenerateVMK()
	require.NoError(t, err)
	vc := crypto.NewVaultCrypto(vmk, "vault-fido2-test")

	store, err := storage.Open(path, "vault-fido2-test", vc)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return store, vmk
}

func wrappedVMKForKEK(t *testing.T, kek []byte) (crypto.WrappedKey, []byte, *memguard.LockedBuffer) {
	t.Helper()
	vmk, err := crypto.GenerateVMK()
	require.NoError(t, err)
	vc := crypto.NewVaultCrypto(vmk, "vault-unlock-test")

	wrapped, err := vc.WrapVMK(kek, "vault-unlock-test", "passkey")
	require.NoError(t, err)

	commitment := crypto.ComputeCommitmentTag(vmk.Bytes())
	return wrapped, commitment, vmk
}
