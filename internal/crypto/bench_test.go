package crypto_test

import (
	"crypto/rand"
	"path/filepath"
	"testing"

	apppkg "github.com/amanthanvi/heimdall/internal/app"
	cryptopkg "github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/awnumar/memguard"
)

func BenchmarkVaultOpenCold(b *testing.B) {
	vaultPath := filepath.Join(b.TempDir(), "vault.db")
	if err := apppkg.BootstrapVault(vaultPath, []byte("bench-passphrase")); err != nil {
		b.Fatalf("bootstrap vault: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vmk, err := cryptopkg.GenerateVMK()
		if err != nil {
			b.Fatalf("generate vmk: %v", err)
		}
		vc := cryptopkg.NewVaultCrypto(vmk, "heimdall-bootstrap-vault")
		store, err := storage.Open(vaultPath, "heimdall-bootstrap-vault", vc)
		if err != nil {
			vmk.Destroy()
			b.Fatalf("open storage: %v", err)
		}
		if err := store.Close(); err != nil {
			vmk.Destroy()
			b.Fatalf("close storage: %v", err)
		}
		vmk.Destroy()
	}
}

func BenchmarkKeyDerivation(b *testing.B) {
	params := cryptopkg.DefaultArgon2Params()
	passphrase := []byte("correct horse battery staple")
	salt := make([]byte, cryptopkg.DefaultArgon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		b.Fatalf("generate salt: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, err := cryptopkg.DeriveKEKFromPassphrase(passphrase, salt, params)
		if err != nil {
			b.Fatalf("derive kek: %v", err)
		}
		memguard.WipeBytes(key)
	}
}
