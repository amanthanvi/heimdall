package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	cryptopkg "github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	backupFormatVersion = 1

	backupVaultDBFileName    = "vault.db"
	backupKnownHostsFileName = "known_hosts"
	backupConfigFileName     = "config.toml"
	backupManifestFileName   = "manifest.json"

	// maxBackupFileSize caps backup file reads to 512 MiB to prevent
	// memory exhaustion from crafted backup archives.
	maxBackupFileSize = 512 << 20

	// maxTarEntrySize caps individual tar archive entries during extraction.
	maxTarEntrySize = 256 << 20

	// Argon2 parameter bounds for untrusted backup envelopes. These
	// prevent DoS via extreme memory/iteration values in crafted backups.
	maxBackupArgon2Memory     = 1 << 20 // 1 GiB in KiB units
	maxBackupArgon2Iterations = 20
	minBackupArgon2Memory     = 64 << 10 // 64 MiB in KiB units
)

var backupAAD = []byte("heimdall.backup.v1")

type backupEnvelope struct {
	Version      int                `json:"version"`
	KDF          string             `json:"kdf"`
	Argon2Params backupArgon2Params `json:"argon2_params"`
	Salt         []byte             `json:"salt"`
	Nonce        []byte             `json:"nonce"`
	Ciphertext   []byte             `json:"ciphertext"`
}

type backupArgon2Params struct {
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	SaltLen     int    `json:"salt_len"`
	KeyLen      uint32 `json:"key_len"`
}

type BackupService struct {
	store *storage.Store
}

func NewBackupService(store *storage.Store) *BackupService {
	return &BackupService{store: store}
}

func (s *BackupService) Create(ctx context.Context, req BackupCreateRequest) (*BackupManifest, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("create backup: store is nil")
	}
	if strings.TrimSpace(req.OutputPath) == "" {
		return nil, fmt.Errorf("%w: output path is required", ErrValidation)
	}

	if req.Unencrypted {
		if !req.ConfirmNoEnc {
			return nil, fmt.Errorf("%w: unencrypted backups require --yes confirmation", ErrValidation)
		}
		if !hasReauth(ctx) {
			return nil, ErrReauthRequired
		}
	} else if len(req.Passphrase) == 0 {
		return nil, fmt.Errorf("%w: backup passphrase is required", ErrValidation)
	}

	if _, err := s.store.DB().ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return nil, fmt.Errorf("create backup: wal checkpoint: %w", err)
	}

	vaultDBPath, err := s.mainDBPath(ctx)
	if err != nil {
		return nil, err
	}
	vaultDBBytes, err := os.ReadFile(vaultDBPath)
	if err != nil {
		return nil, fmt.Errorf("create backup: read vault db: %w", err)
	}

	entries := map[string][]byte{
		backupVaultDBFileName: vaultDBBytes,
	}
	if req.KnownHosts != "" {
		knownHosts, err := os.ReadFile(req.KnownHosts)
		if err != nil {
			return nil, fmt.Errorf("create backup: read known_hosts: %w", err)
		}
		entries[backupKnownHostsFileName] = knownHosts
	}
	if req.ConfigPath != "" {
		configBytes, err := os.ReadFile(req.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("create backup: read config: %w", err)
		}
		entries[backupConfigFileName] = configBytes
	}

	manifest := &BackupManifest{
		Version:   backupFormatVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Files:     map[string]BackupManifestFile{},
	}
	for name, data := range entries {
		manifest.Files[name] = BackupManifestFile{
			SHA256:    sha256Hex(data),
			SizeBytes: int64(len(data)),
		}
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("create backup: marshal manifest: %w", err)
	}
	entries[backupManifestFileName] = manifestBytes

	payload, err := createTarGzEntries(entries)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(req.OutputPath), 0o700); err != nil {
		return nil, fmt.Errorf("create backup: create output directory: %w", err)
	}

	output := payload
	if !req.Unencrypted {
		encrypted, err := encryptBackupPayload(payload, req.Passphrase)
		if err != nil {
			return nil, err
		}
		output = encrypted
	}

	if err := os.WriteFile(req.OutputPath, output, 0o600); err != nil {
		return nil, fmt.Errorf("create backup: write output: %w", err)
	}
	return manifest, nil
}

func (s *BackupService) Restore(ctx context.Context, req BackupRestoreRequest) (*BackupManifest, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("restore backup: store is nil")
	}
	if strings.TrimSpace(req.InputPath) == "" {
		return nil, fmt.Errorf("%w: input path is required", ErrValidation)
	}
	if strings.TrimSpace(req.TargetVaultPath) == "" {
		return nil, fmt.Errorf("%w: target vault path is required", ErrValidation)
	}

	if _, err := os.Stat(req.TargetVaultPath); err == nil {
		if !req.Overwrite {
			return nil, fmt.Errorf("%w: target vault exists; pass --overwrite", ErrValidation)
		}
		if !req.Confirm {
			return nil, fmt.Errorf("%w: overwrite requires confirmation", ErrValidation)
		}
		if !hasReauth(ctx) {
			return nil, ErrReauthRequired
		}
	}

	payload, err := readBackupPayload(req.InputPath, req.Passphrase)
	if err != nil {
		return nil, err
	}
	entries, err := extractTarGzEntries(payload)
	if err != nil {
		return nil, err
	}

	manifestRaw, ok := entries[backupManifestFileName]
	if !ok {
		return nil, fmt.Errorf("restore backup: manifest missing")
	}
	var manifest BackupManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("restore backup: decode manifest: %w", err)
	}
	if manifest.Version != backupFormatVersion {
		return nil, fmt.Errorf("restore backup: unsupported backup version %d", manifest.Version)
	}
	for name, meta := range manifest.Files {
		fileBytes, ok := entries[name]
		if !ok {
			return nil, fmt.Errorf("restore backup: missing file %q from archive", name)
		}
		if got := sha256Hex(fileBytes); !strings.EqualFold(got, meta.SHA256) {
			return nil, fmt.Errorf("restore backup: checksum mismatch for %q", name)
		}
	}

	vaultDB, ok := entries[backupVaultDBFileName]
	if !ok {
		return nil, fmt.Errorf("restore backup: vault db missing")
	}
	if err := os.MkdirAll(filepath.Dir(req.TargetVaultPath), 0o700); err != nil {
		return nil, fmt.Errorf("restore backup: create target directory: %w", err)
	}
	if err := os.WriteFile(req.TargetVaultPath, vaultDB, 0o600); err != nil {
		return nil, fmt.Errorf("restore backup: write vault db: %w", err)
	}

	return &manifest, nil
}

func (s *BackupService) mainDBPath(ctx context.Context) (string, error) {
	rows, err := s.store.DB().QueryContext(ctx, `PRAGMA database_list`)
	if err != nil {
		return "", fmt.Errorf("resolve vault db path: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			seq  int
			name string
			file string
		)
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return "", fmt.Errorf("resolve vault db path: scan row: %w", err)
		}
		if name == "main" && strings.TrimSpace(file) != "" {
			return file, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("resolve vault db path: iterate rows: %w", err)
	}
	return "", fmt.Errorf("resolve vault db path: main database not found")
}

func encryptBackupPayload(payload, passphrase []byte) ([]byte, error) {
	params := cryptopkg.DefaultArgon2Params()
	salt := make([]byte, cryptopkg.DefaultArgon2SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("create backup: generate salt: %w", err)
	}
	key, err := cryptopkg.DeriveKEKFromPassphrase(passphrase, salt, params)
	if err != nil {
		return nil, fmt.Errorf("create backup: derive backup key: %w", err)
	}
	defer memguard.WipeBytes(key)

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("create backup: generate nonce: %w", err)
	}
	ciphertext, err := cryptopkg.SealXChaCha20Poly1305(key, nonce, payload, backupAAD)
	if err != nil {
		return nil, fmt.Errorf("create backup: encrypt payload: %w", err)
	}

	envelope := backupEnvelope{
		Version: backupFormatVersion,
		KDF:     "argon2id",
		Argon2Params: backupArgon2Params{
			Memory:      params.Memory,
			Iterations:  params.Iterations,
			Parallelism: params.Parallelism,
			SaltLen:     params.SaltLen,
			KeyLen:      params.KeyLen,
		},
		Salt:       append([]byte(nil), salt...),
		Nonce:      append([]byte(nil), nonce...),
		Ciphertext: append([]byte(nil), ciphertext...),
	}

	output, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("create backup: encode envelope: %w", err)
	}
	return output, nil
}

func readBackupPayload(path string, passphrase []byte) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read backup payload: %w", err)
	}
	if info.Size() > maxBackupFileSize {
		return nil, fmt.Errorf("read backup payload: file exceeds %d MiB limit", maxBackupFileSize>>20)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read backup payload: %w", err)
	}
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		return raw, nil
	}

	var envelope backupEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("read backup payload: decode envelope: %w", err)
	}
	if envelope.Version != backupFormatVersion {
		return nil, fmt.Errorf("read backup payload: unsupported backup version %d", envelope.Version)
	}
	if envelope.KDF != "" && envelope.KDF != "argon2id" {
		return nil, fmt.Errorf("read backup payload: unsupported kdf %q", envelope.KDF)
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("%w: backup passphrase is required", ErrValidation)
	}

	params := cryptopkg.DefaultArgon2Params()
	if envelope.Argon2Params.Memory > 0 {
		params, err = clampBackupArgon2Params(envelope.Argon2Params)
		if err != nil {
			return nil, fmt.Errorf("read backup payload: %w", err)
		}
	}

	key, err := cryptopkg.DeriveKEKFromPassphrase(passphrase, envelope.Salt, params)
	if err != nil {
		return nil, fmt.Errorf("read backup payload: derive key from passphrase: %w", err)
	}
	defer memguard.WipeBytes(key)

	plaintext, err := cryptopkg.OpenXChaCha20Poly1305(key, envelope.Nonce, envelope.Ciphertext, backupAAD)
	if err != nil {
		return nil, fmt.Errorf("read backup payload: passphrase authentication failed: %w", err)
	}
	return plaintext, nil
}

// clampBackupArgon2Params validates and caps Argon2 parameters from
// untrusted backup envelopes to prevent DoS via extreme values.
func clampBackupArgon2Params(bp backupArgon2Params) (cryptopkg.Argon2Params, error) {
	memory := bp.Memory
	if memory < minBackupArgon2Memory {
		memory = minBackupArgon2Memory
	}
	if memory > maxBackupArgon2Memory {
		return cryptopkg.Argon2Params{}, fmt.Errorf("argon2 memory %d KiB exceeds safe maximum %d KiB", bp.Memory, maxBackupArgon2Memory)
	}

	iterations := bp.Iterations
	if iterations < 1 {
		iterations = 1
	}
	if iterations > maxBackupArgon2Iterations {
		return cryptopkg.Argon2Params{}, fmt.Errorf("argon2 iterations %d exceeds safe maximum %d", bp.Iterations, maxBackupArgon2Iterations)
	}

	parallelism := bp.Parallelism
	if parallelism < 1 {
		parallelism = 1
	}
	if parallelism > 16 {
		parallelism = 16
	}

	keyLen := bp.KeyLen
	if keyLen != 32 {
		keyLen = 32
	}

	return cryptopkg.Argon2Params{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		SaltLen:     bp.SaltLen,
		KeyLen:      keyLen,
	}, nil
}

func createTarGzEntries(entries map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		data := entries[name]
		header := &tar.Header{
			Name:    name,
			Mode:    0o600,
			Size:    int64(len(data)),
			ModTime: time.Unix(0, 0).UTC(),
		}
		if err := tw.WriteHeader(header); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, fmt.Errorf("create tar.gz payload: write header %q: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, fmt.Errorf("create tar.gz payload: write file %q: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return nil, fmt.Errorf("create tar.gz payload: close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("create tar.gz payload: close gzip writer: %w", err)
	}
	return out.Bytes(), nil
}

func extractTarGzEntries(payload []byte) (map[string][]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("extract tar.gz entries: gzip reader: %w", err)
	}
	defer gzReader.Close()

	tr := tar.NewReader(gzReader)
	entries := map[string][]byte{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("extract tar.gz entries: read header: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size > maxTarEntrySize {
			return nil, fmt.Errorf("extract tar.gz entries: %q exceeds %d MiB entry limit", header.Name, maxTarEntrySize>>20)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxTarEntrySize+1))
		if err != nil {
			return nil, fmt.Errorf("extract tar.gz entries: read %q: %w", header.Name, err)
		}
		if int64(len(data)) > maxTarEntrySize {
			return nil, fmt.Errorf("extract tar.gz entries: %q exceeded size limit during read", header.Name)
		}
		entries[header.Name] = data
	}
	return entries, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

