package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/awnumar/memguard"
	_ "modernc.org/sqlite"
)

const (
	pragmaJournalModeWAL     = `PRAGMA journal_mode=WAL`
	pragmaForeignKeysOn      = `PRAGMA foreign_keys=ON`
	pragmaBusyTimeout        = `PRAGMA busy_timeout=5000`
	pragmaWALAutocheckpoint0 = `PRAGMA wal_autocheckpoint=0`
)

type Store struct {
	db      *sql.DB
	path    string
	vaultID string
	crypto  *crypto.VaultCrypto

	Hosts      HostRepository
	Identities IdentityRepository
	Secrets    SecretRepository
	Passkeys   PasskeyRepository
	Audit      AuditRepository
	Sessions   SessionRepository
	Templates  TemplateRepository
	PendingOps PendingOpRepository
}

func Open(path, vaultID string, vc *crypto.VaultCrypto) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("open storage: empty path")
	}
	if vc == nil {
		return nil, fmt.Errorf("open storage: vault crypto is nil")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("open storage: create parent dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open storage: %w", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)

	if err := configureSQLite(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := RunMigrations(db, DefaultMigrations()); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := ensureDBPermissions(path); err != nil {
		_ = db.Close()
		return nil, err
	}

	store := &Store{
		db:      db,
		path:    path,
		vaultID: vaultID,
		crypto:  vc,
	}
	store.Hosts = &hostRepository{db: db, vc: vc}
	store.Identities = &identityRepository{db: db, vc: vc}
	store.Secrets = &secretRepository{db: db, vc: vc}
	store.Passkeys = &passkeyRepository{db: db, vc: vc}
	store.Audit = &auditRepository{db: db, vc: vc}
	store.Sessions = &sessionRepository{db: db, vc: vc}
	store.Templates = &templateRepository{db: db, vc: vc}
	store.PendingOps = &pendingOpRepository{db: db, vc: vc}

	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func configureSQLite(db *sql.DB) error {
	pragmas := []string{pragmaJournalModeWAL, pragmaForeignKeysOn, pragmaBusyTimeout, pragmaWALAutocheckpoint0}
	for _, stmt := range pragmas {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("configure sqlite %q: %w", stmt, err)
		}
	}
	return nil
}

func ensureDBPermissions(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("set db file permissions: %w", err)
		}
	}

	walPath := path + "-wal"
	if err := os.Chmod(walPath, 0o600); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("set wal file permissions: %w", err)
		}
	}
	return nil
}

const wrappedVMKBundleMetaKey = "wrapped_vmk_bundle"

func (s *Store) StoreWrappedVMK(ctx context.Context, bundle WrappedVMKBundle) error {
	data, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("store wrapped vmk: marshal: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO vault_meta(key, value) VALUES(?, ?)`, wrappedVMKBundleMetaKey, string(data)); err != nil {
		return fmt.Errorf("store wrapped vmk: %w", err)
	}
	return nil
}

func (s *Store) LoadWrappedVMK(ctx context.Context) (WrappedVMKBundle, error) {
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM vault_meta WHERE key = ?`, wrappedVMKBundleMetaKey).Scan(&raw); err != nil {
		return WrappedVMKBundle{}, fmt.Errorf("load wrapped vmk: %w", err)
	}
	var bundle WrappedVMKBundle
	if err := json.Unmarshal([]byte(raw), &bundle); err != nil {
		return WrappedVMKBundle{}, fmt.Errorf("load wrapped vmk: unmarshal: %w", err)
	}
	return bundle, nil
}

func (s *Store) VerifyRollbackPreUnlock(homeDir string) error {
	if s == nil {
		return fmt.Errorf("verify rollback pre-unlock: nil store")
	}

	ctx := context.Background()
	dbVersion, err := s.versionCounter(ctx)
	if err != nil {
		return err
	}

	versionFile := filepath.Join(homeDir, rollbackVersionFileName)
	data, err := os.ReadFile(versionFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return writeVersionCounterFile(versionFile, dbVersion)
		}
		return fmt.Errorf("read rollback version file: %w", err)
	}

	fileVersion, err := parseUint(string(data))
	if err != nil {
		return fmt.Errorf("parse rollback version file: %w", err)
	}

	if dbVersion < fileVersion {
		return fmt.Errorf("%w: db=%d file=%d", ErrRollbackDetected, dbVersion, fileVersion)
	}

	if dbVersion > fileVersion {
		if err := writeVersionCounterFile(versionFile, dbVersion); err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) SealVersionCounter(ctx context.Context, vmk *memguard.LockedBuffer) error {
	if vmk == nil || !vmk.IsAlive() {
		return fmt.Errorf("seal version counter: vmk is nil or destroyed")
	}
	counter, err := s.versionCounter(ctx)
	if err != nil {
		return err
	}

	tag := computeVersionCounterHMAC(vmk.Bytes(), counter)
	if _, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO vault_meta(key, value) VALUES(?, ?)`, versionCounterHMACMeta, hex.EncodeToString(tag)); err != nil {
		return fmt.Errorf("seal version counter: %w", err)
	}
	return nil
}

func (s *Store) VerifyRollbackPostUnlock(ctx context.Context, vmk *memguard.LockedBuffer) error {
	if vmk == nil || !vmk.IsAlive() {
		return fmt.Errorf("verify rollback post-unlock: vmk is nil or destroyed")
	}

	counter, err := s.versionCounter(ctx)
	if err != nil {
		return err
	}

	var stored string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM vault_meta WHERE key = ?`, versionCounterHMACMeta).Scan(&stored); err != nil {
		return fmt.Errorf("read version counter hmac: %w", err)
	}

	expected := computeVersionCounterHMAC(vmk.Bytes(), counter)
	storedBytes, err := hex.DecodeString(stored)
	if err != nil {
		return fmt.Errorf("decode stored version counter hmac: %w", err)
	}

	if !hmac.Equal(storedBytes, expected) {
		return fmt.Errorf("%w: version counter hmac mismatch", ErrRollbackDetected)
	}

	return nil
}

func (s *Store) setVersionCounter(ctx context.Context, value uint64) error {
	if _, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO vault_meta(key, value) VALUES(?, ?)`, versionCounterMetaKey, strconv.FormatUint(value, 10)); err != nil {
		return fmt.Errorf("set version counter: %w", err)
	}
	return nil
}

func (s *Store) versionCounter(ctx context.Context) (uint64, error) {
	var value string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM vault_meta WHERE key = ?`, versionCounterMetaKey).Scan(&value); err != nil {
		return 0, fmt.Errorf("read version counter: %w", err)
	}

	counter, err := parseUint(value)
	if err != nil {
		return 0, fmt.Errorf("parse version counter: %w", err)
	}
	return counter, nil
}

func computeVersionCounterHMAC(vmk []byte, version uint64) []byte {
	mac := hmac.New(sha256.New, vmk)
	mac.Write([]byte(strconv.FormatUint(version, 10)))
	return mac.Sum(nil)
}

func writeVersionCounterFile(path string, version uint64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("write rollback version file: create dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(strconv.FormatUint(version, 10)), 0o600); err != nil {
		return fmt.Errorf("write rollback version file: %w", err)
	}
	return nil
}

func parseUint(raw string) (uint64, error) {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}
