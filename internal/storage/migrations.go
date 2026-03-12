package storage

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"time"
)

const (
	schemaVersionMetaKey    = "schema_version"
	versionCounterMetaKey   = "version_counter"
	versionCounterHMACMeta  = "version_counter_hmac"
	auditChainTipMetaKey    = "audit_chain_tip"
	rollbackVersionFileName = "vault.version"
)

type Migration struct {
	Version     int
	Description string
	Up          func(tx *sql.Tx) error
}

var defaultMigrations = []Migration{
	{
		Version:     1,
		Description: "create entity tables",
		Up: func(tx *sql.Tx) error {
			statements := []string{
				`CREATE TABLE IF NOT EXISTS hosts (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL UNIQUE,
					address TEXT NOT NULL,
					port INTEGER NOT NULL,
					user TEXT,
					notes_ciphertext BLOB,
					notes_nonce BLOB,
					key_name TEXT,
					identity_file TEXT,
					proxy_jump TEXT,
					known_hosts_policy TEXT NOT NULL DEFAULT '',
					forward_agent INTEGER NOT NULL DEFAULT 0,
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL,
					deleted_at TEXT
				)`,
				`CREATE TABLE IF NOT EXISTS host_tags (
					host_id TEXT NOT NULL,
					tag TEXT NOT NULL,
					PRIMARY KEY (host_id, tag),
					FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
				)`,
				`CREATE TABLE IF NOT EXISTS identities (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL UNIQUE,
					kind TEXT NOT NULL,
					public_key TEXT,
					private_key_ciphertext BLOB,
					private_key_nonce BLOB,
					status TEXT NOT NULL,
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL,
					deleted_at TEXT
				)`,
				`CREATE TABLE IF NOT EXISTS secrets (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL UNIQUE,
					value_ciphertext BLOB NOT NULL,
					value_nonce BLOB NOT NULL,
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL,
					deleted_at TEXT
				)`,
				`CREATE TABLE IF NOT EXISTS passkey_enrollments (
					id TEXT PRIMARY KEY,
					label TEXT NOT NULL UNIQUE,
					credential_id BLOB NOT NULL,
					public_key_cose BLOB NOT NULL,
					aaguid BLOB,
					supports_hmac_secret INTEGER NOT NULL DEFAULT 0,
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL,
					deleted_at TEXT
				)`,
				`CREATE TABLE IF NOT EXISTS audit_events (
					id TEXT PRIMARY KEY,
					event_type TEXT NOT NULL,
					actor TEXT,
					metadata TEXT,
					action TEXT NOT NULL DEFAULT '',
					target_type TEXT,
					target_id TEXT,
					result TEXT NOT NULL DEFAULT '',
					details_json TEXT NOT NULL DEFAULT '{}',
					prev_hash TEXT NOT NULL DEFAULT '',
					event_hash TEXT NOT NULL DEFAULT '',
					created_at TEXT NOT NULL
				)`,
				`CREATE TABLE IF NOT EXISTS session_history (
					id TEXT PRIMARY KEY,
					host_id TEXT NOT NULL,
					started_at TEXT NOT NULL,
					ended_at TEXT,
					exit_code INTEGER,
					FOREIGN KEY(host_id) REFERENCES hosts(id)
				)`,
				`INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('` + versionCounterMetaKey + `', '1')`,
				`INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('` + versionCounterHMACMeta + `', '')`,
				`INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('` + auditChainTipMetaKey + `', '')`,
			}
			for _, stmt := range statements {
				if _, err := tx.Exec(stmt); err != nil {
					return fmt.Errorf("apply migration v1 statement: %w", err)
				}
			}
			return nil
		},
	},
	{
		Version:     2,
		Description: "reserved for removed host env refs migration",
		Up: func(tx *sql.Tx) error {
			_ = tx
			return nil
		},
	},
	{
		Version:     3,
		Description: "reserved for removed pending operations table",
		Up: func(tx *sql.Tx) error {
			_ = tx
			return nil
		},
	},
	{
		Version:     4,
		Description: "add audit hash chain fields",
		Up: func(tx *sql.Tx) error {
			type columnSpec struct {
				name       string
				definition string
			}

			columns := []columnSpec{
				{name: "action", definition: `TEXT NOT NULL DEFAULT ''`},
				{name: "target_type", definition: `TEXT`},
				{name: "target_id", definition: `TEXT`},
				{name: "result", definition: `TEXT NOT NULL DEFAULT ''`},
				{name: "details_json", definition: `TEXT NOT NULL DEFAULT '{}'`},
				{name: "prev_hash", definition: `TEXT NOT NULL DEFAULT ''`},
				{name: "event_hash", definition: `TEXT NOT NULL DEFAULT ''`},
			}
			for _, column := range columns {
				exists, err := columnExists(tx, "audit_events", column.name)
				if err != nil {
					return err
				}
				if exists {
					continue
				}
				if _, err := tx.Exec(`ALTER TABLE audit_events ADD COLUMN ` + column.name + ` ` + column.definition); err != nil {
					return fmt.Errorf("add audit_events.%s: %w", column.name, err)
				}
			}

			if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_action_created_at ON audit_events(action, created_at)`); err != nil {
				return fmt.Errorf("create audit action index: %w", err)
			}
			if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_target_id_created_at ON audit_events(target_id, created_at)`); err != nil {
				return fmt.Errorf("create audit target index: %w", err)
			}
			if _, err := tx.Exec(`INSERT OR IGNORE INTO vault_meta(key, value) VALUES(?, '')`, auditChainTipMetaKey); err != nil {
				return fmt.Errorf("initialize audit chain tip: %w", err)
			}
			return nil
		},
	},
	{
		Version:     5,
		Description: "reserved for removed host env refs backfill",
		Up: func(tx *sql.Tx) error {
			_ = tx
			return nil
		},
	},
	{
		Version:     6,
		Description: "add canonical host policy fields",
		Up: func(tx *sql.Tx) error {
			type columnSpec struct {
				name       string
				definition string
			}
			columns := []columnSpec{
				{name: "notes_ciphertext", definition: `BLOB`},
				{name: "notes_nonce", definition: `BLOB`},
				{name: "known_hosts_policy", definition: `TEXT NOT NULL DEFAULT ''`},
				{name: "forward_agent", definition: `INTEGER NOT NULL DEFAULT 0`},
			}
			for _, column := range columns {
				exists, err := columnExists(tx, "hosts", column.name)
				if err != nil {
					return err
				}
				if exists {
					continue
				}
				if _, err := tx.Exec(`ALTER TABLE hosts ADD COLUMN ` + column.name + ` ` + column.definition); err != nil {
					return fmt.Errorf("add hosts.%s: %w", column.name, err)
				}
			}
			return nil
		},
	},
	{
		Version:     7,
		Description: "drop reboot-deferred legacy schema",
		Up: func(tx *sql.Tx) error {
			for _, table := range []string{"templates", "pending_ops"} {
				if _, err := tx.Exec(`DROP TABLE IF EXISTS ` + table); err != nil {
					return fmt.Errorf("drop %s: %w", table, err)
				}
			}

			hasEnvRefs, err := columnExists(tx, "hosts", "env_refs")
			if err != nil {
				return err
			}
			if hasEnvRefs {
				if _, err := tx.Exec(`ALTER TABLE hosts DROP COLUMN env_refs`); err != nil {
					return fmt.Errorf("drop hosts.env_refs: %w", err)
				}
			}
			return nil
		},
	},
}

func DefaultMigrations() []Migration {
	out := make([]Migration, len(defaultMigrations))
	copy(out, defaultMigrations)
	return out
}

func CurrentSchemaVersion() int {
	return maxMigrationVersion(defaultMigrations)
}

func RunMigrations(db *sql.DB, migrations []Migration) error {
	if db == nil {
		return fmt.Errorf("run migrations: db is nil")
	}

	if err := ensureMigrationTables(db); err != nil {
		return err
	}

	ordered := make([]Migration, len(migrations))
	copy(ordered, migrations)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Version < ordered[j].Version })

	current, err := readSchemaVersion(db)
	if err != nil {
		return err
	}

	maxVersion := maxMigrationVersion(ordered)
	if current > maxVersion {
		return fmt.Errorf("%w: db=%d code=%d", ErrSchemaTooNew, current, maxVersion)
	}

	for _, migration := range ordered {
		if migration.Version <= current {
			continue
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration v%d: %w", migration.Version, err)
		}

		if err := migration.Up(tx); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration v%d (%s): %w", migration.Version, migration.Description, err)
		}

		if _, err := tx.Exec(`INSERT OR REPLACE INTO schema_migrations(version, applied_at) VALUES (?, ?)`, migration.Version, nowUTCString()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record schema migration v%d: %w", migration.Version, err)
		}

		if _, err := tx.Exec(`INSERT OR REPLACE INTO vault_meta(key, value) VALUES(?, ?)`, schemaVersionMetaKey, strconv.Itoa(migration.Version)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("update schema version v%d: %w", migration.Version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration v%d: %w", migration.Version, err)
		}
	}

	if _, err := db.Exec(`INSERT OR IGNORE INTO vault_meta(key, value) VALUES(?, '1')`, versionCounterMetaKey); err != nil {
		return fmt.Errorf("ensure version counter meta: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO vault_meta(key, value) VALUES(?, '')`, versionCounterHMACMeta); err != nil {
		return fmt.Errorf("ensure version hmac meta: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO vault_meta(key, value) VALUES(?, '')`, auditChainTipMetaKey); err != nil {
		return fmt.Errorf("ensure audit chain tip meta: %w", err)
	}

	return nil
}

func ensureMigrationTables(db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS vault_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`,
		`INSERT OR IGNORE INTO vault_meta(key, value) VALUES('` + schemaVersionMetaKey + `', '0')`,
	}
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure migration tables: %w", err)
		}
	}
	return nil
}

func readSchemaVersion(db *sql.DB) (int, error) {
	var versionStr string
	if err := db.QueryRow(`SELECT value FROM vault_meta WHERE key = ?`, schemaVersionMetaKey).Scan(&versionStr); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		return 0, fmt.Errorf("parse schema version %q: %w", versionStr, err)
	}
	return version, nil
}

func maxMigrationVersion(migrations []Migration) int {
	max := 0
	for _, migration := range migrations {
		if migration.Version > max {
			max = migration.Version
		}
	}
	return max
}

func columnExists(tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, fmt.Errorf("query table info %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			cid     int
			name    string
			typeStr string
			notNull int
			dfltVal sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &typeStr, &notNull, &dfltVal, &pk); err != nil {
			return false, fmt.Errorf("scan table info %s: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate table info %s: %w", table, err)
	}
	return false, nil
}

func nowUTCString() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
