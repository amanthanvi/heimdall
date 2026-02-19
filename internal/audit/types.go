package audit

import "time"

const (
	ActionVaultUnlock           = "vault.unlock"
	ActionVaultLock             = "vault.lock"
	ActionVaultChangePassphrase = "vault.change-passphrase"

	ActionSecretReveal = "secret.reveal"
	ActionSecretExport = "secret.export"
	ActionSecretInject = "secret.inject"
	ActionSecretCreate = "secret.create"
	ActionSecretDelete = "secret.delete"

	ActionKeyExport   = "key.export"
	ActionKeyDelete   = "key.delete"
	ActionKeyRotate   = "key.rotate"
	ActionKeyAgentAdd = "key.agent-add"

	ActionPasskeyEnroll = "passkey.enroll"
	ActionPasskeyRemove = "passkey.remove"
	ActionPasskeyReauth = "passkey.re-auth"

	ActionHostTrust  = "host.trust"
	ActionHostCreate = "host.create"
	ActionHostDelete = "host.delete"

	ActionBackupCreate  = "backup.create"
	ActionBackupRestore = "backup.restore"

	ActionSystemDaemonStart  = "system.daemon-start"
	ActionSystemDaemonStop   = "system.daemon-stop"
	ActionSystemConfigReload = "system.config-reload"
	ActionSystemAuthFailure  = "system.auth-failure"
)

var AllActionTypes = []string{
	ActionVaultUnlock,
	ActionVaultLock,
	ActionVaultChangePassphrase,
	ActionSecretReveal,
	ActionSecretExport,
	ActionSecretInject,
	ActionSecretCreate,
	ActionSecretDelete,
	ActionKeyExport,
	ActionKeyDelete,
	ActionKeyRotate,
	ActionKeyAgentAdd,
	ActionPasskeyEnroll,
	ActionPasskeyRemove,
	ActionPasskeyReauth,
	ActionHostTrust,
	ActionHostCreate,
	ActionHostDelete,
	ActionBackupCreate,
	ActionBackupRestore,
	ActionSystemDaemonStart,
	ActionSystemDaemonStop,
	ActionSystemConfigReload,
	ActionSystemAuthFailure,
}

type Event struct {
	Timestamp  time.Time
	Action     string
	TargetType string
	TargetID   string
	Result     string
	Actor      string
	Details    any
}

type Filter struct {
	Action   string
	TargetID string
	Since    *time.Time
	Until    *time.Time
	Limit    int
}

type RecordedEvent struct {
	ID          string
	Timestamp   time.Time
	Action      string
	TargetType  string
	TargetID    string
	Result      string
	DetailsJSON string
	PrevHash    string
	EventHash   string
}

type VerifyResult struct {
	Valid      bool
	EventCount int
	ChainTip   string
	Error      string
}
