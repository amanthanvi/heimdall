package app

import (
	"context"
	"errors"
	"time"

	"github.com/amanthanvi/heimdall/internal/storage"
)

var (
	ErrValidation         = errors.New("app: validation failed")
	ErrDuplicateName      = errors.New("app: duplicate name")
	ErrReauthRequired     = errors.New("app: re-auth required")
	ErrUnsupportedKeyType = errors.New("app: unsupported key type")
)

type RevealPolicy string

const (
	RevealPolicyOncePerUnlock RevealPolicy = "once-per-unlock"
	RevealPolicyAlwaysReauth  RevealPolicy = "always-reauth"
)

type KeyType string

const (
	KeyTypeEd25519 KeyType = "ed25519"
	KeyTypeRSA     KeyType = "rsa"
)

const (
	SortByName          = "name"
	SortByLastConnected = "last_connected"
)

type CreateHostRequest struct {
	Name    string
	Address string
	Port    int
	User    string
	Tags    []string
	Group   string
	EnvRefs map[string]string
}

type UpdateHostRequest struct {
	Name    string
	NewName string
	Address *string
	Port    *int
	User    *string
	Tags    *[]string
	EnvRefs map[string]string
}

type ListHostsRequest struct {
	Tag    string
	Group  string
	Search string
	SortBy string
}

type CreateSecretRequest struct {
	Name         string
	Value        []byte
	RevealPolicy RevealPolicy
}

type SecretMeta struct {
	ID           string
	Name         string
	RevealPolicy RevealPolicy
}

type GenerateKeyRequest struct {
	Name string
	Type KeyType
}

type ImportKeyRequest struct {
	Name       string
	PrivateKey []byte
	Passphrase []byte
}

type ExportKeyRequest struct {
	Name   string
	Output string
}

type KeyMeta struct {
	ID         string
	Name       string
	Type       KeyType
	PublicKey  string
	PrivateKey []byte
}

type ConnectOpts struct {
	User         string
	Port         int
	JumpHosts    []string
	Forwards     []string
	IdentityPath string
	KnownHosts   string
	PrintCmd     bool
	DryRun       bool
}

type ConnectPlan struct {
	Args         []string
	RedactedArgs []string
}

type ImportWarning struct {
	Line    int
	Message string
}

type ConflictMode string

const (
	ConflictModeSkip      ConflictMode = "skip"
	ConflictModeOverwrite ConflictMode = "overwrite"
	ConflictModeRename    ConflictMode = "rename"
)

type ExportBundle struct {
	Version    int              `json:"version"`
	Hosts      []ExportHost     `json:"hosts"`
	Identities []ExportIdentity `json:"identities"`
	Secrets    []ExportSecret   `json:"secrets"`
}

type ExportHost struct {
	Name    string            `json:"name"`
	Address string            `json:"address"`
	Port    int               `json:"port"`
	User    string            `json:"user,omitempty"`
	Tags    []string          `json:"tags,omitempty"`
	EnvRefs map[string]string `json:"env_refs,omitempty"`
}

type ExportIdentity struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key,omitempty"`
	Status    string `json:"status,omitempty"`
}

type ExportSecret struct {
	Name         string       `json:"name"`
	RevealPolicy RevealPolicy `json:"reveal_policy,omitempty"`
	SizeBytes    int64        `json:"size_bytes"`
}

type ImportCounts struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
}

type ImportResult struct {
	Hosts      ImportCounts `json:"hosts"`
	Identities ImportCounts `json:"identities"`
	Secrets    ImportCounts `json:"secrets"`
}

type BackupCreateRequest struct {
	OutputPath   string
	Passphrase   []byte
	KnownHosts   string
	ConfigPath   string
	Unencrypted  bool
	ConfirmNoEnc bool
}

type BackupRestoreRequest struct {
	InputPath       string
	Passphrase      []byte
	TargetVaultPath string
	Confirm         bool
	Overwrite       bool
}

type BackupManifest struct {
	Version   int                           `json:"version"`
	CreatedAt string                        `json:"created_at"`
	Files     map[string]BackupManifestFile `json:"files"`
}

type BackupManifestFile struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type SecretValueGetter interface {
	GetValue(ctx context.Context, name string) ([]byte, error)
}

type contextKey string

const reauthContextKey contextKey = "app.reauth"

func WithReauth(ctx context.Context) context.Context {
	return context.WithValue(ctx, reauthContextKey, true)
}

func hasReauth(ctx context.Context) bool {
	value, ok := ctx.Value(reauthContextKey).(bool)
	return ok && value
}

type hostWithLastConnected struct {
	host          storage.Host
	lastConnected time.Time
}
