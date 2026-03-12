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
	Name             string
	Address          string
	Port             int
	User             string
	Tags             []string
	Notes            string
	KeyName          string
	IdentityFile     string
	ProxyJump        string
	KnownHostsPolicy string
	ForwardAgent     bool
}

type UpdateHostRequest struct {
	Name                  string
	NewName               string
	Address               *string
	Port                  *int
	User                  *string
	Tags                  *[]string
	Notes                 *string
	ClearNotes            bool
	KeyName               *string
	IdentityFile          *string
	ProxyJump             *string
	KnownHostsPolicy      *string
	ClearKnownHostsPolicy bool
	ForwardAgent          *bool
}

type ListHostsRequest struct {
	Tag    string
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
	User             string
	Port             int
	JumpHosts        []string
	Forwards         []string
	KeyName          string
	IdentityPath     string
	KnownHosts       string
	KnownHostsPolicy string
	ForwardAgent     bool
	ForwardAgentSet  bool
	ProxyJumpNone    bool
	InsecureHostKey  bool
	IgnoreSSHConfig  bool
	PrintCmd         bool
	DryRun           bool
}

type ConnectPlan struct {
	Binary       string
	Args         []string
	RedactedArgs []string
	Env          []string
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
