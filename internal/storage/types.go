package storage

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound         = errors.New("storage: not found")
	ErrSchemaTooNew     = errors.New("storage: schema version newer than code")
	ErrRollbackDetected = errors.New("storage: rollback detected")
)

type Host struct {
	ID        string
	Name      string
	Address   string
	Port      int
	User      string
	EnvRefs   map[string]string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type HostFilter struct {
	Tag            string
	IncludeDeleted bool
}

type IdentityStatus string

const (
	IdentityStatusActive  IdentityStatus = "active"
	IdentityStatusRetired IdentityStatus = "retired"
)

type Identity struct {
	ID         string
	Name       string
	Kind       string
	PublicKey  string
	PrivateKey []byte
	Status     IdentityStatus
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  *time.Time
}

type Secret struct {
	ID        string
	Name      string
	Value     []byte
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type PasskeyEnrollment struct {
	ID                 string
	Label              string
	CredentialID       []byte
	PublicKeyCOSE      []byte
	AAGUID             []byte
	SupportsHMACSecret bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DeletedAt          *time.Time
}

type AuditEvent struct {
	ID string

	// Legacy fields kept for compatibility with existing call sites.
	EventType string
	Actor     string
	Metadata  string

	Action      string
	TargetType  string
	TargetID    string
	Result      string
	DetailsJSON string
	PrevHash    string
	EventHash   string
	CreatedAt   time.Time
}

type AuditFilter struct {
	Action   string
	TargetID string
	Since    *time.Time
	Until    *time.Time
	Limit    int
}

type SessionHistory struct {
	ID        string
	HostID    string
	StartedAt time.Time
	EndedAt   *time.Time
	ExitCode  *int
}

type Template struct {
	ID        string
	Name      string
	Content   string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type PendingOp struct {
	ID            string
	OperationType string
	TargetID      string
	State         string
	Payload       string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// WrappedVMKBundle holds the artifacts produced when wrapping the VMK with a
// passphrase-derived KEK during vault init. All binary fields are hex-encoded
// for storage in vault_meta's TEXT value column.
type WrappedVMKBundle struct {
	Ciphertext    string `json:"ciphertext"`
	Nonce         string `json:"nonce"`
	AAD           string `json:"aad"`
	Argon2Salt    string `json:"argon2_salt"`
	CommitmentTag string `json:"commitment_tag"`
	Memory        uint32 `json:"argon2_memory"`
	Iterations    uint32 `json:"argon2_iterations"`
	Parallelism   uint8  `json:"argon2_parallelism"`
	KeyLen        uint32 `json:"argon2_key_len"`
}

type HostRepository interface {
	Create(ctx context.Context, host *Host) error
	Get(ctx context.Context, name string) (*Host, error)
	List(ctx context.Context, filter HostFilter) ([]Host, error)
	Update(ctx context.Context, host *Host) error
	Delete(ctx context.Context, name string) error
	AddTag(ctx context.Context, hostID, tag string) error
	RemoveTag(ctx context.Context, hostID, tag string) error
}

type IdentityRepository interface {
	Create(ctx context.Context, identity *Identity) error
	Get(ctx context.Context, name string) (*Identity, error)
	Update(ctx context.Context, identity *Identity) error
	Delete(ctx context.Context, name string) error
}

type SecretRepository interface {
	Create(ctx context.Context, secret *Secret) error
	Get(ctx context.Context, name string) (*Secret, error)
	Update(ctx context.Context, secret *Secret) error
	Delete(ctx context.Context, name string) error
}

type PasskeyRepository interface {
	Create(ctx context.Context, enrollment *PasskeyEnrollment) error
	GetByLabel(ctx context.Context, label string) (*PasskeyEnrollment, error)
	GetByCredentialID(ctx context.Context, credentialID []byte) (*PasskeyEnrollment, error)
	Update(ctx context.Context, enrollment *PasskeyEnrollment) error
	Delete(ctx context.Context, label string) error
}

type AuditRepository interface {
	Append(ctx context.Context, event *AuditEvent) error
	AppendWithTip(ctx context.Context, event *AuditEvent, tip string) error
	List(ctx context.Context, filter AuditFilter) ([]AuditEvent, error)
	ChainTip(ctx context.Context) (string, error)
	SetChainTip(ctx context.Context, tip string) error
}

type SessionRepository interface {
	RecordStart(ctx context.Context, entry *SessionHistory) error
	RecordEnd(ctx context.Context, sessionID string, exitCode int) error
	ListByHostID(ctx context.Context, hostID string) ([]SessionHistory, error)
}

type TemplateRepository interface {
	Create(ctx context.Context, template *Template) error
	Get(ctx context.Context, name string) (*Template, error)
	List(ctx context.Context) ([]Template, error)
	Update(ctx context.Context, template *Template) error
	Delete(ctx context.Context, name string) error
}

type PendingOpRepository interface {
	Create(ctx context.Context, op *PendingOp) error
	MarkCompleted(ctx context.Context, id string) error
	ListIncomplete(ctx context.Context) ([]PendingOp, error)
}
