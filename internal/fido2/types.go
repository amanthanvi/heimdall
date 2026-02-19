package fido2

import "context"

// AuditRecorder records events into the hash-chained audit log.
// Satisfied by *audit.Service.
type AuditRecorder interface {
	Record(ctx context.Context, event AuditEvent) error
}

// AuditEvent mirrors audit.Event to avoid import cycle fido2 -> audit.
type AuditEvent struct {
	Action     string
	TargetType string
	TargetID   string
	Result     string
	Details    any
}

type Authenticator interface {
	MakeCredential(opts MakeCredentialOpts) (*Credential, error)
	GetAssertion(opts GetAssertionOpts) (*Assertion, error)
	Close() error
}

type MakeCredentialOpts struct {
	RPID              string
	UserHandle        []byte
	UserName          string
	Algorithm         int
	RequireHMACSecret bool
	UVPolicy          string
	PIN               []byte
}

type GetAssertionOpts struct {
	RPID              string
	CredentialID      []byte
	ClientDataHash    []byte
	RequireHMACSecret bool
	HMACSecretSalt    []byte
	UVPolicy          string
	PIN               []byte
}

type Credential struct {
	CredentialID       []byte
	PublicKeyCOSE      []byte
	AAGUID             []byte
	SupportsHMACSecret bool
}

type Assertion struct {
	AuthData         []byte
	Signature        []byte
	HMACSecretOutput []byte
}
