package fido2

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
