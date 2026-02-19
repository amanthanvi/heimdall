//go:build nofido2 || !fido2

package fido2

type noFIDO2Authenticator struct{}

func NewAuthenticator(_ string) (Authenticator, error) {
	return &noFIDO2Authenticator{}, nil
}

func (a *noFIDO2Authenticator) MakeCredential(_ MakeCredentialOpts) (*Credential, error) {
	return nil, dependencyUnavailableError("passkey enrollment")
}

func (a *noFIDO2Authenticator) GetAssertion(_ GetAssertionOpts) (*Assertion, error) {
	return nil, dependencyUnavailableError("passkey assertion")
}

func (a *noFIDO2Authenticator) Close() error {
	return nil
}
