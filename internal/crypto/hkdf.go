package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const hmacSecretKEKInfo = "heimdall-hmac-secret-kek-v1"

var ErrInvalidHKDFInput = errors.New("invalid hkdf input")

func DeriveHKDFSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	if len(ikm) == 0 {
		return nil, fmt.Errorf("%w: ikm must not be empty", ErrInvalidHKDFInput)
	}
	if length <= 0 {
		return nil, fmt.Errorf("%w: length must be > 0", ErrInvalidHKDFInput)
	}

	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("derive hkdf-sha256 output: %w", err)
	}
	return out, nil
}

func DeriveKEKFromHMACSecret(hmacOutput []byte, vaultSalt []byte) ([]byte, error) {
	key, err := DeriveHKDFSHA256(hmacOutput, vaultSalt, []byte(hmacSecretKEKInfo), int(DefaultArgon2KeyLen))
	if err != nil {
		return nil, fmt.Errorf("derive kek from hmac secret: %w", err)
	}
	return key, nil
}
