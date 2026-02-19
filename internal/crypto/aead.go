package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidAEADInput     = errors.New("invalid aead input")
	ErrAuthenticationFailed = errors.New("authentication failed")
)

func SealXChaCha20Poly1305(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%w: key must be %d bytes", ErrInvalidAEADInput, chacha20poly1305.KeySize)
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidAEADInput, chacha20poly1305.NonceSizeX)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("construct xchacha20-poly1305: %w", err)
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func OpenXChaCha20Poly1305(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%w: key must be %d bytes", ErrInvalidAEADInput, chacha20poly1305.KeySize)
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidAEADInput, chacha20poly1305.NonceSizeX)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("construct xchacha20-poly1305: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}
	return plaintext, nil
}

func randomNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}
