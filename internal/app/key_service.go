package app

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/amanthanvi/heimdall/internal/storage"
	"golang.org/x/crypto/ssh"
)

const (
	defaultRSAKeyBits = 3072
)

type KeyService struct {
	identities storage.IdentityRepository
}

func NewKeyService(identities storage.IdentityRepository) *KeyService {
	return &KeyService{identities: identities}
}

func (s *KeyService) Generate(ctx context.Context, req GenerateKeyRequest) (*KeyMeta, error) {
	if strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("%w: key name is required", ErrValidation)
	}

	keyType := req.Type
	if keyType == "" {
		keyType = KeyTypeEd25519
	}

	privateKey, err := generatePrivateKey(keyType)
	if err != nil {
		return nil, err
	}

	privatePEM, publicKey, err := encodeSSHKeyPair(privateKey, req.Name)
	if err != nil {
		return nil, err
	}

	identity := &storage.Identity{
		Name:       req.Name,
		Kind:       string(keyType),
		PublicKey:  publicKey,
		PrivateKey: privatePEM,
		Status:     storage.IdentityStatusActive,
	}
	if err := s.identities.Create(ctx, identity); err != nil {
		if isDuplicateError(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateName, req.Name)
		}
		return nil, fmt.Errorf("generate key: %w", err)
	}

	return &KeyMeta{
		ID:         identity.ID,
		Name:       identity.Name,
		Type:       keyType,
		PublicKey:  identity.PublicKey,
		PrivateKey: append([]byte(nil), privatePEM...),
	}, nil
}

func (s *KeyService) Import(ctx context.Context, req ImportKeyRequest) (*KeyMeta, error) {
	if strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("%w: key name is required", ErrValidation)
	}
	if len(req.PrivateKey) == 0 {
		return nil, fmt.Errorf("%w: private key is required", ErrValidation)
	}

	privateKey, err := parseSSHPrivateKey(req.PrivateKey, req.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("import key: parse private key: %w", err)
	}
	privatePEM, publicKey, err := encodeSSHKeyPair(privateKey, req.Name)
	if err != nil {
		return nil, err
	}

	keyType, err := keyTypeFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	identity := &storage.Identity{
		Name:       req.Name,
		Kind:       string(keyType),
		PublicKey:  publicKey,
		PrivateKey: privatePEM,
		Status:     storage.IdentityStatusActive,
	}
	if err := s.identities.Create(ctx, identity); err != nil {
		if isDuplicateError(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateName, req.Name)
		}
		return nil, fmt.Errorf("import key: %w", err)
	}

	return &KeyMeta{
		ID:         identity.ID,
		Name:       identity.Name,
		Type:       keyType,
		PublicKey:  identity.PublicKey,
		PrivateKey: append([]byte(nil), privatePEM...),
	}, nil
}

func (s *KeyService) Export(ctx context.Context, req ExportKeyRequest) error {
	if !hasReauth(ctx) {
		return ErrReauthRequired
	}
	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("%w: key name is required", ErrValidation)
	}
	if strings.TrimSpace(req.Output) == "" {
		return fmt.Errorf("%w: output path is required", ErrValidation)
	}

	identity, err := s.identities.Get(ctx, req.Name)
	if err != nil {
		return fmt.Errorf("export key: load identity: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(req.Output), 0o700); err != nil {
		return fmt.Errorf("export key: create output dir: %w", err)
	}
	if err := os.WriteFile(req.Output, identity.PrivateKey, 0o600); err != nil {
		return fmt.Errorf("export key: write file: %w", err)
	}
	return nil
}

func (s *KeyService) Rotate(ctx context.Context, name string) (*KeyMeta, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: key name is required", ErrValidation)
	}

	current, err := s.identities.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("rotate key: load existing identity: %w", err)
	}
	kind := keyTypeFromIdentity(current.Kind)

	current.Status = storage.IdentityStatusRetired
	current.Name = fmt.Sprintf("%s-retired-%d", name, time.Now().UTC().UnixNano())
	if err := s.identities.Update(ctx, current); err != nil {
		return nil, fmt.Errorf("rotate key: retire old identity: %w", err)
	}

	return s.Generate(ctx, GenerateKeyRequest{
		Name: name,
		Type: kind,
	})
}

func generatePrivateKey(keyType KeyType) (crypto.PrivateKey, error) {
	switch keyType {
	case KeyTypeEd25519:
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate key: ed25519: %w", err)
		}
		return privateKey, nil
	case KeyTypeRSA:
		privateKey, err := rsa.GenerateKey(rand.Reader, defaultRSAKeyBits)
		if err != nil {
			return nil, fmt.Errorf("generate key: rsa: %w", err)
		}
		return privateKey, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKeyType, keyType)
	}
}

func keyTypeFromPrivateKey(privateKey crypto.PrivateKey) (KeyType, error) {
	switch privateKey.(type) {
	case ed25519.PrivateKey:
		return KeyTypeEd25519, nil
	case *ed25519.PrivateKey:
		return KeyTypeEd25519, nil
	case *rsa.PrivateKey:
		return KeyTypeRSA, nil
	default:
		return "", fmt.Errorf("%w: %T", ErrUnsupportedKeyType, privateKey)
	}
}

func keyTypeFromIdentity(kind string) KeyType {
	switch strings.ToLower(kind) {
	case string(KeyTypeRSA):
		return KeyTypeRSA
	default:
		return KeyTypeEd25519
	}
}

func parseSSHPrivateKey(raw []byte, passphrase []byte) (crypto.PrivateKey, error) {
	key, err := ssh.ParseRawPrivateKey(raw)
	if err == nil {
		return key, nil
	}
	if len(passphrase) == 0 {
		return nil, err
	}
	key, err = ssh.ParseRawPrivateKeyWithPassphrase(raw, passphrase)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func encodeSSHKeyPair(privateKey crypto.PrivateKey, comment string) ([]byte, string, error) {
	block, err := ssh.MarshalPrivateKey(privateKey, comment)
	if err != nil {
		return nil, "", fmt.Errorf("encode key pair: marshal private key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(block)
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, "", fmt.Errorf("encode key pair: signer: %w", err)
	}
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return privatePEM, publicKey, nil
}
