package app

import (
	"context"
	"fmt"

	"github.com/amanthanvi/heimdall/internal/storage"
)

type SecretService struct {
	secrets storage.SecretRepository
}

func NewSecretService(secrets storage.SecretRepository) *SecretService {
	return &SecretService{secrets: secrets}
}

func (s *SecretService) Create(ctx context.Context, req CreateSecretRequest) (*SecretMeta, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("%w: secret name is required", ErrValidation)
	}
	if len(req.Value) == 0 {
		return nil, fmt.Errorf("%w: secret value is required", ErrValidation)
	}
	policy := req.RevealPolicy
	if policy == "" {
		policy = RevealPolicyOncePerUnlock
	}
	if policy != RevealPolicyAlwaysReauth && policy != RevealPolicyOncePerUnlock {
		return nil, fmt.Errorf("%w: unsupported reveal policy %q", ErrValidation, policy)
	}

	secret := &storage.Secret{
		Name:         req.Name,
		Value:        append([]byte(nil), req.Value...),
		RevealPolicy: string(policy),
	}
	if err := s.secrets.Create(ctx, secret); err != nil {
		if isDuplicateError(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateName, req.Name)
		}
		return nil, fmt.Errorf("create secret: %w", err)
	}

	return &SecretMeta{
		ID:           secret.ID,
		Name:         req.Name,
		RevealPolicy: policy,
	}, nil
}

func (s *SecretService) GetValue(ctx context.Context, name string) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: secret name is required", ErrValidation)
	}

	meta, err := s.secrets.GetMeta(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get secret value: %w", err)
	}

	policy := RevealPolicy(meta.RevealPolicy)
	if policy == "" {
		policy = RevealPolicyOncePerUnlock
	}
	switch policy {
	case RevealPolicyAlwaysReauth:
		if !hasReauth(ctx) {
			return nil, ErrReauthRequired
		}
	case RevealPolicyOncePerUnlock:
	default:
		return nil, fmt.Errorf("%w: unsupported reveal policy %q", ErrValidation, policy)
	}

	secret, err := s.secrets.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get secret value: %w", err)
	}

	return append([]byte(nil), secret.Value...), nil
}
