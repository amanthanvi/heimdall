package app

import (
	"context"
	"fmt"
	"sync"

	"github.com/amanthanvi/heimdall/internal/storage"
)

type SecretService struct {
	secrets storage.SecretRepository

	mu              sync.Mutex
	revealPolicy    map[string]RevealPolicy
	revealedSecrets map[string]bool
}

func NewSecretService(secrets storage.SecretRepository) *SecretService {
	return &SecretService{
		secrets:         secrets,
		revealPolicy:    map[string]RevealPolicy{},
		revealedSecrets: map[string]bool{},
	}
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
		Name:  req.Name,
		Value: append([]byte(nil), req.Value...),
	}
	if err := s.secrets.Create(ctx, secret); err != nil {
		if isDuplicateError(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateName, req.Name)
		}
		return nil, fmt.Errorf("create secret: %w", err)
	}

	s.mu.Lock()
	s.revealPolicy[req.Name] = policy
	s.mu.Unlock()

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

	policy := s.policyForSecret(name)
	switch policy {
	case RevealPolicyAlwaysReauth:
		if !hasReauth(ctx) {
			return nil, ErrReauthRequired
		}
	case RevealPolicyOncePerUnlock:
		if !s.wasRevealed(name) && !hasReauth(ctx) {
			return nil, ErrReauthRequired
		}
	default:
		return nil, fmt.Errorf("%w: unsupported reveal policy %q", ErrValidation, policy)
	}

	secret, err := s.secrets.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get secret value: %w", err)
	}

	if hasReauth(ctx) {
		s.mu.Lock()
		s.revealedSecrets[name] = true
		s.mu.Unlock()
	}
	return append([]byte(nil), secret.Value...), nil
}

func (s *SecretService) ResetRevealCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revealedSecrets = map[string]bool{}
}

func (s *SecretService) policyForSecret(name string) RevealPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, ok := s.revealPolicy[name]
	if !ok {
		return RevealPolicyOncePerUnlock
	}
	return policy
}

func (s *SecretService) wasRevealed(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revealedSecrets[name]
}
