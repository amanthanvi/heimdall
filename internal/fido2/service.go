package fido2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/awnumar/memguard"
)

const defaultRPID = "heimdall.cli"

type Service struct {
	auth     Authenticator
	passkeys storage.PasskeyRepository
	audit    AuditRecorder
	rpID     string

	mu          sync.RWMutex
	reauthByPID map[int]time.Time
}

func NewService(auth Authenticator, passkeys storage.PasskeyRepository, audit AuditRecorder) *Service {
	return &Service{
		auth:        auth,
		passkeys:    passkeys,
		audit:       audit,
		rpID:        defaultRPID,
		reauthByPID: map[int]time.Time{},
	}
}

func (s *Service) Enroll(ctx context.Context, label, userName string) (*storage.PasskeyEnrollment, error) {
	if s == nil || s.auth == nil {
		return nil, dependencyUnavailableError("passkey enrollment")
	}
	if s.passkeys == nil {
		return nil, fmt.Errorf("fido2 enroll: passkey repository is nil")
	}
	if label == "" {
		return nil, fmt.Errorf("fido2 enroll: label is required")
	}

	userHandle, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("fido2 enroll: generate user handle: %w", err)
	}
	if userName == "" {
		userName = label
	}

	cred, err := s.auth.MakeCredential(MakeCredentialOpts{
		RPID:              s.rpID,
		UserHandle:        userHandle,
		UserName:          userName,
		Algorithm:         -7,
		RequireHMACSecret: true,
		UVPolicy:          "preferred",
	})
	if err != nil {
		return nil, fmt.Errorf("fido2 enroll: make credential: %w", err)
	}

	enrollment := &storage.PasskeyEnrollment{
		Label:              label,
		CredentialID:       append([]byte(nil), cred.CredentialID...),
		PublicKeyCOSE:      append([]byte(nil), cred.PublicKeyCOSE...),
		AAGUID:             append([]byte(nil), cred.AAGUID...),
		SupportsHMACSecret: cred.SupportsHMACSecret,
	}
	if err := s.passkeys.Create(ctx, enrollment); err != nil {
		if isDuplicateLabelError(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateLabel, label)
		}
		return nil, fmt.Errorf("fido2 enroll: persist enrollment: %w", err)
	}

	s.recordAudit(ctx, "passkey.enroll", "passkey", label, "success")
	return enrollment, nil
}

func (s *Service) UnlockWithPasskey(
	ctx context.Context,
	label string,
	wrapped crypto.WrappedKey,
	commitmentTag []byte,
	vaultSalt []byte,
	hmacSecretSalt []byte,
) (*memguard.LockedBuffer, error) {
	if s == nil || s.auth == nil {
		return nil, dependencyUnavailableError("vault unlock --passkey")
	}
	if s.passkeys == nil {
		return nil, fmt.Errorf("fido2 unlock: passkey repository is nil")
	}

	enrollment, err := s.passkeys.GetByLabel(ctx, label)
	if err != nil {
		return nil, fmt.Errorf("fido2 unlock: load enrollment: %w", err)
	}
	if !enrollment.SupportsHMACSecret {
		return nil, fmt.Errorf("%w: enrollment %q", ErrHMACSecretUnsupported, label)
	}

	clientDataHash, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("fido2 unlock: generate client data hash: %w", err)
	}

	assertion, err := s.auth.GetAssertion(GetAssertionOpts{
		RPID:              s.rpID,
		CredentialID:      enrollment.CredentialID,
		ClientDataHash:    clientDataHash,
		RequireHMACSecret: true,
		HMACSecretSalt:    hmacSecretSalt,
		UVPolicy:          "preferred",
	})
	if err != nil {
		return nil, authFailedError("passkey assertion failed", err)
	}

	kek, err := crypto.DeriveKEKFromHMACSecret(assertion.HMACSecretOutput, vaultSalt)
	if err != nil {
		return nil, fmt.Errorf("fido2 unlock: derive kek: %w", err)
	}
	defer memguard.WipeBytes(kek)
	vmk, err := crypto.UnwrapVMK(kek, wrapped, commitmentTag)
	if err != nil {
		return nil, authFailedError("vault unlock failed", err)
	}

	s.recordAudit(ctx, "vault.unlock", "vault", "", "success")
	return vmk, nil
}

func (s *Service) Reauthenticate(ctx context.Context, label string, pid int) error {
	if s == nil || s.auth == nil {
		return dependencyUnavailableError("passkey re-auth")
	}
	if s.passkeys == nil {
		return fmt.Errorf("fido2 re-auth: passkey repository is nil")
	}
	if pid <= 0 {
		return fmt.Errorf("fido2 re-auth: pid must be > 0")
	}

	enrollment, err := s.passkeys.GetByLabel(ctx, label)
	if err != nil {
		return authFailedError("passkey enrollment lookup failed", err)
	}

	clientDataHash, err := randomBytes(32)
	if err != nil {
		return fmt.Errorf("fido2 re-auth: generate client data hash: %w", err)
	}

	assertion, err := s.auth.GetAssertion(GetAssertionOpts{
		RPID:           s.rpID,
		CredentialID:   enrollment.CredentialID,
		ClientDataHash: clientDataHash,
		UVPolicy:       "required",
	})
	if err != nil {
		return authFailedError("passkey assertion failed", err)
	}

	if err := VerifyAssertionSignature(enrollment.PublicKeyCOSE, assertion.AuthData, assertion.Signature); err != nil {
		return authFailedError("passkey signature verification failed", err)
	}

	now := time.Now().UTC()
	s.mu.Lock()
	s.reauthByPID[pid] = now
	s.mu.Unlock()

	s.recordAudit(ctx, "passkey.re-auth", "auth", fmt.Sprintf("pid=%d", pid), "success")
	return nil
}

func (s *Service) LastReauthForPID(pid int) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.reauthByPID[pid]
	return ts, ok
}

func (s *Service) Close() error {
	if s == nil || s.auth == nil {
		return nil
	}
	return s.auth.Close()
}

func (s *Service) recordAudit(ctx context.Context, action, targetType, targetID, result string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, AuditEvent{
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Result:     result,
	})
}

func PasskeyCommandUnavailable(command string) error {
	return dependencyUnavailableError(fmt.Sprintf("heimdall passkey %s", command))
}

func VaultUnlockPasskeyUnavailable() error {
	return dependencyUnavailableError("heimdall vault unlock --passkey")
}

func VerifyAssertionSignature(publicKeyCOSE, authData, signature []byte) error {
	if len(publicKeyCOSE) != ed25519.PublicKeySize {
		return fmt.Errorf("unsupported public key format")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyCOSE), authData, signature) {
		return fmt.Errorf("signature verify failed")
	}
	return nil
}

func randomBytes(size int) ([]byte, error) {
	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func isDuplicateLabelError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrDuplicateLabel) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") && strings.Contains(msg, "label")
}
