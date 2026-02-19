package grpc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/amanthanvi/heimdall/internal/agent"
	"github.com/amanthanvi/heimdall/internal/app"
	"github.com/amanthanvi/heimdall/internal/fido2"
	"github.com/amanthanvi/heimdall/internal/storage"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

type keyAgent interface {
	AddKey(identity *agent.Identity, ttl time.Duration) error
	RemoveKey(fingerprint string) error
}

type passkeyEnroller interface {
	Enroll(ctx context.Context, label, userName string) (*storage.PasskeyEnrollment, error)
}

func (s *Server) Unlock(_ context.Context, req *v1.UnlockRequest) (*v1.UnlockResponse, error) {
	if req == nil {
		return nil, grpcstatus.Error(codes.InvalidArgument, "unlock vault: request is required")
	}

	passkeyLabel := strings.TrimSpace(req.GetPasskeyLabel())
	if passkeyLabel != "" {
		type passkeyUnlocker interface {
			UnlockWithPasskey(label string) error
		}
		unlocker, ok := s.cfg.Daemon.(passkeyUnlocker)
		if !ok {
			return nil, grpcstatus.Error(codes.FailedPrecondition, "unlock vault: passkey unlock is not supported")
		}
		if err := unlocker.UnlockWithPasskey(passkeyLabel); err != nil {
			return nil, grpcstatus.Errorf(codes.PermissionDenied, "unlock vault: %v", err)
		}
	} else {
		passphrase := []byte(req.GetPassphrase())
		if len(passphrase) == 0 {
			return nil, grpcstatus.Error(codes.InvalidArgument, "unlock vault: passphrase is required")
		}
		if err := s.cfg.Daemon.Unlock(passphrase); err != nil {
			return nil, grpcstatus.Errorf(codes.PermissionDenied, "unlock vault: %v", err)
		}
	}

	s.reauthCache.clear()
	return &v1.UnlockResponse{Unlocked: true}, nil
}

func (s *Server) CreateHost(ctx context.Context, req *v1.CreateHostRequest) (*v1.CreateHostResponse, error) {
	hostSvc := app.NewHostService(s.cfg.Store.Hosts, s.cfg.Store.Sessions)
	host, err := hostSvc.Create(ctx, app.CreateHostRequest{
		Name:    req.GetName(),
		Address: req.GetAddress(),
		Port:    int(req.GetPort()),
		User:    req.GetUser(),
		Tags:    append([]string(nil), req.GetTags()...),
		Group:   req.GetGroup(),
		EnvRefs: cloneStringMap(req.GetEnvRefs()),
	})
	if err != nil {
		return nil, mapAppError("create host", err)
	}
	return &v1.CreateHostResponse{Host: hostToProto(host)}, nil
}

func (s *Server) GetHost(ctx context.Context, req *v1.GetHostRequest) (*v1.GetHostResponse, error) {
	hostSvc := app.NewHostService(s.cfg.Store.Hosts, s.cfg.Store.Sessions)
	host, err := hostSvc.Get(ctx, req.GetName())
	if err != nil {
		return nil, mapAppError("get host", err)
	}
	return &v1.GetHostResponse{Host: hostToProto(host)}, nil
}

func (s *Server) UpdateHost(ctx context.Context, req *v1.UpdateHostRequest) (*v1.UpdateHostResponse, error) {
	updateReq := app.UpdateHostRequest{
		Name:    req.GetName(),
		NewName: req.GetNewName(),
		EnvRefs: cloneStringMap(req.GetEnvRefs()),
	}
	if address := strings.TrimSpace(req.GetAddress()); address != "" {
		updateReq.Address = &address
	}
	if req.GetPort() != 0 {
		port := int(req.GetPort())
		updateReq.Port = &port
	}
	if user := strings.TrimSpace(req.GetUser()); user != "" {
		updateReq.User = &user
	}

	if req.GetClearTags() {
		tags := []string{}
		updateReq.Tags = &tags
	} else if len(req.GetTags()) > 0 {
		tags := append([]string(nil), req.GetTags()...)
		updateReq.Tags = &tags
	}

	hostSvc := app.NewHostService(s.cfg.Store.Hosts, s.cfg.Store.Sessions)
	host, err := hostSvc.Update(ctx, updateReq)
	if err != nil {
		return nil, mapAppError("update host", err)
	}
	return &v1.UpdateHostResponse{Host: hostToProto(host)}, nil
}

func (s *Server) DeleteHost(ctx context.Context, req *v1.DeleteHostRequest) (*v1.DeleteHostResponse, error) {
	hostSvc := app.NewHostService(s.cfg.Store.Hosts, s.cfg.Store.Sessions)
	if err := hostSvc.Delete(ctx, req.GetName()); err != nil {
		return nil, mapAppError("delete host", err)
	}
	return &v1.DeleteHostResponse{}, nil
}

func (s *Server) CreateSecret(ctx context.Context, req *v1.CreateSecretRequest) (*v1.CreateSecretResponse, error) {
	secretSvc := app.NewSecretService(s.cfg.Store.Secrets)
	meta, err := secretSvc.Create(ctx, app.CreateSecretRequest{
		Name:         req.GetName(),
		Value:        append([]byte(nil), req.GetValue()...),
		RevealPolicy: app.RevealPolicy(req.GetRevealPolicy()),
	})
	if err != nil {
		return nil, mapAppError("create secret", err)
	}
	return &v1.CreateSecretResponse{
		Secret: &v1.SecretMeta{
			Id:           meta.ID,
			Name:         meta.Name,
			RevealPolicy: string(meta.RevealPolicy),
			SizeBytes:    int64(len(req.GetValue())),
		},
	}, nil
}

func (s *Server) GenerateKey(ctx context.Context, req *v1.GenerateKeyRequest) (*v1.GenerateKeyResponse, error) {
	keySvc := app.NewKeyService(s.cfg.Store.Identities)
	meta, err := keySvc.Generate(ctx, app.GenerateKeyRequest{
		Name: req.GetName(),
		Type: app.KeyType(req.GetKeyType()),
	})
	if err != nil {
		return nil, mapAppError("generate key", err)
	}
	return &v1.GenerateKeyResponse{Key: keyMetaFromApp(meta, storage.IdentityStatusActive)}, nil
}

func (s *Server) ImportKey(ctx context.Context, req *v1.ImportKeyRequest) (*v1.ImportKeyResponse, error) {
	keySvc := app.NewKeyService(s.cfg.Store.Identities)
	meta, err := keySvc.Import(ctx, app.ImportKeyRequest{
		Name:       req.GetName(),
		PrivateKey: append([]byte(nil), req.GetPrivateKey()...),
		Passphrase: append([]byte(nil), req.GetPassphrase()...),
	})
	if err != nil {
		return nil, mapAppError("import key", err)
	}
	return &v1.ImportKeyResponse{Key: keyMetaFromApp(meta, storage.IdentityStatusActive)}, nil
}

func (s *Server) ListKeys(ctx context.Context, _ *v1.ListKeysRequest) (*v1.ListKeysResponse, error) {
	rows, err := s.cfg.Store.DB().QueryContext(ctx, `
		SELECT id, name, kind, public_key, status
		FROM identities
		WHERE deleted_at IS NULL
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "list keys: %v", err)
	}
	defer rows.Close()

	items := []*v1.KeyMeta{}
	for rows.Next() {
		var (
			id        string
			name      string
			kind      string
			publicKey string
			status    string
		)
		if err := rows.Scan(&id, &name, &kind, &publicKey, &status); err != nil {
			return nil, grpcstatus.Errorf(codes.Internal, "list keys: %v", err)
		}
		items = append(items, &v1.KeyMeta{
			Id:        id,
			Name:      name,
			KeyType:   kind,
			PublicKey: publicKey,
			Status:    status,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "list keys: %v", err)
	}
	return &v1.ListKeysResponse{Keys: items}, nil
}

func (s *Server) ShowKey(ctx context.Context, req *v1.ShowKeyRequest) (*v1.ShowKeyResponse, error) {
	identity, err := s.cfg.Store.Identities.Get(ctx, req.GetName())
	if err != nil {
		return nil, mapAppError("show key", err)
	}
	return &v1.ShowKeyResponse{
		Key: &v1.KeyMeta{
			Id:        identity.ID,
			Name:      identity.Name,
			KeyType:   identity.Kind,
			PublicKey: identity.PublicKey,
			Status:    string(identity.Status),
		},
	}, nil
}

func (s *Server) DeleteKey(ctx context.Context, req *v1.DeleteKeyRequest) (*v1.DeleteKeyResponse, error) {
	if err := s.cfg.Store.Identities.Delete(ctx, req.GetName()); err != nil {
		return nil, mapAppError("delete key", err)
	}
	return &v1.DeleteKeyResponse{}, nil
}

func (s *Server) RotateKey(ctx context.Context, req *v1.RotateKeyRequest) (*v1.RotateKeyResponse, error) {
	keySvc := app.NewKeyService(s.cfg.Store.Identities)
	meta, err := keySvc.Rotate(ctx, req.GetName())
	if err != nil {
		return nil, mapAppError("rotate key", err)
	}
	return &v1.RotateKeyResponse{Key: keyMetaFromApp(meta, storage.IdentityStatusActive)}, nil
}

func (s *Server) AgentAdd(ctx context.Context, req *v1.AgentAddRequest) (*v1.AgentAddResponse, error) {
	agentManager := s.cfg.KeyAgent
	if agentManager == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "agent add: ssh agent integration is not configured")
	}

	identity, err := s.cfg.Store.Identities.Get(ctx, req.GetName())
	if err != nil {
		return nil, mapAppError("agent add", err)
	}

	privateKey, err := ssh.ParsePrivateKey(identity.PrivateKey)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "agent add: parse private key: %v", err)
	}
	fingerprint := ssh.FingerprintSHA256(privateKey.PublicKey())

	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	if ttl < 0 {
		return nil, grpcstatus.Error(codes.InvalidArgument, "agent add: ttl must be >= 0")
	}
	if err := agentManager.AddKey(&agent.Identity{
		Name:       identity.Name,
		PrivateKey: append([]byte(nil), identity.PrivateKey...),
		SessionID:  req.GetSessionId(),
	}, ttl); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "agent add: %v", err)
	}

	return &v1.AgentAddResponse{Fingerprint: fingerprint}, nil
}

func (s *Server) AgentRemove(_ context.Context, req *v1.AgentRemoveRequest) (*v1.AgentRemoveResponse, error) {
	agentManager := s.cfg.KeyAgent
	if agentManager == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "agent remove: ssh agent integration is not configured")
	}
	if strings.TrimSpace(req.GetFingerprint()) == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "agent remove: fingerprint is required")
	}

	if err := agentManager.RemoveKey(req.GetFingerprint()); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "agent remove: %v", err)
	}
	return &v1.AgentRemoveResponse{}, nil
}

func (s *Server) Enroll(ctx context.Context, req *v1.EnrollPasskeyRequest) (*v1.EnrollPasskeyResponse, error) {
	enroller := s.cfg.PasskeyEnroller
	if enroller == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "passkey enroll: passkey enrollment is not configured")
	}

	enrollment, err := enroller.Enroll(ctx, strings.TrimSpace(req.GetLabel()), strings.TrimSpace(req.GetUserName()))
	if err != nil {
		return nil, mapAppError("passkey enroll", err)
	}
	return &v1.EnrollPasskeyResponse{
		Passkey: &v1.PasskeyMeta{
			Id:                 enrollment.ID,
			Label:              enrollment.Label,
			SupportsHmacSecret: enrollment.SupportsHMACSecret,
		},
	}, nil
}

func (s *Server) RemovePasskey(ctx context.Context, req *v1.RemovePasskeyRequest) (*v1.RemovePasskeyResponse, error) {
	if err := s.cfg.Store.Passkeys.Delete(ctx, req.GetLabel()); err != nil {
		return nil, mapAppError("remove passkey", err)
	}
	return &v1.RemovePasskeyResponse{}, nil
}

func (s *Server) TestPasskey(ctx context.Context, req *v1.TestPasskeyRequest) (*v1.TestPasskeyResponse, error) {
	enrollment, err := s.cfg.Store.Passkeys.GetByLabel(ctx, req.GetLabel())
	if err != nil {
		return nil, mapAppError("test passkey", err)
	}
	if len(req.GetAuthData()) == 0 || len(req.GetSignature()) == 0 {
		return &v1.TestPasskeyResponse{Ok: enrollment.SupportsHMACSecret || len(enrollment.PublicKeyCOSE) > 0}, nil
	}

	if err := fido2.VerifyAssertionSignature(enrollment.PublicKeyCOSE, req.GetAuthData(), req.GetSignature()); err != nil {
		return nil, grpcstatus.Errorf(codes.PermissionDenied, "test passkey: %v", err)
	}
	return &v1.TestPasskeyResponse{Ok: true}, nil
}

func (s *Server) VerifyChain(ctx context.Context, _ *v1.VerifyChainRequest) (*v1.VerifyChainResponse, error) {
	if s.cfg.AuditService == nil {
		return &v1.VerifyChainResponse{Valid: true}, nil
	}

	result, err := s.cfg.AuditService.Verify(ctx)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "verify audit chain: %v", err)
	}
	return &v1.VerifyChainResponse{
		Valid:      result.Valid,
		EventCount: int32(result.EventCount),
		ChainTip:   result.ChainTip,
		Error:      result.Error,
	}, nil
}

func (s *Server) RestoreBackup(ctx context.Context, req *v1.RestoreBackupRequest) (*v1.RestoreBackupResponse, error) {
	backupSvc := app.NewBackupService(s.cfg.Store)
	targetVaultPath, err := backupSvcMainDBPath(ctx, s.cfg.Store)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "restore backup: %v", err)
	}

	_, err = backupSvc.Restore(ctx, app.BackupRestoreRequest{
		InputPath:       req.GetInputPath(),
		Passphrase:      []byte(req.GetPassphrase()),
		TargetVaultPath: targetVaultPath,
		Confirm:         req.GetOverwrite(),
		Overwrite:       req.GetOverwrite(),
	})
	if err != nil {
		return nil, mapAppError("restore backup", err)
	}
	return &v1.RestoreBackupResponse{Restored: true}, nil
}

func mapAppError(operation string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, app.ErrValidation):
		return grpcstatus.Errorf(codes.InvalidArgument, "%s: %v", operation, err)
	case errors.Is(err, app.ErrDuplicateName), errors.Is(err, fido2.ErrDuplicateLabel), isUniqueConstraint(err):
		return grpcstatus.Errorf(codes.AlreadyExists, "%s: %v", operation, err)
	case errors.Is(err, storage.ErrNotFound):
		return grpcstatus.Errorf(codes.NotFound, "%s: %v", operation, err)
	case errors.Is(err, app.ErrReauthRequired):
		return permissionDeniedError("REAUTH_REQUIRED", false, true, "re-authentication required for sensitive operation")
	case errors.Is(err, fido2.ErrDependencyUnavailable):
		return grpcstatus.Errorf(codes.FailedPrecondition, "%s: %v", operation, err)
	default:
		return grpcstatus.Errorf(codes.Internal, "%s: %v", operation, err)
	}
}

func hostToProto(host *storage.Host) *v1.Host {
	if host == nil {
		return nil
	}
	return &v1.Host{
		Id:      host.ID,
		Name:    host.Name,
		Address: host.Address,
		Port:    int32(host.Port),
		User:    host.User,
		Tags:    append([]string(nil), host.Tags...),
		EnvRefs: cloneStringMap(host.EnvRefs),
	}
}

func keyMetaFromApp(meta *app.KeyMeta, status storage.IdentityStatus) *v1.KeyMeta {
	if meta == nil {
		return nil
	}
	return &v1.KeyMeta{
		Id:        meta.ID,
		Name:      meta.Name,
		KeyType:   string(meta.Type),
		PublicKey: meta.PublicKey,
		Status:    string(status),
	}
}

func backupSvcMainDBPath(ctx context.Context, store *storage.Store) (string, error) {
	rows, err := store.DB().QueryContext(ctx, `PRAGMA database_list`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			seq  int
			name string
			file string
		)
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return "", err
		}
		if name == "main" {
			return file, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("main database path not found")
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
