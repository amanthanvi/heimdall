package grpc

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/amanthanvi/heimdall/internal/app"
	auditpkg "github.com/amanthanvi/heimdall/internal/audit"
	"github.com/amanthanvi/heimdall/internal/fido2"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

const defaultDownloadChunkSize = 256 * 1024

type VersionInfo struct {
	Version   string
	Commit    string
	BuildTime string
}

type ServerConfig struct {
	Daemon             daemonState
	Store              *storage.Store
	AuditService       *auditpkg.Service
	KeyAgent           keyAgent
	PasskeyEnroller    passkeyEnroller
	Version            VersionInfo
	Clock              clock
	ReauthTTL          time.Duration
	PassphraseVerifier func(context.Context, string) bool
	AssertionVerifier  func(publicKey, authData, signature []byte) error
}

type Server struct {
	v1.UnimplementedVaultServiceServer
	v1.UnimplementedVersionServiceServer
	v1.UnimplementedHostServiceServer
	v1.UnimplementedSecretServiceServer
	v1.UnimplementedKeyServiceServer
	v1.UnimplementedPasskeyServiceServer
	v1.UnimplementedConnectServiceServer
	v1.UnimplementedAuditServiceServer
	v1.UnimplementedBackupServiceServer
	v1.UnimplementedSessionServiceServer
	v1.UnimplementedReauthServiceServer

	cfg         ServerConfig
	grpcServer  *grpc.Server
	connectSvc  *app.ConnectService
	reauthCache *reauthCache
	lockout     *reauthLockout
	rateLimiter *rateLimiter
	clk         clock
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Daemon == nil {
		return nil, fmt.Errorf("new grpc server: daemon is nil")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("new grpc server: store is nil")
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}

	s := &Server{
		cfg:         cfg,
		connectSvc:  app.NewConnectService(cfg.Store.Hosts),
		reauthCache: newReauthCache(cfg.ReauthTTL, cfg.Clock),
		lockout:     newReauthLockout(cfg.Clock),
		rateLimiter: newRateLimiter(cfg.Clock),
		clk:         cfg.Clock,
	}

	s.grpcServer = grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			RateLimitInterceptor(cfg.Daemon, s.rateLimiter),
			AuthInterceptor(cfg.Daemon, s.reauthCache),
			AuditInterceptor(cfg.AuditService, cfg.Clock),
		),
		grpc.ChainStreamInterceptor(
			RateLimitStreamInterceptor(cfg.Daemon, s.rateLimiter),
			AuthStreamInterceptor(cfg.Daemon, s.reauthCache),
		),
	)

	v1.RegisterVaultServiceServer(s.grpcServer, s)
	v1.RegisterVersionServiceServer(s.grpcServer, s)
	v1.RegisterHostServiceServer(s.grpcServer, s)
	v1.RegisterSecretServiceServer(s.grpcServer, s)
	v1.RegisterKeyServiceServer(s.grpcServer, s)
	v1.RegisterPasskeyServiceServer(s.grpcServer, s)
	v1.RegisterConnectServiceServer(s.grpcServer, s)
	v1.RegisterAuditServiceServer(s.grpcServer, s)
	v1.RegisterBackupServiceServer(s.grpcServer, s)
	v1.RegisterSessionServiceServer(s.grpcServer, s)
	v1.RegisterReauthServiceServer(s.grpcServer, s)

	return s, nil
}

func (s *Server) GRPCServer() *grpc.Server {
	if s == nil {
		return nil
	}
	return s.grpcServer
}

func (s *Server) Serve(listener net.Listener) error {
	if s == nil || s.grpcServer == nil {
		return fmt.Errorf("serve grpc: server is nil")
	}
	if listener == nil {
		return fmt.Errorf("serve grpc: listener is nil")
	}
	return s.grpcServer.Serve(listener)
}

func (s *Server) Stop() {
	if s == nil || s.grpcServer == nil {
		return
	}
	s.grpcServer.Stop()
}

func (s *Server) Status(_ context.Context, _ *v1.StatusRequest) (*v1.StatusResponse, error) {
	return &v1.StatusResponse{
		Locked:     s.cfg.Daemon.IsLocked(),
		HasLiveVmk: s.cfg.Daemon.HasLiveVMK(),
	}, nil
}

func (s *Server) Lock(_ context.Context, _ *v1.LockRequest) (*v1.LockResponse, error) {
	if err := s.cfg.Daemon.Lock(); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "lock vault: %v", err)
	}
	s.reauthCache.clear()
	return &v1.LockResponse{}, nil
}

func (s *Server) GetVersion(_ context.Context, _ *v1.GetVersionRequest) (*v1.GetVersionResponse, error) {
	return &v1.GetVersionResponse{
		Version:   s.cfg.Version.Version,
		Commit:    s.cfg.Version.Commit,
		BuildTime: s.cfg.Version.BuildTime,
	}, nil
}

func (s *Server) ListHosts(ctx context.Context, req *v1.ListHostsRequest) (*v1.ListHostsResponse, error) {
	hosts, err := s.cfg.Store.Hosts.List(ctx, storage.HostFilter{})
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "list hosts: %v", err)
	}
	out := make([]*v1.Host, 0, len(hosts))
	for _, host := range hosts {
		entry := &v1.Host{
			Id:   host.ID,
			Name: host.Name,
		}
		if !req.GetNamesOnly() {
			entry.Address = host.Address
			entry.Port = int32(host.Port)
			entry.User = host.User
			entry.Tags = append([]string(nil), host.Tags...)
		}
		out = append(out, entry)
	}
	return &v1.ListHostsResponse{Hosts: out}, nil
}

func (s *Server) ListSecrets(ctx context.Context, _ *v1.ListSecretsRequest) (*v1.ListSecretsResponse, error) {
	rows, err := s.cfg.Store.DB().QueryContext(ctx, `
		SELECT id, name, length(value_ciphertext)
		FROM secrets
		WHERE deleted_at IS NULL
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "list secrets: %v", err)
	}
	defer rows.Close()

	items := []*v1.SecretMeta{}
	for rows.Next() {
		var (
			id   string
			name string
			size int64
		)
		if err := rows.Scan(&id, &name, &size); err != nil {
			return nil, grpcstatus.Errorf(codes.Internal, "list secrets: %v", err)
		}
		items = append(items, &v1.SecretMeta{
			Id:           id,
			Name:         name,
			RevealPolicy: string(app.RevealPolicyOncePerUnlock),
			SizeBytes:    size,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "list secrets: %v", err)
	}
	return &v1.ListSecretsResponse{Secrets: items}, nil
}

func (s *Server) GetSecretValue(ctx context.Context, req *v1.GetSecretValueRequest) (*v1.GetSecretValueResponse, error) {
	secret, err := s.cfg.Store.Secrets.Get(ctx, req.GetName())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, grpcstatus.Error(codes.NotFound, "secret not found")
		}
		return nil, grpcstatus.Errorf(codes.Internal, "get secret: %v", err)
	}
	return &v1.GetSecretValueResponse{Value: append([]byte(nil), secret.Value...)}, nil
}

func (s *Server) DeleteSecret(ctx context.Context, req *v1.DeleteSecretRequest) (*v1.DeleteSecretResponse, error) {
	if err := s.cfg.Store.Secrets.Delete(ctx, req.GetName()); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, grpcstatus.Error(codes.NotFound, "secret not found")
		}
		return nil, grpcstatus.Errorf(codes.Internal, "delete secret: %v", err)
	}
	return &v1.DeleteSecretResponse{}, nil
}

func (s *Server) UploadFileSecret(stream v1.SecretService_UploadFileSecretServer) error {
	var (
		name   string
		policy string
		buf    bytes.Buffer
	)
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return grpcstatus.Errorf(codes.Internal, "upload secret: %v", err)
		}
		if name == "" {
			name = strings.TrimSpace(chunk.GetName())
			policy = strings.TrimSpace(chunk.GetRevealPolicy())
		}
		if chunk.GetName() != "" && chunk.GetName() != name {
			return grpcstatus.Error(codes.InvalidArgument, "secret name changed mid-stream")
		}
		if _, err := buf.Write(chunk.GetData()); err != nil {
			return grpcstatus.Errorf(codes.Internal, "upload secret: %v", err)
		}
		if chunk.GetEof() {
			break
		}
	}

	if name == "" {
		return grpcstatus.Error(codes.InvalidArgument, "secret name is required")
	}
	if buf.Len() == 0 {
		return grpcstatus.Error(codes.InvalidArgument, "secret value is required")
	}

	secret := &storage.Secret{Name: name, Value: buf.Bytes()}
	if err := s.cfg.Store.Secrets.Create(stream.Context(), secret); err != nil {
		return grpcstatus.Errorf(codes.Internal, "upload secret: %v", err)
	}

	if policy == "" {
		policy = string(app.RevealPolicyOncePerUnlock)
	}
	return stream.SendAndClose(&v1.UploadFileSecretResponse{
		Secret: &v1.SecretMeta{
			Id:           secret.ID,
			Name:         secret.Name,
			RevealPolicy: policy,
			SizeBytes:    int64(buf.Len()),
		},
	})
}

func (s *Server) DownloadFileSecret(req *v1.DownloadRequest, stream v1.SecretService_DownloadFileSecretServer) error {
	secret, err := s.cfg.Store.Secrets.Get(stream.Context(), req.GetName())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return grpcstatus.Error(codes.NotFound, "secret not found")
		}
		return grpcstatus.Errorf(codes.Internal, "download secret: %v", err)
	}
	chunkSize := int(req.GetChunkSize())
	if chunkSize <= 0 {
		chunkSize = defaultDownloadChunkSize
	}
	if len(secret.Value) == 0 {
		return stream.Send(&v1.DownloadChunk{Eof: true})
	}
	for offset := 0; offset < len(secret.Value); offset += chunkSize {
		end := offset + chunkSize
		if end > len(secret.Value) {
			end = len(secret.Value)
		}
		if err := stream.Send(&v1.DownloadChunk{
			Data: append([]byte(nil), secret.Value[offset:end]...),
			Eof:  end == len(secret.Value),
		}); err != nil {
			return grpcstatus.Errorf(codes.Internal, "download secret: %v", err)
		}
	}
	return nil
}

func (s *Server) ExportKey(ctx context.Context, req *v1.ExportKeyRequest) (*v1.ExportKeyResponse, error) {
	identity, err := s.cfg.Store.Identities.Get(ctx, req.GetName())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, grpcstatus.Error(codes.NotFound, "key not found")
		}
		return nil, grpcstatus.Errorf(codes.Internal, "export key: %v", err)
	}
	return &v1.ExportKeyResponse{
		Name:       identity.Name,
		KeyType:    identity.Kind,
		PublicKey:  identity.PublicKey,
		PrivateKey: append([]byte(nil), identity.PrivateKey...),
	}, nil
}

func (s *Server) ListPasskeys(ctx context.Context, _ *v1.ListPasskeysRequest) (*v1.ListPasskeysResponse, error) {
	rows, err := s.cfg.Store.DB().QueryContext(ctx, `
		SELECT id, label, supports_hmac_secret
		FROM passkey_enrollments
		WHERE deleted_at IS NULL
		ORDER BY label ASC
	`)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "list passkeys: %v", err)
	}
	defer rows.Close()

	items := []*v1.PasskeyMeta{}
	for rows.Next() {
		var (
			id      string
			label   string
			support int
		)
		if err := rows.Scan(&id, &label, &support); err != nil {
			return nil, grpcstatus.Errorf(codes.Internal, "list passkeys: %v", err)
		}
		items = append(items, &v1.PasskeyMeta{Id: id, Label: label, SupportsHmacSecret: support == 1})
	}
	if err := rows.Err(); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "list passkeys: %v", err)
	}
	return &v1.ListPasskeysResponse{Passkeys: items}, nil
}

func (s *Server) Plan(ctx context.Context, req *v1.PlanConnectRequest) (*v1.PlanConnectResponse, error) {
	plan, err := s.connectSvc.Plan(ctx, req.GetHostName(), app.ConnectOpts{
		User:         req.GetUser(),
		Port:         int(req.GetPort()),
		JumpHosts:    append([]string(nil), req.GetJumpHosts()...),
		Forwards:     append([]string(nil), req.GetForwards()...),
		IdentityPath: req.GetIdentityPath(),
		KnownHosts:   req.GetKnownHosts(),
		PrintCmd:     req.GetPrintCmd(),
		DryRun:       req.GetDryRun(),
	})
	if err != nil {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "plan connect: %v", err)
	}

	binary := "ssh"
	args := append([]string(nil), plan.Args...)
	redacted := append([]string(nil), plan.RedactedArgs...)
	if len(args) > 0 {
		binary = args[0]
		args = args[1:]
	}
	if len(redacted) > 0 {
		redacted = redacted[1:]
	}
	return &v1.PlanConnectResponse{
		Command: &v1.SSHCommand{
			Binary:       binary,
			Args:         args,
			RedactedArgs: redacted,
		},
	}, nil
}

func (s *Server) ListEvents(ctx context.Context, req *v1.ListEventsRequest) (*v1.ListEventsResponse, error) {
	if s.cfg.AuditService == nil {
		return &v1.ListEventsResponse{}, nil
	}
	limit := int(req.GetLimit())
	events, err := s.cfg.AuditService.List(ctx, auditpkg.Filter{Limit: limit})
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "list audit events: %v", err)
	}
	out := make([]*v1.AuditEvent, 0, len(events))
	for _, event := range events {
		out = append(out, &v1.AuditEvent{
			Id:          event.ID,
			Action:      event.Action,
			TargetType:  event.TargetType,
			TargetId:    event.TargetID,
			Result:      event.Result,
			DetailsJson: event.DetailsJSON,
		})
	}
	return &v1.ListEventsResponse{Events: out}, nil
}

func (s *Server) CreateBackup(ctx context.Context, req *v1.CreateBackupRequest) (*v1.CreateBackupResponse, error) {
	backupSvc := app.NewBackupService(s.cfg.Store)
	_, err := backupSvc.Create(ctx, app.BackupCreateRequest{
		OutputPath: req.GetOutputPath(),
		Passphrase: []byte(req.GetPassphrase()),
	})
	if err != nil {
		return nil, mapAppError("create backup", err)
	}
	return &v1.CreateBackupResponse{
		Accepted:   true,
		OutputPath: req.GetOutputPath(),
	}, nil
}

func (s *Server) RecordSessionStart(ctx context.Context, req *v1.RecordSessionStartRequest) (*v1.RecordSessionStartResponse, error) {
	sessionID := strings.TrimSpace(req.GetSessionId())
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	entry := &storage.SessionHistory{
		ID:        sessionID,
		HostID:    strings.TrimSpace(req.GetHostId()),
		StartedAt: s.clk.Now(),
	}
	if err := s.cfg.Store.Sessions.RecordStart(ctx, entry); err != nil {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "record session start: %v", err)
	}
	s.cfg.Daemon.RegisterSigningSession(sessionID)

	if s.cfg.AuditService != nil {
		_ = s.cfg.AuditService.Record(ctx, auditpkg.Event{
			Timestamp:  s.clk.Now(),
			Action:     "session.start",
			TargetType: "host",
			TargetID:   entry.HostID,
			Result:     "success",
		})
	}

	return &v1.RecordSessionStartResponse{SessionId: sessionID}, nil
}

func (s *Server) RecordSessionEnd(ctx context.Context, req *v1.RecordSessionEndRequest) (*v1.RecordSessionEndResponse, error) {
	if err := s.cfg.Store.Sessions.RecordEnd(ctx, req.GetSessionId(), int(req.GetExitCode())); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, grpcstatus.Error(codes.NotFound, "session not found")
		}
		return nil, grpcstatus.Errorf(codes.Internal, "record session end: %v", err)
	}
	if s.cfg.AuditService != nil {
		_ = s.cfg.AuditService.Record(ctx, auditpkg.Event{
			Timestamp:  s.clk.Now(),
			Action:     "session.end",
			TargetType: "session",
			TargetID:   req.GetSessionId(),
			Result:     "success",
		})
	}
	return &v1.RecordSessionEndResponse{}, nil
}

func (s *Server) VerifyAssertion(ctx context.Context, req *v1.VerifyAssertionRequest) (*v1.VerifyAssertionResponse, error) {
	caller := callerFromContext(ctx, s.cfg.Daemon)
	if blocked, remaining := s.lockout.check(caller); blocked {
		return nil, permissionDeniedError("AUTH_LOCKED_OUT", false, false, lockoutGuidance(remaining))
	}

	enrollment, err := s.cfg.Store.Passkeys.GetByLabel(ctx, req.GetLabel())
	if err != nil {
		delay := s.lockout.recordFailure(caller)
		return nil, permissionDeniedError("AUTH_FAILED", false, false, lockoutGuidance(delay))
	}

	verify := s.cfg.AssertionVerifier
	if verify == nil {
		verify = fido2.VerifyAssertionSignature
	}
	if err := verify(enrollment.PublicKeyCOSE, req.GetAuthData(), req.GetSignature()); err != nil {
		delay := s.lockout.recordFailure(caller)
		return nil, permissionDeniedError("AUTH_FAILED", false, false, lockoutGuidance(delay))
	}

	s.reauthCache.mark(caller)
	s.lockout.reset(caller)
	if s.cfg.AuditService != nil {
		_ = s.cfg.AuditService.Record(ctx, auditpkg.Event{
			Timestamp:  s.clk.Now(),
			Action:     auditpkg.ActionPasskeyReauth,
			TargetType: "passkey",
			TargetID:   req.GetLabel(),
			Result:     "success",
		})
	}
	return &v1.VerifyAssertionResponse{Ok: true}, nil
}

func (s *Server) VerifyPassphrase(ctx context.Context, req *v1.VerifyPassphraseRequest) (*v1.VerifyPassphraseResponse, error) {
	caller := callerFromContext(ctx, s.cfg.Daemon)
	if blocked, remaining := s.lockout.check(caller); blocked {
		return nil, permissionDeniedError("AUTH_LOCKED_OUT", false, false, lockoutGuidance(remaining))
	}

	passphrase := req.GetPassphrase()
	if passphrase == "" {
		delay := s.lockout.recordFailure(caller)
		return nil, permissionDeniedError("AUTH_FAILED", false, false, lockoutGuidance(delay))
	}

	verifier := s.cfg.PassphraseVerifier
	ok := true
	if verifier != nil {
		ok = verifier(ctx, passphrase)
	}
	if !ok {
		delay := s.lockout.recordFailure(caller)
		return nil, permissionDeniedError("AUTH_FAILED", false, false, lockoutGuidance(delay))
	}

	s.reauthCache.mark(caller)
	s.lockout.reset(caller)
	if s.cfg.AuditService != nil {
		_ = s.cfg.AuditService.Record(ctx, auditpkg.Event{
			Timestamp:  s.clk.Now(),
			Action:     auditpkg.ActionPasskeyReauth,
			TargetType: "auth",
			Result:     "success",
		})
	}
	return &v1.VerifyPassphraseResponse{Ok: true}, nil
}

func isUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "unique")
}
