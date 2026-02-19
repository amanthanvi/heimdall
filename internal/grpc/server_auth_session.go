package grpc

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	auditpkg "github.com/amanthanvi/heimdall/internal/audit"
	"github.com/amanthanvi/heimdall/internal/fido2"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

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
