package grpc

import (
	"context"
	"fmt"
	"strings"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/amanthanvi/heimdall/internal/audit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var knownAuditActions = func() map[string]struct{} {
	out := make(map[string]struct{}, len(audit.AllActionTypes))
	for _, action := range audit.AllActionTypes {
		out[action] = struct{}{}
	}
	return out
}()

var grpcMethodAuditActions = map[string]string{
	v1.VaultService_Unlock_FullMethodName:          audit.ActionVaultUnlock,
	v1.VaultService_Lock_FullMethodName:            audit.ActionVaultLock,
	v1.HostService_CreateHost_FullMethodName:       audit.ActionHostCreate,
	v1.HostService_DeleteHost_FullMethodName:       audit.ActionHostDelete,
	v1.SecretService_CreateSecret_FullMethodName:   audit.ActionSecretCreate,
	v1.SecretService_DeleteSecret_FullMethodName:   audit.ActionSecretDelete,
	v1.KeyService_DeleteKey_FullMethodName:         audit.ActionKeyDelete,
	v1.KeyService_RotateKey_FullMethodName:         audit.ActionKeyRotate,
	v1.KeyService_ExportKey_FullMethodName:         audit.ActionKeyExport,
	v1.KeyService_AgentAdd_FullMethodName:          audit.ActionKeyAgentAdd,
	v1.PasskeyService_Enroll_FullMethodName:        audit.ActionPasskeyEnroll,
	v1.PasskeyService_RemovePasskey_FullMethodName: audit.ActionPasskeyRemove,
	v1.BackupService_CreateBackup_FullMethodName:   audit.ActionBackupCreate,
	v1.BackupService_RestoreBackup_FullMethodName:  audit.ActionBackupRestore,
}

var grpcMethodAuditSkips = map[string]struct{}{
	v1.SessionService_RecordSessionStart_FullMethodName: {},
	v1.SessionService_RecordSessionEnd_FullMethodName:   {},
	v1.ReauthService_VerifyAssertion_FullMethodName:     {},
	v1.ReauthService_VerifyPassphrase_FullMethodName:    {},
}

func AuthInterceptor(daemon daemonState, cache *reauthCache) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		tier := methodTier(info.FullMethod)
		if tier >= tier1 && daemon.IsLocked() {
			return nil, permissionDeniedError(
				"VAULT_LOCKED",
				true,
				false,
				"vault is locked; run `heimdall vault unlock`",
			)
		}
		if tier >= tier2 {
			caller := callerFromContext(ctx, daemon)
			if !cache.isValid(caller) {
				return nil, permissionDeniedError(
					"REAUTH_REQUIRED",
					false,
					true,
					"re-authentication required for sensitive operation",
				)
			}
		}
		return handler(ctx, req)
	}
}

func AuthStreamInterceptor(daemon daemonState, cache *reauthCache) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		tier := methodTier(info.FullMethod)
		if tier >= tier1 && daemon.IsLocked() {
			return permissionDeniedError(
				"VAULT_LOCKED",
				true,
				false,
				"vault is locked; run `heimdall vault unlock`",
			)
		}
		if tier >= tier2 {
			caller := callerFromContext(ss.Context(), daemon)
			if !cache.isValid(caller) {
				return permissionDeniedError(
					"REAUTH_REQUIRED",
					false,
					true,
					"re-authentication required for sensitive operation",
				)
			}
		}
		return handler(srv, ss)
	}
}

func AuditInterceptor(auditSvc *audit.Service, clk clock) grpc.UnaryServerInterceptor {
	if clk == nil {
		clk = realClock{}
	}
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := handler(ctx, req)
		if auditSvc == nil {
			return resp, err
		}

		result := "success"
		if err != nil {
			result = "error"
		}
		action, ok := auditActionForMethod(ctx, info.FullMethod)
		if !ok {
			return resp, err
		}
		_ = auditSvc.Record(ctx, audit.Event{
			Timestamp: clk.Now(),
			Action:    action,
			Result:    result,
			Details: struct {
				Method string `json:"method"`
			}{Method: info.FullMethod},
		})
		return resp, err
	}
}

func auditActionForMethod(ctx context.Context, method string) (string, bool) {
	if shouldSkipAuditMethod(method) {
		return "", false
	}
	if method == v1.SecretService_GetSecretValue_FullMethodName {
		if action, ok := auditActionFromMetadata(ctx); ok {
			return action, true
		}
	}
	if action, ok := grpcMethodAuditActions[method]; ok {
		return action, true
	}
	return grpcMethodToAuditAction(method), true
}

func shouldSkipAuditMethod(method string) bool {
	_, ok := grpcMethodAuditSkips[method]
	return ok
}

func auditActionFromMetadata(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	for _, value := range md.Get(auditActionMetadataKey) {
		action := strings.TrimSpace(value)
		if isKnownAuditAction(action) {
			return action, true
		}
	}
	return "", false
}

func isKnownAuditAction(action string) bool {
	_, ok := knownAuditActions[action]
	return ok
}

func RateLimitInterceptor(daemon daemonState, limiter *rateLimiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		caller := callerFromContext(ctx, daemon)
		tier := methodTier(info.FullMethod)
		if !limiter.allow(caller, tier) {
			return nil, resourceExhaustedError(
				"RATE_LIMITED",
				fmt.Sprintf("rate limit exceeded for tier %d", tier),
			)
		}
		return handler(ctx, req)
	}
}

func RateLimitStreamInterceptor(daemon daemonState, limiter *rateLimiter) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		caller := callerFromContext(ss.Context(), daemon)
		tier := methodTier(info.FullMethod)
		if !limiter.allow(caller, tier) {
			return resourceExhaustedError(
				"RATE_LIMITED",
				fmt.Sprintf("rate limit exceeded for tier %d", tier),
			)
		}
		return handler(srv, ss)
	}
}

func grpcMethodToAuditAction(method string) string {
	normalized := strings.TrimPrefix(method, "/")
	parts := strings.Split(normalized, "/")
	if len(parts) != 2 {
		return "grpc.unknown"
	}
	service := strings.TrimPrefix(parts[0], "heimdall.v1.")
	rpc := parts[1]
	return fmt.Sprintf("grpc.%s.%s", strings.ToLower(service), strings.ToLower(rpc))
}

func lockoutGuidance(delay time.Duration) string {
	if delay <= 0 {
		return "re-authentication failed"
	}
	return fmt.Sprintf("too many authentication failures; retry in %s", delay.Round(time.Second))
}
