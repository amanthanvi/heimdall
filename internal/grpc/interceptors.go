package grpc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/amanthanvi/heimdall/internal/audit"
	"google.golang.org/grpc"
)

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
		action := grpcMethodToAuditAction(info.FullMethod)
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
