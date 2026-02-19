package grpc

import (
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func permissionDeniedError(errorCode string, vaultLocked, reauthRequired bool, guidance string) error {
	if guidance == "" {
		guidance = "permission denied"
	}
	st := grpcstatus.New(codes.PermissionDenied, guidance)
	detail := &errdetails.ErrorInfo{
		Reason: errorCode,
		Domain: "heimdall",
		Metadata: map[string]string{
			"error_code":      errorCode,
			"vault_locked":    fmt.Sprintf("%t", vaultLocked),
			"reauth_required": fmt.Sprintf("%t", reauthRequired),
			"guidance":        guidance,
		},
	}
	withDetails, err := st.WithDetails(detail)
	if err != nil {
		return st.Err()
	}
	return withDetails.Err()
}

func resourceExhaustedError(errorCode, guidance string) error {
	if guidance == "" {
		guidance = "rate limit exceeded"
	}
	st := grpcstatus.New(codes.ResourceExhausted, guidance)
	detail := &errdetails.ErrorInfo{
		Reason: errorCode,
		Domain: "heimdall",
		Metadata: map[string]string{
			"error_code":      errorCode,
			"vault_locked":    "false",
			"reauth_required": "false",
			"guidance":        guidance,
		},
	}
	withDetails, err := st.WithDetails(detail)
	if err != nil {
		return st.Err()
	}
	return withDetails.Err()
}
