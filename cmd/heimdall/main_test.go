package main

import (
	"fmt"
	"testing"

	"github.com/amanthanvi/heimdall/internal/cli"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func TestFormatErrorStripsWrappedGRPCNoise(t *testing.T) {
	err := &cli.ExitError{
		Code: cli.ExitCodeGeneric,
		Err:  grpcstatus.Error(codes.AlreadyExists, "create host: duplicate name: prod"),
	}

	require.Equal(t, "create host: duplicate name: prod", formatError(err))
}

func TestFormatErrorFallsBackToOriginalError(t *testing.T) {
	err := fmt.Errorf("plain error")
	require.Equal(t, "plain error", formatError(err))
}
