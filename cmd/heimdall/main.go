package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/amanthanvi/heimdall/internal/cli"
	"github.com/amanthanvi/heimdall/internal/version"
	grpcstatus "google.golang.org/grpc/status"
)

func main() {
	cmd := cli.NewRootCommand(os.Stdout, cli.BuildInfo{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildTime: version.BuildTime,
	})
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, formatError(err))
		var withExitCode interface{ ExitCode() int }
		if errors.As(err, &withExitCode) {
			os.Exit(withExitCode.ExitCode())
		}
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "unknown command") || strings.Contains(lower, "unknown flag") || strings.Contains(lower, "invalid argument") {
			os.Exit(cli.ExitCodeUsage)
		}
		os.Exit(1)
	}
}

// formatError returns a user-friendly error message, stripping gRPC
// protocol details that add noise without helping the operator.
func formatError(err error) string {
	// Unwrap through ExitError and other wrappers to find gRPC status.
	for e := err; e != nil; e = errors.Unwrap(e) {
		if st, ok := grpcstatus.FromError(e); ok {
			return st.Message()
		}
	}
	return err.Error()
}
