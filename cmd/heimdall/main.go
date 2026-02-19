package main

import (
	"errors"
	"os"
	"strings"

	"github.com/amanthanvi/heimdall/internal/cli"
	"github.com/amanthanvi/heimdall/internal/version"
)

func main() {
	cmd := cli.NewRootCommand(os.Stdout, cli.BuildInfo{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildTime: version.BuildTime,
	})
	if err := cmd.Execute(); err != nil {
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
