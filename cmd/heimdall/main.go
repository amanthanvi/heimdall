package main

import (
	"os"

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
		os.Exit(1)
	}
}
