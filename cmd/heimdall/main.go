package main

import (
	"os"

	"github.com/athanvi/heimdall/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		os.Exit(cli.ExitCode(err))
	}
}
