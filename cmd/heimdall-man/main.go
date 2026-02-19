package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/amanthanvi/heimdall/internal/cli"
	"github.com/amanthanvi/heimdall/internal/version"
)

func main() {
	var outDir string
	flag.StringVar(&outDir, "out", "dist/man", "output directory for generated man pages")
	flag.Parse()

	err := cli.GenerateManPages(outDir, cli.BuildInfo{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildTime: version.BuildTime,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "heimdall-man: %v\n", err)
		os.Exit(1)
	}
}
