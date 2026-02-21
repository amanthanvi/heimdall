package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build version information",
		Example: "  heimdall version\n" +
			"  heimdall --json version",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("version does not accept positional arguments")
			}
			if deps.globals.JSON {
				return mapCommandError(printJSON(deps.out, deps.build))
			}
			_, err := fmt.Fprintf(
				deps.out,
				"version=%s commit=%s build_time=%s\n",
				deps.build.Version,
				deps.build.Commit,
				deps.build.BuildTime,
			)
			return mapCommandError(err)
		},
	}
}
