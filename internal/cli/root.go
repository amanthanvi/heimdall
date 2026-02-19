package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

func NewRootCommand(out io.Writer, build BuildInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "heimdall",
		Short:         "Heimdall CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.SetOut(out)
	cmd.SetErr(out)

	cmd.AddCommand(newVersionCommand(out, build))
	cmd.AddCommand(newPasskeyCommand())
	cmd.AddCommand(newVaultCommand(out))
	cmd.InitDefaultCompletionCmd()
	return cmd
}

func newVersionCommand(out io.Writer, build BuildInfo) *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print build version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(build)
			}

			_, err := fmt.Fprintf(out, "version=%s commit=%s build_time=%s\n", build.Version, build.Commit, build.BuildTime)
			return err
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "Print version as JSON")
	return cmd
}
