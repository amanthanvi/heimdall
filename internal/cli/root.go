package cli

import (
	"io"
	"time"

	"github.com/spf13/cobra"
)

type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

type GlobalOptions struct {
	JSON        bool
	Quiet       bool
	NoColor     bool
	Timeout     time.Duration
	Yes         bool
	VaultPath   string
	ConfigPath  string
	Interactive bool
}

type commandDeps struct {
	out     io.Writer
	errOut  io.Writer
	build   BuildInfo
	globals *GlobalOptions
}

func NewRootCommand(out io.Writer, build BuildInfo) *cobra.Command {
	globals := &GlobalOptions{
		Timeout: 10 * time.Second,
	}
	deps := commandDeps{
		out:     out,
		errOut:  out,
		build:   build,
		globals: globals,
	}

	cmd := &cobra.Command{
		Use:           "heimdall",
		Short:         "Heimdall CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageErrorf("%v", err)
	})

	cmd.PersistentFlags().BoolVar(&globals.JSON, "json", false, "Output machine-readable JSON")
	cmd.PersistentFlags().BoolVar(&globals.Quiet, "quiet", false, "Suppress non-essential output")
	cmd.PersistentFlags().BoolVar(&globals.NoColor, "no-color", false, "Disable ANSI color output")
	cmd.PersistentFlags().DurationVar(&globals.Timeout, "timeout", globals.Timeout, "Command timeout (for daemon RPCs)")
	cmd.PersistentFlags().BoolVarP(&globals.Yes, "yes", "y", false, "Automatic yes to prompts and confirmations")
	cmd.PersistentFlags().StringVar(&globals.VaultPath, "vault", "", "Path to vault database")
	cmd.PersistentFlags().StringVar(&globals.ConfigPath, "config", "", "Path to config file")
	cmd.PersistentFlags().BoolVar(&globals.Interactive, "interactive", false, "Force interactive mode")

	cmd.AddCommand(
		newInitCommand(deps),
		newVersionCommand(deps),
		newStatusCommand(deps),
		newDoctorCommand(deps),
		newVaultCommand(deps),
		newDaemonCommand(deps),
		newHostCommand(deps),
		newSecretCommand(deps),
		newKeyCommand(deps),
		newPasskeyCommand(deps),
		newConnectCommand(deps),
		newBackupCommand(deps),
		newAuditCommand(deps),
		newImportCommand(deps),
		newExportCommand(deps),
		newSSHConfigCommand(deps),
		newDebugCommand(deps),
	)

	cmd.InitDefaultCompletionCmd()
	return cmd
}
