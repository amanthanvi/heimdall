package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newGroupCommand(use, short, example string, legacy map[string]string) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Example: example,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_ = cmd.Help()
				return nil
			}
			name := strings.TrimSpace(args[0])
			if replacement, ok := legacy[name]; ok && strings.TrimSpace(replacement) != "" {
				return usageErrorf("unknown command %q for %q; use %q", name, cmd.CommandPath(), fmt.Sprintf("%s %s", cmd.CommandPath(), replacement))
			}
			return usageErrorf("unknown command %q for %q", name, cmd.CommandPath())
		},
	}
}
