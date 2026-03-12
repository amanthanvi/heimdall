package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	auditpkg "github.com/amanthanvi/heimdall/internal/audit"
	"github.com/spf13/cobra"
)

const (
	completionShellBash = "bash"
	completionShellZsh  = "zsh"
	completionShellFish = "fish"
)

func initCompletionSupport(root *cobra.Command, deps commandDeps) {
	root.InitDefaultCompletionCmd()
	hardenDefaultCompletionCommands(root)
	completionCmd := findSubcommand(root, "completion")
	if completionCmd != nil {
		completionCmd.AddCommand(newCompletionInstallCommand(root, deps))
	}
	registerDynamicCompletions(root, deps)
}

func hardenDefaultCompletionCommands(root *cobra.Command) {
	completionCmd := findSubcommand(root, "completion")
	if completionCmd == nil {
		return
	}
	zshCmd := findSubcommand(completionCmd, completionShellZsh)
	if zshCmd == nil {
		return
	}
	zshCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 {
			return usageErrorf("completion zsh does not accept positional arguments")
		}
		script, err := generateCompletionScript(root, completionShellZsh)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(script)
		return err
	}
}

func registerDynamicCompletions(root *cobra.Command, deps commandDeps) {
	hostNames := completeHostNames(deps)
	keyNames := completeKeyNames(deps)
	secretNames := completeSecretNames(deps)
	passkeyLabels := completePasskeyLabels(deps)

	registerValidArgs(root, []string{"connect"}, hostNames)
	registerFlagCompletion(root, []string{"connect"}, "key", keyNames)
	registerFlagCompletion(root, []string{"connect"}, "jump", hostNames)

	registerValidArgs(root, []string{"host", "show"}, hostNames)
	registerValidArgs(root, []string{"host", "edit"}, hostNames)
	registerValidArgs(root, []string{"host", "remove"}, hostNames)
	registerFlagCompletion(root, []string{"host", "add"}, "key", keyNames)
	registerFlagCompletion(root, []string{"host", "edit"}, "key", keyNames)
	registerFlagCompletion(root, []string{"host", "add"}, "proxy-jump", hostNames)
	registerFlagCompletion(root, []string{"host", "edit"}, "proxy-jump", hostNames)

	registerValidArgs(root, []string{"key", "show"}, keyNames)
	registerValidArgs(root, []string{"key", "remove"}, keyNames)
	registerValidArgs(root, []string{"key", "rotate"}, keyNames)
	registerValidArgs(root, []string{"key", "export"}, keyNames)
	registerValidArgs(root, []string{"key", "agent", "add"}, keyNames)

	registerValidArgs(root, []string{"secret", "show"}, secretNames)
	registerValidArgs(root, []string{"secret", "remove"}, secretNames)
	registerValidArgs(root, []string{"secret", "export"}, secretNames)
	registerValidArgs(root, []string{"secret", "env"}, secretNames)

	registerValidArgs(root, []string{"passkey", "remove"}, passkeyLabels)
	registerValidArgs(root, []string{"passkey", "test"}, passkeyLabels)
	registerFlagCompletion(root, []string{"vault", "unlock"}, "passkey-label", passkeyLabels)

	registerFlagCompletion(root, []string{"key", "generate"}, "type", staticCompletion("ed25519", "rsa"))
	registerFlagCompletion(root, []string{"audit", "list"}, "action", staticCompletion(auditpkg.AllActionTypes...))
}

func registerValidArgs(root *cobra.Command, path []string, fn func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)) {
	cmd := findCommand(root, path)
	if cmd == nil {
		return
	}
	cmd.ValidArgsFunction = fn
}

func registerFlagCompletion(root *cobra.Command, path []string, flagName string, fn func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)) {
	cmd := findCommand(root, path)
	if cmd == nil {
		return
	}
	_ = cmd.RegisterFlagCompletionFunc(flagName, fn)
}

func findCommand(root *cobra.Command, path []string) *cobra.Command {
	current := root
	for _, name := range path {
		current = findSubcommand(current, name)
		if current == nil {
			return nil
		}
	}
	return current
}

func findSubcommand(cmd *cobra.Command, name string) *cobra.Command {
	for _, child := range cmd.Commands() {
		if child.Name() == name {
			return child
		}
	}
	return nil
}

func completeHostNames(deps commandDeps) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		items, directive, err := listCompletionNames(deps, toComplete, func(ctx context.Context, clients daemonClients) ([]string, error) {
			resp, err := clients.host.ListHosts(ctx, &v1.ListHostsRequest{NamesOnly: true})
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(resp.GetHosts()))
			for _, host := range resp.GetHosts() {
				out = append(out, host.GetName())
			}
			return out, nil
		})
		if err != nil {
			return completionError(err)
		}
		return items, directive
	}
}

func completeKeyNames(deps commandDeps) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		items, directive, err := listCompletionNames(deps, toComplete, func(ctx context.Context, clients daemonClients) ([]string, error) {
			resp, err := clients.key.ListKeys(ctx, &v1.ListKeysRequest{})
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(resp.GetKeys()))
			for _, key := range resp.GetKeys() {
				out = append(out, key.GetName())
			}
			return out, nil
		})
		if err != nil {
			return completionError(err)
		}
		return items, directive
	}
}

func completeSecretNames(deps commandDeps) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		items, directive, err := listCompletionNames(deps, toComplete, func(ctx context.Context, clients daemonClients) ([]string, error) {
			resp, err := clients.secret.ListSecrets(ctx, &v1.ListSecretsRequest{})
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(resp.GetSecrets()))
			for _, secret := range resp.GetSecrets() {
				out = append(out, secret.GetName())
			}
			return out, nil
		})
		if err != nil {
			return completionError(err)
		}
		return items, directive
	}
}

func completePasskeyLabels(deps commandDeps) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		items, directive, err := listCompletionNames(deps, toComplete, func(ctx context.Context, clients daemonClients) ([]string, error) {
			resp, err := clients.passkey.ListPasskeys(ctx, &v1.ListPasskeysRequest{})
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(resp.GetPasskeys()))
			for _, passkey := range resp.GetPasskeys() {
				out = append(out, passkey.GetLabel())
			}
			return out, nil
		})
		if err != nil {
			return completionError(err)
		}
		return items, directive
	}
}

func staticCompletion(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		out := filterCompletionValues(values, toComplete)
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeFilesystemPaths() func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	}
}

func completionError(err error) ([]string, cobra.ShellCompDirective) {
	var withExit interface{ ExitCode() int }
	if errors.As(err, &withExit) && withExit.ExitCode() == ExitCodeAuthFailed {
		return cobra.AppendActiveHelp(nil, "vault is locked; run `heimdall vault unlock`"), cobra.ShellCompDirectiveNoFileComp
	}
	return nil, cobra.ShellCompDirectiveNoFileComp
}

func listCompletionNames(
	deps commandDeps,
	toComplete string,
	fetch func(context.Context, daemonClients) ([]string, error),
) ([]string, cobra.ShellCompDirective, error) {
	var names []string
	err := withDaemonClients(context.Background(), deps, func(ctx context.Context, clients daemonClients) error {
		var err error
		names, err = fetch(ctx, clients)
		return err
	})
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp, err
	}
	sort.Strings(names)
	return filterCompletionValues(names, toComplete), cobra.ShellCompDirectiveNoFileComp, nil
}

func filterCompletionValues(values []string, prefix string) []string {
	if len(values) == 0 {
		return nil
	}
	prefix = strings.TrimSpace(prefix)
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if prefix != "" && !strings.HasPrefix(value, prefix) {
			continue
		}
		out = append(out, value)
	}
	return out
}

func newCompletionInstallCommand(root *cobra.Command, deps commandDeps) *cobra.Command {
	var (
		shellName string
		target    string
		updateRC  bool
		verify    bool
		overwrite bool
		dryRun    bool
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install shell completion script",
		Example: "  heimdall completion install --shell zsh\n" +
			"  heimdall completion install --shell bash --path ~/.local/share/bash-completion/completions/heimdall",
		RunE: func(cmd *cobra.Command, _ []string) error {
			shellID := normalizeShellName(shellName)
			if shellID == "" {
				shellID = detectCompletionShell()
			}
			if shellID == "" {
				return usageErrorf("completion install requires --shell (bash|zsh|fish)")
			}
			if shellID != completionShellBash && shellID != completionShellZsh && shellID != completionShellFish {
				return usageErrorf("unsupported shell %q (expected bash|zsh|fish)", shellID)
			}

			destPath, err := resolveCompletionPath(shellID, target)
			if err != nil {
				return err
			}
			payload, err := generateCompletionScript(root, shellID)
			if err != nil {
				return err
			}
			if dryRun {
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{
						"shell":   shellID,
						"path":    destPath,
						"dry_run": true,
					})
				}
				_, err := fmt.Fprintf(deps.out, "completion install dry-run: shell=%s path=%s\n", shellID, destPath)
				return err
			}

			if !overwrite {
				if _, err := os.Stat(destPath); err == nil {
					return usageErrorf("completion install target already exists: %s (use --overwrite)", destPath)
				}
			}

			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return fmt.Errorf("completion install: create directory: %w", err)
			}
			if err := os.WriteFile(destPath, payload, 0o644); err != nil {
				return fmt.Errorf("completion install: write file: %w", err)
			}
			if updateRC {
				if err := ensureCompletionRCSnippet(shellID, destPath); err != nil {
					return err
				}
			}
			if verify {
				if err := verifyCompletionInstall(shellID, destPath); err != nil {
					return err
				}
			}

			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{
					"shell":      shellID,
					"path":       destPath,
					"updated_rc": updateRC,
					"verified":   verify,
				})
			}
			if deps.globals.Quiet {
				return nil
			}
			if _, err := fmt.Fprintf(deps.out, "completion installed: shell=%s path=%s\n", shellID, destPath); err != nil {
				return err
			}
			if hint := completionPostInstallHint(shellID, updateRC); hint != "" {
				_, err := fmt.Fprintln(deps.out, hint)
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&shellName, "shell", "", "Shell type (bash|zsh|fish)")
	cmd.Flags().StringVar(&target, "path", "", "Install path override")
	cmd.Flags().BoolVar(&updateRC, "update-rc", false, "Append shell rc snippet when needed")
	cmd.Flags().BoolVar(&verify, "verify", true, "Verify completion script content after install")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing completion script")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview install path without writing")
	_ = cmd.RegisterFlagCompletionFunc("shell", staticCompletion(completionShellBash, completionShellZsh, completionShellFish))
	return cmd
}

func completionPostInstallHint(shellName string, updatedRC bool) string {
	switch shellName {
	case completionShellZsh:
		if updatedRC {
			return "next: restart shell (exec zsh)"
		}
		return "next: rerun with --update-rc (or add ~/.zfunc to fpath), then restart shell"
	case completionShellBash:
		if updatedRC {
			return "next: restart shell (exec bash)"
		}
		return "next: rerun with --update-rc (or source the completion file), then restart shell"
	case completionShellFish:
		return "next: restart shell (exec fish)"
	default:
		return ""
	}
}

func normalizeShellName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "/bin/")
	value = strings.TrimPrefix(value, "/usr/bin/")
	if value == "sh" {
		return ""
	}
	return value
}

func detectCompletionShell() string {
	return normalizeShellName(filepath.Base(strings.TrimSpace(os.Getenv("SHELL"))))
}

func resolveCompletionPath(shellName, rawPath string) (string, error) {
	if strings.TrimSpace(rawPath) != "" {
		return expandUserPath(rawPath)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("completion install: resolve home directory: %w", err)
	}
	switch shellName {
	case completionShellBash:
		return filepath.Join(home, ".local", "share", "bash-completion", "completions", "heimdall"), nil
	case completionShellZsh:
		return filepath.Join(home, ".zfunc", "_heimdall"), nil
	case completionShellFish:
		return filepath.Join(home, ".config", "fish", "completions", "heimdall.fish"), nil
	default:
		return "", usageErrorf("unsupported shell %q", shellName)
	}
}

func expandUserPath(rawPath string) (string, error) {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return "", usageErrorf("path must not be empty")
	}
	if strings.HasPrefix(rawPath, "~/") || rawPath == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("completion install: resolve home directory: %w", err)
		}
		if rawPath == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(rawPath, "~/")), nil
	}
	return rawPath, nil
}

func generateCompletionScript(root *cobra.Command, shellName string) ([]byte, error) {
	var buf bytes.Buffer
	switch shellName {
	case completionShellBash:
		if err := root.GenBashCompletion(&buf); err != nil {
			return nil, fmt.Errorf("completion install: generate bash completion: %w", err)
		}
	case completionShellZsh:
		if err := root.GenZshCompletion(&buf); err != nil {
			return nil, fmt.Errorf("completion install: generate zsh completion: %w", err)
		}
		return []byte(hardenZSHCompletionScript(buf.String())), nil
	case completionShellFish:
		if err := root.GenFishCompletion(&buf, true); err != nil {
			return nil, fmt.Errorf("completion install: generate fish completion: %w", err)
		}
	default:
		return nil, usageErrorf("unsupported shell %q", shellName)
	}
	return buf.Bytes(), nil
}

func hardenZSHCompletionScript(script string) string {
	const loopNeedle = "    while IFS='\\n' read -r comp; do\n        # Check if this is an activeHelp statement (i.e., prefixed with $activeHelpMarker)\n"
	const loopReplacement = "    while IFS='\\n' read -r comp; do\n" +
		"        if [[ \"$comp\" =~ '^:[0-9]+$' ]]; then\n" +
		"            __heimdall_debug \"Skipping leaked directive token: ${comp}\"\n" +
		"            continue\n" +
		"        fi\n" +
		"        if [[ \"$comp\" == \"Completion ended with directive:\"* ]]; then\n" +
		"            __heimdall_debug \"Skipping leaked completion summary: ${comp}\"\n" +
		"            continue\n" +
		"        fi\n" +
		"        # Check if this is an activeHelp statement (i.e., prefixed with $activeHelpMarker)\n"
	if strings.Contains(script, "Skipping leaked directive token: ${comp}") {
		return script
	}
	return strings.Replace(script, loopNeedle, loopReplacement, 1)
}

func verifyCompletionInstall(shellName, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("completion verify: read %s: %w", path, err)
	}
	text := string(raw)
	switch shellName {
	case completionShellBash:
		if !strings.Contains(text, "__start_heimdall") {
			return fmt.Errorf("completion verify: %s is not a valid bash completion script", path)
		}
	case completionShellZsh:
		if !strings.Contains(text, "#compdef heimdall") {
			return fmt.Errorf("completion verify: %s is not a valid zsh completion script", path)
		}
	case completionShellFish:
		if !strings.Contains(text, "complete -c heimdall") {
			return fmt.Errorf("completion verify: %s is not a valid fish completion script", path)
		}
	default:
		return usageErrorf("unsupported shell %q", shellName)
	}
	return nil
}

func ensureCompletionRCSnippet(shellName, scriptPath string) error {
	rcPath, snippet, err := completionRCSnippet(shellName, scriptPath)
	if err != nil {
		return err
	}
	if rcPath == "" || snippet == "" {
		return nil
	}
	data, err := os.ReadFile(rcPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("completion install: read rc file %s: %w", rcPath, err)
	}
	if strings.Contains(string(data), snippet) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(rcPath), 0o755); err != nil {
		return fmt.Errorf("completion install: create rc directory: %w", err)
	}
	file, err := os.OpenFile(rcPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("completion install: open rc file %s: %w", rcPath, err)
	}
	defer func() { _ = file.Close() }()
	if _, err := fmt.Fprintf(file, "\n%s\n", snippet); err != nil {
		return fmt.Errorf("completion install: append rc snippet: %w", err)
	}
	return nil
}

func completionRCSnippet(shellName, scriptPath string) (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("completion install: resolve home directory: %w", err)
	}
	switch shellName {
	case completionShellBash:
		return filepath.Join(home, ".bashrc"), fmt.Sprintf("source %q", scriptPath), nil
	case completionShellZsh:
		absScript, err := filepath.Abs(scriptPath)
		if err != nil {
			return "", "", fmt.Errorf("completion install: resolve path: %w", err)
		}
		snippet := fmt.Sprintf("fpath=(%q $fpath)\nautoload -Uz compinit && compinit", filepath.Dir(absScript))
		return filepath.Join(home, ".zshrc"), snippet, nil
	case completionShellFish:
		return filepath.Join(home, ".config", "fish", "config.fish"), "", nil
	default:
		return "", "", usageErrorf("unsupported shell %q", shellName)
	}
}
