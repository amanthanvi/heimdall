// Command heimdall-proto is the disposable G02 Go + Bubble Tea prototype
// (docs/g02/slice-contract.md). It is gate evidence, not production code.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/term"

	"github.com/heimdall-g02/proto-go/internal/agent"
	"github.com/heimdall-g02/proto-go/internal/profile"
	"github.com/heimdall-g02/proto-go/internal/result"
	"github.com/heimdall-g02/proto-go/internal/run"
	"github.com/heimdall-g02/proto-go/internal/tui"
)

const (
	protoVersion = "0.0.0-g02"
	teaModule    = "charm.land/bubbletea/v2"
	usageText    = `usage:
  heimdall-proto profile show --file <path> [--json]
  heimdall-proto agent list --socket <path> [--timeout-ms N] [--json]
  heimdall-proto run [--meta-file <path>] -- <argv...>
  heimdall-proto tui --file <path>
  heimdall-proto version [--json]`
)

func main() { os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr)) }

func hasJSON(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--json" || a == "-json" || a == "--json=true" || a == "-json=true" {
			return true
		}
	}
	return false
}

// usage reports a usage error: JSON on stdout only with --json; exit 2 always.
func usage(stdout, stderr io.Writer, jsonOut bool, msg string) int {
	fmt.Fprintf(stderr, "heimdall-proto: %s\n%s\n", msg, usageText)
	if jsonOut {
		_ = result.Write(stdout, result.Fail(result.UsageError, nil, msg))
	}
	return result.ExitUsage
}

// exitByResultOnBrokenPipe makes a write to a stdout or stderr whose reader
// has gone fail with EPIPE instead of killing the process (K12 closed stdout,
// slice-contract §9.4, Q17). By default the Go runtime turns that write on
// fd 1/2 into death by SIGPIPE, so a --json error result (which writes
// stdout) died of SIGPIPE while the same error without --json (stderr only)
// exited 2 or 5. With SIGPIPE routed to a channel nobody reads, write errors
// are ignored as before and every mode exits with its result's code.
// Not used for run (the child's signal state must stay as inherited) or tui
// (stdout is a terminal).
func exitByResultOnBrokenPipe() { signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE) }

func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "run" && args[0] != "tui") {
		exitByResultOnBrokenPipe()
	}
	jsonOut := hasJSON(args)
	if len(args) == 0 {
		return usage(stdout, stderr, jsonOut, "missing subcommand")
	}
	switch args[0] {
	case "profile":
		if len(args) < 2 || args[1] != "show" {
			return usage(stdout, stderr, jsonOut, "expected 'profile show'")
		}
		return cmdProfileShow(args[2:], stdout, stderr)
	case "agent":
		if len(args) < 2 || args[1] != "list" {
			return usage(stdout, stderr, jsonOut, "expected 'agent list'")
		}
		return cmdAgentList(args[2:], stdout, stderr)
	case "run":
		return cmdRun(args[1:], stderr)
	case "tui":
		return cmdTUI(args[1:], stdout, stderr)
	case "version":
		return cmdVersion(args[1:], stdout, stderr)
	default:
		return usage(stdout, stderr, jsonOut, "unknown subcommand")
	}
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseFlags parses and rejects stray positional arguments.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errors.New("help requested")
		}
		return errors.New("invalid flag or missing flag value")
	}
	if fs.NArg() > 0 {
		return errors.New("unexpected positional argument")
	}
	return nil
}

func cmdProfileShow(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("profile show")
	file := fs.String("file", "", "")
	jsonOut := fs.Bool("json", false, "")
	if err := parseFlags(fs, args); err != nil {
		return usage(stdout, stderr, hasJSON(args), err.Error())
	}
	if *file == "" {
		return usage(stdout, stderr, *jsonOut, "--file is required")
	}
	p, perr := profile.Load(*file)
	if perr != nil {
		fmt.Fprintf(stderr, "heimdall-proto: %s\n", perr.Error())
		if *jsonOut {
			_ = result.Write(stdout, result.Fail(perr.Code, perr.KeyPath, perr.Message, perr.Warnings...))
		}
		return result.ExitCode(perr.Code)
	}
	if *jsonOut {
		_ = result.Write(stdout, result.OK(result.ProfileOK, map[string]any{"profile": p}))
		return result.ExitOK
	}
	fmt.Fprintf(stdout, "%s (revision %d)\n", tui.Sanitize(p.Name), p.Revision)
	for _, d := range p.Destinations {
		fmt.Fprintf(stdout, "%s  %s@%s:%d\n", tui.Sanitize(d.Alias), tui.Sanitize(d.Account), tui.Sanitize(d.Host), d.Port)
	}
	return result.ExitOK
}

func cmdAgentList(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("agent list")
	sock := fs.String("socket", "", "")
	timeoutRaw := fs.String("timeout-ms", "5000", "")
	jsonOut := fs.Bool("json", false, "")
	if err := parseFlags(fs, args); err != nil {
		return usage(stdout, stderr, hasJSON(args), err.Error())
	}
	if *sock == "" {
		return usage(stdout, stderr, *jsonOut, "--socket is required")
	}
	ms, err := strconv.ParseUint(*timeoutRaw, 10, 31)
	if err != nil || ms == 0 {
		return usage(stdout, stderr, *jsonOut, "--timeout-ms must be a positive integer")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res := agent.Probe(ctx, *sock, time.Duration(ms)*time.Millisecond)

	var env result.Envelope
	switch res.Outcome {
	case agent.OutcomeOK:
		env = result.OK(result.AgentOK, map[string]any{"identities": res.Identities})
	case agent.OutcomeCancelled:
		env = result.CancelledEnvelope()
	case agent.OutcomeRefused:
		env = result.Fail(result.AgentRefused, nil, res.Detail)
	case agent.OutcomeProtocolError:
		env = result.Fail(result.AgentProtocolError, nil, res.Detail)
	default:
		env = result.Fail(result.AgentUnavailable, nil, res.Detail)
	}
	if res.Outcome != agent.OutcomeOK {
		fmt.Fprintf(stderr, "heimdall-proto: agent list: %s\n", res.Detail)
	}
	if *jsonOut {
		_ = result.Write(stdout, env)
	} else if res.Outcome == agent.OutcomeOK {
		for _, id := range res.Identities {
			fmt.Fprintf(stdout, "%s %s %s\n", id.KeyType, id.Fingerprint, id.Comment)
		}
	}
	return result.ExitCode(env.Code)
}

func cmdRun(args []string, stderr io.Writer) int {
	var meta string
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
		case a == "--meta-file" || a == "-meta-file":
			if i+1 >= len(args) {
				return usage(io.Discard, stderr, false, "--meta-file requires a value")
			}
			i++
			meta = args[i]
			continue
		case len(a) > len("--meta-file=") && a[:len("--meta-file=")] == "--meta-file=":
			meta = a[len("--meta-file="):]
			continue
		default:
			return usage(io.Discard, stderr, false, "run: expected '--' before the command")
		}
		break
	}
	if i >= len(args) {
		return usage(io.Discard, stderr, false, "run: missing '--'")
	}
	argv := args[i+1:]
	if len(argv) == 0 {
		return usage(io.Discard, stderr, false, "run: empty command after '--'")
	}

	st := run.Run(argv)
	if !st.Launched {
		fmt.Fprintf(stderr, "heimdall-proto: run: %s\n", st.LaunchErr)
	}
	if meta != "" {
		code, state := result.ChildExited, result.Succeeded
		if !st.Launched {
			code, state = result.ChildLaunchFailed, result.Failed
		}
		env := result.Envelope{
			SchemaVersion: result.SchemaVersion, State: state, Code: code, Warnings: []string{},
			Data: map[string]any{"launched": st.Launched, "exit_code": st.ExitCode, "signal": st.Signal},
		}
		if err := writeMeta(meta, env); err != nil {
			fmt.Fprintln(stderr, "heimdall-proto: run: cannot write --meta-file")
		}
	}
	return st.Exit
}

func writeMeta(path string, env result.Envelope) error {
	f, err := openMeta(path)
	if err != nil {
		return err
	}
	if err := result.Write(f, env); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// tuiBeforeRun is a no-op in the shipped binary. Tests replace it to inject
// a panic before tea.Program.Run (K10).
var tuiBeforeRun = func() {}

func cmdTUI(args []string, stdout, stderr io.Writer) (code int) {
	// K10: an internal panic anywhere on the TUI path that Bubble Tea does not
	// recover itself (before Program.Run, or after it returned) exits 1 with no
	// stdout. Before Run the terminal has not been changed; inside Run Bubble
	// Tea restores it and returns ErrProgramPanic. A panic in a goroutine that
	// Bubble Tea or ultraviolet starts without a recover (input decoding,
	// renderer flush, resize listener) cannot be caught by any Go code and ends
	// the process with status 2: a stack limitation recorded in REPORT.md.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(stderr, "heimdall-proto: tui: internal error (panic)")
			code = result.ExitInternal
		}
	}()
	fs := newFlags("tui")
	file := fs.String("file", "", "")
	if err := parseFlags(fs, args); err != nil {
		return usage(io.Discard, stderr, false, err.Error())
	}
	if *file == "" {
		return usage(io.Discard, stderr, false, "--file is required")
	}
	if !term.IsTerminal(os.Stdin.Fd()) || !term.IsTerminal(os.Stdout.Fd()) {
		return usage(io.Discard, stderr, false, "tui requires a terminal on stdin and stdout")
	}
	p, perr := profile.Load(*file)
	if perr != nil {
		fmt.Fprintf(stderr, "heimdall-proto: %s\n", perr.Error())
		return result.ExitCode(perr.Code)
	}
	// Bubble Tea reads TEA_TRACE (log file) and TEA_DEBUG (panic dump file)
	// from the environment; the contract forbids file writes in tui.
	_ = os.Unsetenv("TEA_TRACE")
	_ = os.Unsetenv("TEA_DEBUG")

	m := tui.New(p.Destinations, os.Getenv("NO_COLOR") != "")
	return runTUI(m, m, os.Stdin, stdout, stderr)
}

// hangupInput reports EOF/EIO on the terminal input (the terminal went away)
// so a hangup without a SIGHUP still ends the picker with 129 (K10). Bubble
// Tea's input reader treats EOF as a silent stop, which would otherwise leave
// the picker running against a dead terminal. Embedding *os.File keeps Fd()
// and Name(), so raw mode and the cancelable reader still apply.
type hangupInput struct {
	*os.File
	onHangup func()
}

func (h hangupInput) Read(p []byte) (int, error) {
	n, err := h.File.Read(p)
	if err != nil && inputHangup(err) {
		h.onHangup()
	}
	return n, err
}

// runTUI runs the picker and maps every exit path to the contract status
// (§5, K10). model is normally m itself; tests substitute a wrapper (for
// example one that panics), pass a pty as in, and add output options.
// Bubble Tea restores the alternate screen, cursor and termios on every
// return path of Run, including a recovered panic.
func runTUI(model tea.Model, m *tui.Model, in *os.File, stdout, stderr io.Writer, opts ...tea.ProgramOption) int {
	var hungUp atomic.Bool
	var prog *tea.Program
	input := hangupInput{File: in, onHangup: func() {
		if !hungUp.Swap(true) {
			go prog.Send(tui.HangupMsg{})
		}
	}}
	base := []tea.ProgramOption{tea.WithoutSignalHandler(), tea.WithInput(input),
		tea.WithColorProfile(colorProfileFromEnv(os.Environ()))}
	tuiBeforeRun()
	prog = tea.NewProgram(model, append(base, opts...)...)

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigs {
			switch s {
			case syscall.SIGTERM:
				prog.Send(tui.TermMsg{})
			case syscall.SIGHUP:
				hungUp.Store(true)
				prog.Send(tui.HangupMsg{})
			default:
				prog.Send(tea.InterruptMsg{})
			}
		}
	}()
	_, err := prog.Run()
	signal.Stop(sigs)
	switch {
	case hungUp.Load() || m.Outcome == tui.HungUp:
		// K10: SIGHUP or terminal hangup: restore what is possible, exit 129.
		return 128 + int(syscall.SIGHUP)
	case errors.Is(err, tea.ErrProgramPanic):
		// K10: internal panic: terminal restored by Bubble Tea, exit 1.
		fmt.Fprintln(stderr, "heimdall-proto: tui: internal error (panic); terminal restored")
		return result.ExitInternal
	case err != nil:
		if inputHangup(err) {
			return 128 + int(syscall.SIGHUP)
		}
		fmt.Fprintln(stderr, "heimdall-proto: tui: internal error; terminal restored")
		return result.ExitInternal
	}
	switch m.Outcome {
	case tui.Selected:
		fmt.Fprintf(stdout, "SELECTED %s\n", tui.Sanitize(m.Alias))
		return 0
	case tui.Cancelled:
		return result.ExitCancelled
	case tui.Terminated:
		return 128 + int(syscall.SIGTERM)
	default:
		return 0
	}
}

// colorProfileFromEnv decides the color profile from environment variables
// only (TERM, COLORTERM, NO_COLOR, CLICOLOR...). The TUI has already checked
// that stdout is a terminal. Bubble Tea would otherwise call
// colorprofile.Detect, which runs `tmux info` (resolved from PATH, no
// timeout) whenever TMUX is set (K16), and reads the terminfo entry that
// TERM, TERMINFO, TERMINFO_DIRS and HOME select through xo/terminfo without a
// size bound, a regular-file check or a path check on TERM: TERM=../../dev/zero
// grew without bound, a FIFO hung the TUI, and a malformed entry panicked the
// decoder before Run. The profile only decides how colors are downsampled;
// the cost of skipping terminfo is that a terminal advertising truecolor
// only through its terminfo Tc/RGB flags gets 256 colors.
func colorProfileFromEnv(environ []string) colorprofile.Profile {
	return colorprofile.Env(environ)
}

// inputHangup reports a terminal input result that means the terminal went
// away rather than an internal error: EIO (Linux, after the pty master closes)
// or EOF (macOS).
func inputHangup(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.EIO)
}

func teaVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == teaModule {
				if d.Replace != nil {
					return d.Replace.Version
				}
				return d.Version
			}
		}
	}
	return "unknown"
}

func cmdVersion(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("version")
	jsonOut := fs.Bool("json", false, "")
	if err := parseFlags(fs, args); err != nil {
		return usage(stdout, stderr, hasJSON(args), err.Error())
	}
	data := map[string]any{
		"name": "heimdall-proto", "version": protoVersion, "candidate": "go",
		"runtime":       runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH,
		"tui_framework": teaModule, "tui_framework_version": teaVersion(),
	}
	if *jsonOut {
		_ = result.Write(stdout, result.OK(result.VersionOK, data))
	} else {
		fmt.Fprintf(stdout, "heimdall-proto %s (go, %s, %s %s)\n", protoVersion, data["runtime"], teaModule, data["tui_framework_version"])
	}
	return result.ExitOK
}
