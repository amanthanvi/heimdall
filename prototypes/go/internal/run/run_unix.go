//go:build !windows

package run

import (
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/x/term"
	"golang.org/x/sys/unix"
)

var forwarded = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGWINCH}

// Signal and terminal model (K6, K6a; docs/g02/slice-contract.md §9, §9.1).
//
// Go's os/signal reports no siginfo, so heimdall-proto cannot tell a signal
// the kernel sent to its whole process group (terminal Ctrl-C, killpg) from
// one sent to its PID alone. The model therefore depends on who else shares
// heimdall-proto's process group and terminal:
//
//   - modeNoTTY: no controlling terminal (none on stdio, and /dev/tty cannot
//     be opened). The child runs in its own process group; every signal
//     heimdall-proto receives is forwarded once. No job control exists.
//   - modeExclusive: there is a controlling terminal, heimdall-proto is the
//     only process in its process group, and neither stdin nor stdout is a
//     pipe or socket (so it is not a pipeline member). The child runs in its own
//     process group, which gets the terminal foreground whenever
//     heimdall-proto's group holds it: at start, and after the shell's `fg`
//     (polled every handoffPoll). A terminal signal then reaches only the
//     child's group, and every signal heimdall-proto receives is explicit or
//     group-directed at heimdall-proto's group, so it is forwarded once.
//     Taking the foreground from heimdall-proto's own group takes it from no
//     other process. Stops of the child are mirrored onto heimdall-proto's
//     group (only heimdall-proto) so the shell sees the job stop.
//   - modeShared: there is a controlling terminal and heimdall-proto shares
//     its process group (pipeline peers, or the script that started it as a
//     `&` job of a non-job-control shell), or stdin or stdout is a pipe or
//     socket. The child stays in heimdall-proto's process group (exec
//     semantics) and heimdall-proto never changes the terminal foreground or
//     stops its group (K6a). Every signal heimdall-proto receives is forwarded
//     (K6d, ranked above the §4 duplicate rule by K6b): a SIGINT, SIGQUIT,
//     SIGWINCH or SIGHUP that the terminal generated for the foreground group
//     has then reached the child twice, once from the kernel and once
//     forwarded. Without siginfo the two origins cannot be told apart.
//
// In every mode a signal that heimdall-proto inherited as ignored and that
// the Go runtime leaves ignored (SIGINT, SIGHUP) is neither handled nor
// forwarded, and stays ignored in the child (exec semantics). The runtime
// installs its own handler for SIGQUIT, SIGTERM and SIGWINCH whatever their
// inherited disposition and resets it to the default in the child; that is a
// stack limitation recorded in REPORT.md.
//
// Job control (K6e, modeExclusive): when the child stops, heimdall-proto
// stops itself with kill(0, sig) so the shell sees the job stop. In a
// multithreaded process that call returns before the stop has taken effect
// (Linux stops the thread group asynchronously), so heimdall-proto then waits
// for its own SIGCONT before it looks at the terminal again (stopSelf).

type mode int

const (
	modeNoTTY mode = iota
	modeExclusive
	modeShared
)

const handoffPoll = 50 * time.Millisecond

// stopWait bounds the wait for our own SIGCONT after kill(0, sig) when the
// stop was not taken at all (the stop signal was inherited as ignored, or the
// group became orphaned in between). A stop takes effect within
// microseconds, so a running heimdall-proto that sees no SIGCONT within this
// time was not stopped.
const stopWait = time.Second

// isCtty reports a terminal that is our controlling terminal: TIOCGPGRP
// fails for a terminal that is not. The terminal check comes first because
// BSD-derived kernels (macOS) also answer TIOCGPGRP on pipes and sockets.
func isCtty(fd int) bool {
	if !term.IsTerminal(uintptr(fd)) {
		return false
	}
	_, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	return err == nil
}

// controllingTTY returns a descriptor of our controlling terminal: a stdio
// descriptor if one is, else /dev/tty opened read-only without blocking.
// closeFn releases an opened /dev/tty.
func controllingTTY() (fd int, closeFn func()) {
	for _, fd := range []int{0, 1, 2} {
		if isCtty(fd) {
			return fd, func() {}
		}
	}
	t, err := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, func() {}
	}
	if !isCtty(t) {
		unix.Close(t)
		return -1, func() {}
	}
	return t, func() { unix.Close(t) }
}

func tcgetpgrp(fd int) int {
	pg, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		return -1
	}
	return pg
}

// stdioIsPipe reports a stdin or stdout that is a pipe, FIFO or socket:
// heimdall-proto is then most likely a pipeline member, even if its peers
// have not yet joined its process group. stderr is not considered: a piped
// stderr alone (log capture) does not make a pipeline.
func stdioIsPipe() bool {
	for _, fd := range []int{0, 1} {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil {
			if t := st.Mode & unix.S_IFMT; t == unix.S_IFIFO || t == unix.S_IFSOCK {
				return true
			}
		}
	}
	return false
}

// chooseMode decides the model once, before the child starts.
func chooseMode(ttyFD, own int) mode {
	switch {
	case ttyFD < 0:
		return modeNoTTY
	case stdioIsPipe() || groupHasOthers(own):
		return modeShared
	default:
		return modeExclusive
	}
}

// startAndWait launches the child, forwards signals according to the mode,
// reaps the child, and in modeExclusive returns the terminal foreground to
// heimdall-proto's group if the child's group held it.
func startAndWait(cmd *exec.Cmd) Status {
	ttyFD, closeTTY := controllingTTY()
	defer closeTTY()
	own := unix.Getpgrp()
	md := chooseMode(ttyFD, own)

	switch md {
	case modeNoTTY:
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	case modeExclusive:
		attr := &syscall.SysProcAttr{Setpgid: true}
		if tcgetpgrp(ttyFD) == own {
			attr.Foreground, attr.Ctty = true, ttyFD // Ctty: parent descriptor
		}
		cmd.SysProcAttr = attr
	case modeShared:
		// exec semantics: the child stays in heimdall-proto's group.
	}

	var handled []os.Signal
	for _, s := range forwarded {
		if !signal.Ignored(s) { // inherited SIG_IGN: not handled, not forwarded (K6a)
			handled = append(handled, s)
		}
	}
	sigs := make(chan os.Signal, 16)
	if len(handled) > 0 {
		signal.Notify(sigs, handled...)
	}
	defer signal.Stop(sigs)
	cont := make(chan os.Signal, 1)

	if err := cmd.Start(); err != nil {
		msg := "command could not be started"
		if os.IsPermission(err) {
			msg = "command is not executable"
		}
		return Status{Exit: ExitLaunchFailed, LaunchErr: msg}
	}
	pid := cmd.Process.Pid // == the child's process group id except in modeShared
	if md == modeExclusive {
		// tcsetpgrp from a background group raises SIGTTOU; heimdall-proto
		// ignores it from now on. Only after Start: an ignored disposition
		// would be inherited by the child. os/signal cannot restore SIG_DFL for
		// SIGTTOU (Reset leaves it ignored), so it is not toggled per call.
		signal.Ignore(syscall.SIGTTOU)
		// Our own SIGCONT tells stopSelf that a mirrored stop is over (K6e).
		// Also only after Start: a handled signal is reset to SIG_DFL in the
		// child, which would drop an inherited SIG_IGN for SIGCONT.
		signal.Notify(cont, syscall.SIGCONT)
		defer signal.Stop(cont)
	}

	var mu sync.Mutex // serializes signal delivery and terminal handoff with reaping
	reaped := false
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				mu.Lock()
				if !reaped {
					_ = cmd.Process.Signal(s) // every mode: forward (K6, K6d)
				}
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()
	if md == modeExclusive {
		go func() {
			t := time.NewTicker(handoffPoll)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					mu.Lock()
					if !reaped && tcgetpgrp(ttyFD) == own && !groupHasOthers(own) {
						setFG(ttyFD, pid) // we are in the foreground: no SIGTTOU
					}
					mu.Unlock()
				case <-done:
					return
				}
			}
		}()
	}

	flags := 0
	if md == modeExclusive {
		flags = syscall.WUNTRACED
	}
	var ws syscall.WaitStatus
	for {
		_, err := syscall.Wait4(pid, &ws, flags, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			close(done)
			if md == modeExclusive {
				restoreFG(ttyFD, pid, own)
			}
			return Status{Launched: true, Exit: 1}
		}
		if ws.Stopped() {
			mirrorStop(ttyFD, pid, own, ws.StopSignal(), &mu, cont)
			continue
		}
		break
	}
	mu.Lock()
	reaped = true
	mu.Unlock()
	close(done)
	if md == modeExclusive {
		restoreFG(ttyFD, pid, own)
	}

	if ws.Signaled() {
		n := int(ws.Signal())
		return Status{Launched: true, Signal: intp(n), Exit: 128 + n}
	}
	code := ws.ExitStatus()
	return Status{Launched: true, ExitCode: intp(code), Exit: code}
}

// mirrorStop handles a stopped child (modeExclusive only).
func mirrorStop(ttyFD, pid, own int, sig syscall.Signal, mu *sync.Mutex, cont <-chan os.Signal) {
	mu.Lock()
	defer mu.Unlock()
	fg := tcgetpgrp(ttyFD)
	if fg == own && (sig == syscall.SIGTTIN || sig == syscall.SIGTTOU) {
		// The child touched the terminal in the short window before the
		// handoff: give it the terminal and let it continue.
		setFG(ttyFD, pid)
		_ = syscall.Kill(-pid, syscall.SIGCONT)
		return
	}
	// Stop our own group (heimdall-proto alone in modeExclusive) so the shell
	// sees the job stop. SIGSTOP is never sent to our own group: in an
	// orphaned group the kernel discards SIGTSTP/SIGTTIN/SIGTTOU, but SIGSTOP
	// would stop us with nobody to continue us. SIGTTOU is ignored by
	// heimdall-proto (setFG), so that stop is mirrored as SIGTSTP.
	if sig == syscall.SIGSTOP || sig == syscall.SIGTTOU {
		sig = syscall.SIGTSTP
	}
	if fg == pid {
		setFG(ttyFD, own) // reclaim the terminal for the shell's view of the job
	}
	stopSelf(sig, own, cont)
	// Resumed (or the stop was not taken): hand the terminal back only if our
	// group holds the foreground (`fg`), never after `bg`.
	if tcgetpgrp(ttyFD) == own {
		setFG(ttyFD, pid)
	}
	_ = syscall.Kill(-pid, syscall.SIGCONT)
}

// stopSelf stops heimdall-proto's group with sig and returns once heimdall-
// proto has been continued. kill(0, sig) returns before a multithreaded
// process has actually stopped, so the return of kill says nothing; our own
// SIGCONT does (K6e). If the stop cannot happen (orphaned group, or the
// signal inherited as ignored) it returns after a short or bounded wait.
func stopSelf(sig syscall.Signal, own int, cont <-chan os.Signal) {
	for len(cont) > 0 { // a SIGCONT from an earlier `fg` or `bg`
		<-cont
	}
	if orphaned(own) {
		time.Sleep(handoffPoll) // the kernel discards the stop; avoid a busy loop
		return
	}
	_ = syscall.Kill(0, sig)
	select {
	case <-cont:
	case <-time.After(stopWait):
	}
}

// orphaned reports whether our process group is orphaned (POSIX): no member
// has a parent in another process group of the same session. In modeExclusive
// heimdall-proto is the only member, so only its parent counts. Errors count
// as orphaned, which never waits for a SIGCONT that may not come.
func orphaned(own int) bool {
	ppid := os.Getppid()
	sid, err1 := unix.Getsid(0)
	psid, err2 := unix.Getsid(ppid)
	ppg, err3 := unix.Getpgid(ppid)
	if err1 != nil || err2 != nil || err3 != nil {
		return true
	}
	return psid != sid || ppg == own
}

// restoreFG gives the terminal foreground back to heimdall's group if the
// child's group holds it; it never takes the terminal from anyone else.
func restoreFG(ttyFD, pid, own int) {
	if tcgetpgrp(ttyFD) == pid {
		setFG(ttyFD, own)
	}
}

// setFG is tcsetpgrp. From a background group it would raise SIGTTOU, which
// heimdall-proto ignores in modeExclusive once the child has started.
func setFG(fd, pgid int) {
	_ = unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pgid)
}
