// sigign: print the ignored-signal mask and the caught-signal mask of one PID
// (darwin), as hex, via sysctl kern.proc.pid. Probe helper for
// M00-T05-r4-x2-t1cal-verify: macOS ps has no keyword for ignored signals.
// Exit 1 if the PID does not exist.
//
// Built offline inside the scratch copy of prototypes/go (its module already requires
// golang.org/x/sys):  cp sigign.go <copy>/cmd/sigign/main.go &&
//   cd <copy> && CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath -o tools/sigign ./cmd/sigign
package main

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func main() {
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		os.Exit(2)
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(kp.Proc.P_pid) != pid {
		os.Exit(1)
	}
	fmt.Printf("%x %x\n", kp.Proc.P_sigignore, kp.Proc.P_sigcatch)
}
