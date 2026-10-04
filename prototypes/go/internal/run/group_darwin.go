package run

import (
	"os"

	"golang.org/x/sys/unix"
)

// groupHasOthers reports whether any process other than heimdall-proto is in
// process group pgid (sysctl kern.proc.pgrp). On error it answers true, which
// selects the conservative exec-like model.
func groupHasOthers(pgid int) bool {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pgid)
	if err != nil {
		return true
	}
	self := os.Getpid()
	for _, p := range procs {
		if int(p.Proc.P_pid) != self {
			return true
		}
	}
	return false
}
