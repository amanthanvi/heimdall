package run

import (
	"bytes"
	"os"
	"strconv"
)

// groupHasOthers reports whether any process other than heimdall-proto is in
// process group pgid, by scanning /proc/<pid>/stat (field 5, pgrp). On error
// it answers true, which selects the conservative exec-like model.
func groupHasOthers(pgid int) bool {
	d, err := os.Open("/proc")
	if err != nil {
		return true
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return true
	}
	self := os.Getpid()
	for _, n := range names {
		pid, err := strconv.Atoi(n)
		if err != nil || pid == self {
			continue
		}
		b, err := os.ReadFile("/proc/" + n + "/stat")
		if err != nil {
			continue // exited meanwhile
		}
		// "pid (comm) state ppid pgrp ...": comm may contain spaces and ')'.
		i := bytes.LastIndexByte(b, ')')
		if i < 0 {
			continue
		}
		f := bytes.Fields(b[i+1:])
		if len(f) >= 3 {
			if pg, err := strconv.Atoi(string(f[2])); err == nil && pg == pgid {
				return true
			}
		}
	}
	return false
}
