//go:build !windows && !darwin && !linux

package run

// groupHasOthers: no process-table query is implemented on this platform, so
// the conservative exec-like model is used whenever a terminal is present.
func groupHasOthers(pgid int) bool { return true }
