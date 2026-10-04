//go:build windows

package main

import "os"

// openMeta opens the --meta-file for writing. COMPILE-CHECKED ONLY.
func openMeta(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}
