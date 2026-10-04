//go:build windows

package profile

import "os"

// openNoBlock: Load has already refused non-regular paths (named pipes,
// devices, directories) by Stat, so a plain open cannot block on Windows.
// COMPILE-CHECKED ONLY.
func openNoBlock(path string) (*os.File, error) { return os.Open(path) }
