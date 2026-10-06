//go:build !windows

// Non-Windows stub so `go vet ./...` and editors work on the dev host.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "x4-windows spike runs on Windows only")
	os.Exit(2)
}
