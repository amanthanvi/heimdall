package main

import (
	"os"
	"testing"
)

// helperChildren maps argv[1] to a helper-child entry point that platform
// test files register (for example hp-child-sigrec, k6d_test.go).
var helperChildren = map[string]func(dir string){}

// TestMain lets tests run this test binary as heimdall-proto itself
// (HP_AS_MAIN=1), so resource and process behavior is measured on a real
// process without needing a separately built artifact.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && helperChildren[os.Args[1]] != nil {
		helperChildren[os.Args[1]](os.Args[2]) // helper child process; never returns
	}
	if os.Getenv("HP_AS_MAIN") == "1" {
		if os.Getenv("HP_TEST_PANIC_BEFORE_RUN") == "1" {
			tuiBeforeRun = func() { panic("K10 test panic before Run") }
		}
		os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}
