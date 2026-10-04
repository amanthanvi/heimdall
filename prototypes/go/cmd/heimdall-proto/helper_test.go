package main

import (
	"os"
	"testing"
)

// TestMain lets tests run this test binary as heimdall-proto itself
// (HP_AS_MAIN=1), so resource and process behavior is measured on a real
// process without needing a separately built artifact.
func TestMain(m *testing.M) {
	if os.Getenv("HP_AS_MAIN") == "1" {
		os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}
