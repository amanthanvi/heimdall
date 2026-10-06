//go:build nobackends

package main

// Baseline build: identical skeleton, no platform backends.
func pick(string) (backend, string) { return nil, "" }
