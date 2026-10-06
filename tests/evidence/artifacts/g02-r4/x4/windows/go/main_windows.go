//go:build windows

// x4-windows-go: compile-only spike for G02 round 4 / X4 (DPAPI, CNG, named pipe + client SID check).
// Subcommands: dpapi | cng -op probe|create|sign|delete|all [-provider software|platform] [-name N]
//
//	pipe-server [-name N] [-count N] [-timeout S] [-expect-sid SID] | pipe-client [-name N] [-level L]
//
// Each prints one JSON object per line. No secrets are printed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
)

var outMu sync.Mutex

func emit(m map[string]any) {
	outMu.Lock()
	defer outMu.Unlock()
	b, _ := json.Marshal(m)
	fmt.Println(string(b))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: x4 dpapi|cng|pipe-server|pipe-client [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	op := fs.String("op", "all", "cng op")
	prov := fs.String("provider", "software", "software|platform")
	name := fs.String("name", "heimdall-x4-spike", "key name / pipe name")
	count := fs.Int("count", 1, "connections to serve")
	timeout := fs.Int("timeout", 30, "server lifetime seconds")
	expect := fs.String("expect-sid", "", "override expected client SID (refusal test)")
	level := fs.String("level", "identification", "client impersonation level")
	fs.Parse(os.Args[2:])

	var res map[string]any
	switch os.Args[1] {
	case "dpapi":
		res = runDPAPI()
	case "cng":
		res = runCNG(*op, *prov, *name)
	case "pipe-server":
		if err := runPipeServer(*name, *count, *timeout, *expect, emit); err != nil {
			emit(map[string]any{"event": "error", "error": err.Error()})
			os.Exit(1)
		}
		return
	case "pipe-client":
		res = runPipeClient(*name, *level)
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand")
		os.Exit(2)
	}
	emit(res)
	if res["ok"] != true {
		os.Exit(1)
	}
}
