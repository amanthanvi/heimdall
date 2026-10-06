//go:build windows

// argvdump: Windows test child for the G02 X1 native script (Invoke-G02WindowsX1.ps1).
// Harness code, not product code. Standard library only.
//
// Behaviour is selected by environment variables so the argument vector under test is never touched:
//
//	ARGVDUMP_OUT=<file>        write a JSON report: the raw command line (GetCommandLineW) and the
//	                           CommandLineToArgvW split, each as UTF-16 code units in hex, plus the
//	                           executable path (for the resolution-order rows), the working directory
//	                           and ARGVDUMP_TAG.
//	ARGVDUMP_STDOUT_HEX=<hex>  write these bytes to stdout (binary pass-through out of `run`).
//	ARGVDUMP_STDIN_OUT=<file>  copy stdin to <file> until EOF (binary pass-through into `run`).
//	ARGVDUMP_CTRLC=<file>      count console interrupts (os.Interrupt: CTRL_C_EVENT/CTRL_BREAK_EVENT):
//	                           write <file>.ready once the handler is installed, wait up to 20 s for the
//	                           first one, then 1.5 s more, write {"interrupts":n,...} to <file> and exit.
//	ARGVDUMP_EXIT=<int32>      exit code (default 0; 99 when ARGVDUMP_CTRLC saw nothing).
//
// Nothing here reads or prints environment values other than its own ARGVDUMP_* controls.
package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

func u16hex(p *uint16) string {
	if p == nil {
		return ""
	}
	var units []uint16
	for q := unsafe.Pointer(p); *(*uint16)(q) != 0; q = unsafe.Add(q, 2) {
		units = append(units, *(*uint16)(q))
	}
	b := make([]byte, 0, 4*len(units))
	for _, u := range units {
		b = append(b, []byte(strconvHex4(u))...)
	}
	return string(b)
}

func strconvHex4(u uint16) string {
	s := strconv.FormatUint(uint64(u), 16)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

func exitCode() int {
	if v := os.Getenv("ARGVDUMP_EXIT"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return int(int32(n))
		}
	}
	return 0
}

func main() {
	if out := os.Getenv("ARGVDUMP_OUT"); out != "" {
		cl := syscall.GetCommandLine()
		var argc int32
		argv, err := syscall.CommandLineToArgv(cl, &argc)
		rep := map[string]interface{}{"tag": os.Getenv("ARGVDUMP_TAG"), "cmdline_u16": u16hex(cl)}
		if err != nil {
			rep["split_error"] = err.Error()
		} else {
			args := make([]string, 0, argc)
			for i := int32(0); i < argc; i++ {
				args = append(args, u16hex(&(*argv[i])[0]))
			}
			rep["argv_u16"] = args
			syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(argv))))
		}
		if exe, err := os.Executable(); err == nil {
			rep["exe"] = exe
		}
		if wd, err := os.Getwd(); err == nil {
			rep["cwd"] = wd
		}
		b, _ := json.Marshal(rep)
		_ = os.WriteFile(out, append(b, '\n'), 0o600)
	}
	if h := os.Getenv("ARGVDUMP_STDOUT_HEX"); h != "" {
		if b, err := hex.DecodeString(h); err == nil {
			_, _ = os.Stdout.Write(b)
		}
	}
	if p := os.Getenv("ARGVDUMP_STDIN_OUT"); p != "" {
		b, _ := io.ReadAll(os.Stdin)
		_ = os.WriteFile(p, b, 0o600)
	}
	if p := os.Getenv("ARGVDUMP_CTRLC"); p != "" {
		ch := make(chan os.Signal, 16)
		signal.Notify(ch, os.Interrupt)
		_ = os.WriteFile(p+".ready", []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
		n := 0
		start := time.Now()
		var firstMs int64 = -1
		select {
		case <-ch:
			n = 1
			firstMs = time.Since(start).Milliseconds()
		case <-time.After(20 * time.Second):
		}
		if n > 0 {
			t := time.After(1500 * time.Millisecond)
		loop:
			for {
				select {
				case <-ch:
					n++
				case <-t:
					break loop
				}
			}
		}
		b, _ := json.Marshal(map[string]interface{}{"interrupts": n, "first_after_ready_ms": firstMs})
		_ = os.WriteFile(p, append(b, '\n'), 0o600)
		if n == 0 {
			os.Exit(99)
		}
	}
	os.Exit(exitCode())
}
