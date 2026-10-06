//go:build windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

var (
	advapi32     = windows.NewLazySystemDLL("advapi32.dll")
	pImpersonate = advapi32.NewProc("ImpersonateNamedPipeClient") // not wrapped by x/sys/windows
)

func redactSID(s string) string { // never write machine/user-unique SID bodies to evidence
	if strings.HasPrefix(s, "S-1-5-21-") {
		return "S-1-5-21-<redacted>-" + s[strings.LastIndex(s, "-")+1:]
	}
	return s
}

func tokenUserSID(t windows.Token) (*windows.SID, error) {
	u, err := t.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

func selfSID() (*windows.SID, error) {
	t := windows.GetCurrentProcessToken()
	return tokenUserSID(t)
}

// clientSIDByImpersonation: ImpersonateNamedPipeClient, read the thread token, always revert.
// Needs the OS thread pinned; if the revert fails the thread must never be returned to the Go pool.
func clientSIDByImpersonation(h windows.Handle) (sid *windows.SID, level uint32, err error) {
	runtime.LockOSThread()
	if r, _, e := pImpersonate.Call(uintptr(h)); r == 0 {
		runtime.UnlockOSThread()
		return nil, 0, fmt.Errorf("ImpersonateNamedPipeClient: %w", e)
	}
	defer func() {
		if rerr := windows.RevertToSelf(); rerr != nil {
			panic("RevertToSelf failed; cannot continue on an impersonating thread") // fail closed
		}
		runtime.UnlockOSThread()
	}()
	th, err := windows.GetCurrentThread()
	if err != nil {
		return nil, 0, err
	}
	var tok windows.Token
	if err = windows.OpenThreadToken(th, windows.TOKEN_QUERY, true, &tok); err != nil {
		return nil, 0, fmt.Errorf("OpenThreadToken: %w", err)
	}
	defer tok.Close()
	var ret uint32
	if err = windows.GetTokenInformation(tok, windows.TokenImpersonationLevel, (*byte)(unsafe.Pointer(&level)), 4, &ret); err != nil {
		return nil, 0, fmt.Errorf("GetTokenInformation(level): %w", err)
	}
	sid, err = tokenUserSID(tok)
	if err == nil {
		sid, err = sid.Copy() // the SID memory belongs to the token buffer; copy before returning
	}
	return sid, level, err
}

func clientSIDByPID(h windows.Handle) (pid uint32, sid *windows.SID, err error) {
	if err = windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		return
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err = windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return
	}
	defer tok.Close()
	sid, err = tokenUserSID(tok)
	if err == nil {
		sid, err = sid.Copy()
	}
	return
}

// serve handles one connection: authenticate first, speak second.
func serve(c net.Conn, want *windows.SID, emit func(map[string]any)) {
	defer c.Close()
	ev := map[string]any{"event": "conn"}
	fd, ok := c.(interface{ Fd() uintptr })
	if !ok {
		ev["decision"], ev["error"] = "refuse", "no handle"
		emit(ev)
		return
	}
	h := windows.Handle(fd.Fd())
	sid, level, err := clientSIDByImpersonation(h)
	accept := err == nil && sid.Equals(want)
	if err != nil {
		ev["impersonation_error"] = err.Error()
	} else {
		ev["client_sid"], ev["impersonation_level"] = redactSID(sid.String()), level
	}
	if pid, psid, perr := clientSIDByPID(h); perr == nil {
		ev["client_pid_is_nonzero"], ev["pid_sid_matches_expected"] = pid != 0, psid.Equals(want)
	} else {
		ev["pid_check_error"] = perr.Error()
	}
	ev["decision"] = map[bool]string{true: "accept", false: "refuse"}[accept]
	emit(ev)
	if !accept {
		io.WriteString(c, "denied\n")
	} else {
		io.WriteString(c, "ok\n")
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		io.WriteString(c, "echo:"+strings.TrimSpace(line)+"\n")
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.Copy(io.Discard, c) // wait for the client to close so the verdict is not lost
}

func runPipeServer(name string, count, timeoutSec int, expectSID string, emit func(map[string]any)) error {
	me, err := selfSID()
	if err != nil {
		return err
	}
	want := me
	if expectSID != "" {
		if want, err = windows.StringToSid(expectSID); err != nil {
			return err
		}
	}
	// Protected DACL, one ACE: GENERIC_ALL for the current user SID. SYSTEM/Administrators/Everyone get nothing.
	sddl := "D:P(A;;GA;;;" + me.String() + ")"
	l, err := winio.ListenPipe(`\\.\pipe\`+name, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 4096, OutputBufferSize: 4096})
	if err != nil {
		return err
	}
	defer l.Close()
	time.AfterFunc(time.Duration(timeoutSec)*time.Second, func() { l.Close() })
	emit(map[string]any{"event": "listening", "dacl": "D:P(A;;GA;;;<current-user>)", "first_instance_exclusive": true, "reject_remote": true})
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		c, err := l.Accept()
		if err != nil {
			break
		}
		wg.Add(1)
		go func() { defer wg.Done(); serve(c, want, emit) }()
	}
	wg.Wait()
	return nil
}

// runPipeClient opens the pipe with SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION (go-winio sets both).
func runPipeClient(name, level string) map[string]any {
	imp := winio.PipeImpLevelIdentification
	switch level {
	case "anonymous":
		imp = winio.PipeImpLevelAnonymous
	case "impersonation":
		imp = winio.PipeImpLevelImpersonation
	}
	res := map[string]any{"op": "pipe-client", "level": level}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := winio.DialPipeAccessImpLevel(ctx, `\\.\pipe\`+name, windows.GENERIC_READ|windows.GENERIC_WRITE, imp)
	if err != nil {
		res["ok"], res["error"] = false, err.Error()
		return res
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	verdict, err := r.ReadString('\n')
	res["verdict"] = strings.TrimSpace(verdict)
	if err != nil && verdict == "" {
		res["ok"], res["error"] = false, err.Error()
		return res
	}
	if strings.TrimSpace(verdict) != "ok" {
		res["ok"] = false
		return res
	}
	io.WriteString(c, "hello\n")
	echo, _ := r.ReadString('\n')
	res["echo"] = strings.TrimSpace(echo)
	res["ok"] = res["echo"] == "echo:hello"
	return res
}
