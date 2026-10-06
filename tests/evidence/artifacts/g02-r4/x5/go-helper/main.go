// Command x5-gosup is a disposable M00 G02 round-4 X5 probe (not production code).
//
// It supervises two instances of the Rust iroh helper (x5-iroh helper) over stdio
// length-prefixed frames (u32 big-endian length + UTF-8 text), asks helper B to send one
// message to helper A across a loopback-only iroh link, checks that A received it from B,
// then shuts both down and waits for clean exits. Standard library only, no cgo.
//
// Usage: x5-gosup -helper <path-to-x5-iroh> [-hold-ms N]
// Output: one JSON line on stdout; diagnostics on stderr. Exit 0 only on full success.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const maxFrame = 65536

type child struct {
	name  string
	cmd   *exec.Cmd
	in    io.WriteCloser
	out   *bufio.Reader
	id    string
	addr  string
	frame chan string
	done  chan error
}

func writeFrame(w io.Writer, s string) error {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}
	_, err := io.WriteString(w, s)
	return err
}

func readFrame(r io.Reader) (string, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > maxFrame {
		return "", errors.New("frame too large")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

func start(name, path string) (*child, error) {
	cmd := exec.Command(path, "helper")
	cmd.Env = []string{} // nothing inherited: no SSH_AUTH_SOCK, no proxies
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &child{name: name, cmd: cmd, in: in, out: bufio.NewReader(out), frame: make(chan string, 8), done: make(chan error, 1)}
	go func() {
		for {
			f, err := readFrame(c.out)
			if err != nil {
				close(c.frame)
				return
			}
			c.frame <- f
		}
	}()
	return c, nil
}

func (c *child) expect(prefix string, d time.Duration) (string, error) {
	select {
	case f, ok := <-c.frame:
		if !ok {
			return "", fmt.Errorf("%s: stdout closed while waiting for %q", c.name, prefix)
		}
		if !strings.HasPrefix(f, prefix) {
			return "", fmt.Errorf("%s: got %q, want %q", c.name, f, prefix)
		}
		return f, nil
	case <-time.After(d):
		return "", fmt.Errorf("%s: timeout waiting for %q", c.name, prefix)
	}
}

func (c *child) wait(d time.Duration) (int, error) {
	go func() { c.done <- c.cmd.Wait() }()
	select {
	case <-c.done:
		return c.cmd.ProcessState.ExitCode(), nil
	case <-time.After(d):
		_ = c.cmd.Process.Kill() // exact child we started
		<-c.done
		return -1, fmt.Errorf("%s: did not exit in %s; killed pid %d", c.name, d, c.cmd.Process.Pid)
	}
}

type result struct {
	OK          bool   `json:"ok"`
	Message     string `json:"message"`
	FromMatches bool   `json:"from_matches_sender"`
	AAddr       string `json:"a_addr"`
	BAddr       string `json:"b_addr"`
	ExitA       int    `json:"exit_a"`
	ExitB       int    `json:"exit_b"`
	ElapsedMs   int64  `json:"elapsed_ms"`
	Error       string `json:"error,omitempty"`
}

func run(path string, hold time.Duration) (res result) {
	t0 := time.Now()
	defer func() { res.ElapsedMs = time.Since(t0).Milliseconds() }()
	res.ExitA, res.ExitB = -1, -1
	a, err := start("A", path)
	if err != nil {
		res.Error = "start A: " + err.Error()
		return
	}
	b, err := start("B", path)
	if err != nil {
		res.Error = "start B: " + err.Error()
		_ = a.in.Close()
		res.ExitA, _ = a.wait(5 * time.Second)
		return
	}
	fmt.Fprintf(os.Stderr, "x5-gosup: pid %d, helper A pid %d, helper B pid %d\n", os.Getpid(), a.cmd.Process.Pid, b.cmd.Process.Pid)
	shutdown := func() {
		for _, c := range []*child{a, b} {
			_ = writeFrame(c.in, "shutdown")
			if _, err := c.expect("bye", 10*time.Second); err != nil && res.Error == "" {
				res.Error = err.Error()
			}
			_ = c.in.Close()
		}
		res.ExitA, _ = a.wait(10 * time.Second)
		res.ExitB, _ = b.wait(10 * time.Second)
	}
	defer shutdown()
	for _, c := range []*child{a, b} {
		f, err := c.expect("ready ", 15*time.Second)
		if err != nil {
			res.Error = err.Error()
			return
		}
		p := strings.Split(f, " ")
		if len(p) != 3 {
			res.Error = c.name + ": malformed ready"
			return
		}
		ap, err := net.ResolveUDPAddr("udp", p[2])
		if err != nil || !ap.IP.IsLoopback() {
			res.Error = c.name + ": helper address is not loopback"
			return
		}
		c.id, c.addr = p[1], p[2]
	}
	res.AAddr, res.BAddr = a.addr, b.addr
	msg := "heimdall x5 go->rust->iroh->rust->go"
	if err := writeFrame(b.in, fmt.Sprintf("send %s %s %s", a.id, a.addr, hex.EncodeToString([]byte(msg)))); err != nil {
		res.Error = "write send: " + err.Error()
		return
	}
	got, err := a.expect("recv ", 15*time.Second)
	if err != nil {
		res.Error = err.Error()
		return
	}
	if _, err := b.expect("sent ", 15*time.Second); err != nil {
		res.Error = err.Error()
		return
	}
	p := strings.Split(got, " ")
	if len(p) == 3 {
		raw, _ := hex.DecodeString(p[2])
		res.Message = string(raw)
		res.FromMatches = p[1] == b.id
	}
	if hold > 0 {
		fmt.Fprintf(os.Stderr, "x5-gosup: holding %s for socket inspection\n", hold)
		time.Sleep(hold)
	}
	res.OK = res.Message == msg && res.FromMatches
	return
}

func main() {
	path := flag.String("helper", "", "path to the x5-iroh helper binary")
	holdMs := flag.Int("hold-ms", 0, "pause after the exchange (ms) for socket inspection")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "usage: x5-gosup -helper <path> [-hold-ms N]")
		os.Exit(64)
	}
	res := run(*path, time.Duration(*holdMs)*time.Millisecond)
	ok := res.OK && res.ExitA == 0 && res.ExitB == 0 && res.Error == ""
	res.OK = ok
	_ = json.NewEncoder(os.Stdout).Encode(res)
	if !ok {
		os.Exit(1)
	}
}
