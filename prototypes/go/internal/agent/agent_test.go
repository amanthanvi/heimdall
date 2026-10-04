package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

func keyBlob(kt string) []byte {
	return append(sshString([]byte(kt)), sshString([]byte("fake-key-material"))...)
}

func answer(keys ...[2][]byte) []byte {
	b := []byte{MsgIdentitiesAnswer}
	b = binary.BigEndian.AppendUint32(b, uint32(len(keys)))
	for _, k := range keys {
		b = append(b, sshString(k[0])...)
		b = append(b, sshString(k[1])...)
	}
	return b
}

func frame(body []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}

func TestParseOK(t *testing.T) {
	blob := keyBlob("ssh-ed25519")
	ids, err := ParseResponse(answer([2][]byte{blob, []byte("me@host \xff ok")}))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	if len(ids) != 1 || ids[0].KeyType != "ssh-ed25519" || ids[0].Fingerprint != want || ids[0].Comment != "me@host � ok" {
		t.Fatalf("%+v", ids)
	}
	if len(ids[0].Fingerprint) != len("SHA256:")+43 {
		t.Fatal("fingerprint length")
	}
	ids, err = ParseResponse(answer())
	if err != nil || len(ids) != 0 {
		t.Fatal("zero keys")
	}
}

func TestParseRejects(t *testing.T) {
	good := answer([2][]byte{keyBlob("ssh-ed25519"), []byte("c")})
	hugeN := []byte{MsgIdentitiesAnswer, 0xff, 0xff, 0xff, 0xff}
	overMax := binary.BigEndian.AppendUint32([]byte{MsgIdentitiesAnswer}, MaxKeys+1)
	overMax = append(overMax, make([]byte, (MaxKeys+1)*8)...)
	nTooBig := binary.BigEndian.AppendUint32([]byte{MsgIdentitiesAnswer}, 3) // claims 3, has 1
	nTooBig = append(nTooBig, good[5:]...)
	strOver := []byte{MsgIdentitiesAnswer, 0, 0, 0, 1, 0x7f, 0xff, 0xff, 0xff, 'x'}
	cases := map[string][]byte{
		"huge nkeys":          hugeN,
		"nkeys over max":      overMax,
		"nkeys > present":     nTooBig,
		"string over frame":   strOver,
		"trailing bytes":      append(append([]byte{}, good...), 0),
		"truncated nkeys":     {MsgIdentitiesAnswer, 0, 0},
		"truncated key":       good[:len(good)-1],
		"wrong type":          {6},
		"sign response":       {14, 0, 0, 0, 0},
		"failure+trailing":    {MsgFailure, 0},
		"empty":               {},
		"bad keytype in blob": answer([2][]byte{{0, 0, 0, 9, 'a'}, []byte("c")}),
	}
	for name, body := range cases {
		if _, err := ParseResponse(body); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := ParseResponse([]byte{MsgFailure}); !errors.Is(err, ErrRefused) {
		t.Fatalf("failure: %v", err)
	}
}

// countingReader fails the test if more than limit bytes are requested in a
// single Read, proving no allocation is driven by an unchecked length.
func TestReadFrameBounds(t *testing.T) {
	over := binary.BigEndian.AppendUint32(nil, MaxFrameLen+1)
	if _, err := ReadFrame(bytes.NewReader(over)); !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize: %v", err)
	}
	max32 := []byte{0xff, 0xff, 0xff, 0xff}
	if _, err := ReadFrame(bytes.NewReader(max32)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("max uint32: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("short header: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 10, 12})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("short body: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("zero length: %v", err)
	}
	exact := frame(append([]byte{MsgIdentitiesAnswer}, make([]byte, MaxFrameLen-1)...))
	if b, err := ReadFrame(bytes.NewReader(exact)); err != nil || len(b) != MaxFrameLen {
		t.Fatalf("exact max: %v", err)
	}
}

func TestSafeTextStripsEscapes(t *testing.T) {
	if got := SafeText([]byte("a\x1b[31mb\x9bc")); strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x9b) {
		t.Fatalf("%q", got)
	}
}

// fakeAgent serves one connection on a Unix socket in a private temp dir.
func fakeAgent(t *testing.T, handle func(c net.Conn)) (string, chan []byte) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix socket fake agent")
	}
	dir, err := os.MkdirTemp("/tmp", "hpa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req := make([]byte, 5)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := c.Read(req)
		got <- req[:n]
		handle(c)
	}()
	return path, got
}

func TestProbeOK(t *testing.T) {
	path, got := fakeAgent(t, func(c net.Conn) {
		c.Write(frame(answer([2][]byte{keyBlob("ssh-ed25519"), []byte("fixture")})))
	})
	r := Probe(context.Background(), path, 2*time.Second)
	if r.Outcome != OutcomeOK || len(r.Identities) != 1 {
		t.Fatalf("%+v", r)
	}
	if req := <-got; !bytes.Equal(req, RequestIdentitiesFrame) {
		t.Fatalf("sent %x", req)
	}
}

func TestProbeRefusedAndProtocol(t *testing.T) {
	path, _ := fakeAgent(t, func(c net.Conn) { c.Write(frame([]byte{MsgFailure})) })
	if r := Probe(context.Background(), path, 2*time.Second); r.Outcome != OutcomeRefused {
		t.Fatalf("%+v", r)
	}
	path, _ = fakeAgent(t, func(c net.Conn) { c.Write([]byte{0xff, 0xff, 0xff, 0xff}) })
	if r := Probe(context.Background(), path, 2*time.Second); r.Outcome != OutcomeProtocolError {
		t.Fatalf("%+v", r)
	}
	path, _ = fakeAgent(t, func(c net.Conn) { c.Write([]byte{0, 0, 0, 9, 12}) }) // truncated then close
	if r := Probe(context.Background(), path, 2*time.Second); r.Outcome != OutcomeProtocolError {
		t.Fatalf("%+v", r)
	}
}

func TestProbeUnavailable(t *testing.T) {
	dir := t.TempDir()
	if r := Probe(context.Background(), filepath.Join(dir, "missing"), time.Second); r.Outcome != OutcomeUnavailable {
		t.Fatalf("%+v", r)
	}
	path, _ := fakeAgent(t, func(c net.Conn) { c.Write([]byte{0, 0, 0, 9, 12}); time.Sleep(3 * time.Second) })
	start := time.Now()
	r := Probe(context.Background(), path, 300*time.Millisecond)
	if r.Outcome != OutcomeUnavailable || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("%+v after %v", r, time.Since(start))
	}
}

func TestProbeCancel(t *testing.T) {
	path, _ := fakeAgent(t, func(c net.Conn) { time.Sleep(5 * time.Second) })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	r := Probe(ctx, path, 10*time.Second)
	el := time.Since(start) - 200*time.Millisecond
	if r.Outcome != OutcomeCancelled || el > 500*time.Millisecond {
		t.Fatalf("%+v cancel latency %v", r, el)
	}
	t.Logf("cancel latency after signal: %v", el)
}

// K3 (slice-contract §9): peer close before any response byte is
// AGENT_UNAVAILABLE; EOF after at least one byte but before a complete frame
// is AGENT_PROTOCOL_ERROR.
func TestK3EOFClassification(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, ErrNoResponse) || errors.Is(err, ErrProtocol) {
		t.Fatalf("zero bytes: %v", err)
	}
	for _, partial := range [][]byte{{0}, {0, 0, 0}, {0, 0, 0, 5}, {0, 0, 0, 5, 12, 0}} {
		if _, err := ReadFrame(bytes.NewReader(partial)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("%x: %v", partial, err)
		}
	}
	// Close after reading the request, without sending anything.
	path, got := fakeAgent(t, func(c net.Conn) {})
	if r := Probe(context.Background(), path, 2*time.Second); r.Outcome != OutcomeUnavailable {
		t.Fatalf("zero-byte EOF: %+v", r)
	}
	if req := <-got; !bytes.Equal(req, RequestIdentitiesFrame) {
		t.Fatalf("sent %x", req)
	}
	// One response byte, then close.
	path, _ = fakeAgent(t, func(c net.Conn) { c.Write([]byte{0}) })
	if r := Probe(context.Background(), path, 2*time.Second); r.Outcome != OutcomeProtocolError {
		t.Fatalf("one-byte EOF: %+v", r)
	}
}

// K4 (slice-contract §9): SSH_AGENT_FAILURE must have length exactly 1; a
// type-5 frame with any payload is AGENT_PROTOCOL_ERROR, end to end.
func TestK4FailureFrameShape(t *testing.T) {
	for _, body := range [][]byte{{MsgFailure, 0}, {MsgFailure, 1, 2, 3}} {
		path, _ := fakeAgent(t, func(c net.Conn) { c.Write(frame(body)) })
		if r := Probe(context.Background(), path, 2*time.Second); r.Outcome != OutcomeProtocolError {
			t.Fatalf("%x: %+v", body, r)
		}
	}
	path, _ := fakeAgent(t, func(c net.Conn) { c.Write(frame([]byte{MsgFailure})) })
	if r := Probe(context.Background(), path, 2*time.Second); r.Outcome != OutcomeRefused {
		t.Fatalf("length-1 failure: %+v", r)
	}
}

// K1 (slice-contract §9): in key_type and comment, invalid UTF-8 and every
// C0 (including TAB), DEL and C1 code point become U+FFFD.
func TestK1ControlCharactersInIdentity(t *testing.T) {
	var ctl []byte
	for r := rune(0); r <= 0x9f; r++ {
		if r < 0x20 || r >= 0x7f {
			ctl = utf8.AppendRune(ctl, r) // C1 as proper 2-byte UTF-8
		}
	}
	raw := append([]byte("k\xffT"), ctl...)
	blob := append(sshString(raw), sshString([]byte("m"))...)
	ids, err := ParseResponse(answer([2][]byte{blob, raw}))
	if err != nil {
		t.Fatal(err)
	}
	want := "k�T" + strings.Repeat("�", 0x20+0x21)
	for _, s := range []string{ids[0].KeyType, ids[0].Comment} {
		if s != want {
			t.Fatalf("%q want %q", s, want)
		}
		for _, r := range s {
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				t.Fatalf("control %U survived", r)
			}
		}
	}
}
