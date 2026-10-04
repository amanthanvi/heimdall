// Package agent implements the G02 explicit SSH-agent identity probe
// (docs/g02/slice-contract.md §3, draft-miller-ssh-agent). It only ever sends
// SSH_AGENTC_REQUEST_IDENTITIES and never signs.
package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Protocol constants and bounds.
const (
	MsgFailure            = 5
	MsgRequestIdentities  = 11
	MsgIdentitiesAnswer   = 12
	MaxFrameLen           = 262144
	MaxKeys               = 1024
	frameLenPrefix        = 4
	minEncodedKeyOverhead = 8 // two uint32 string lengths
)

// RequestIdentitiesFrame is the only message this package ever sends.
var RequestIdentitiesFrame = []byte{0, 0, 0, 1, MsgRequestIdentities}

// Identity is one emitted key; the raw blob is never retained.
type Identity struct {
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
}

// ErrProtocol marks a malformed or out-of-bounds response (AGENT_PROTOCOL_ERROR).
var ErrProtocol = errors.New("agent protocol error")

// ErrRefused marks SSH_AGENT_FAILURE (AGENT_REFUSED).
var ErrRefused = errors.New("agent refused request")

func protoErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, a...))
}

// ErrNoResponse marks a peer that closed the connection before sending any
// response byte (K3, docs/g02/slice-contract.md §9): AGENT_UNAVAILABLE.
var ErrNoResponse = errors.New("agent closed the connection before any response byte")

// ReadFrame reads one length-prefixed frame. The length is checked against
// MaxFrameLen before any body allocation. EOF or a connection reset (K3,
// K3a) before any response byte is ErrNoResponse; EOF or a reset after at
// least one byte but before a complete frame is a protocol (truncation)
// error. Other errors (for example a deadline, or our own close on cancel)
// are returned unwrapped for the caller to classify.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [frameLenPrefix]byte
	if n, err := io.ReadFull(r, hdr[:]); err != nil {
		if n == 0 && (errors.Is(err, io.EOF) || isReset(err)) {
			return nil, ErrNoResponse
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isReset(err) {
			return nil, protoErr("truncated frame header")
		}
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, protoErr("empty frame")
	}
	if n > MaxFrameLen {
		return nil, protoErr("frame length %d exceeds %d", n, MaxFrameLen)
	}
	body := make([]byte, n) // bounded by MaxFrameLen above
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isReset(err) {
			return nil, protoErr("truncated frame body")
		}
		return nil, err
	}
	return body, nil
}

type cursor struct{ b []byte }

func (c *cursor) u32() (uint32, bool) {
	if len(c.b) < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(c.b)
	c.b = c.b[4:]
	return v, true
}

// str returns a subslice; the declared length is compared to the remaining
// bytes before slicing, so no allocation is driven by untrusted lengths.
func (c *cursor) str() ([]byte, bool) {
	n, ok := c.u32()
	if !ok || uint64(n) > uint64(len(c.b)) {
		return nil, false
	}
	s := c.b[:n]
	c.b = c.b[n:]
	return s, true
}

// ParseResponse parses one response frame body (without length prefix).
func ParseResponse(body []byte) ([]Identity, error) {
	if len(body) == 0 {
		return nil, protoErr("empty frame")
	}
	switch body[0] {
	case MsgFailure:
		if len(body) != 1 {
			return nil, protoErr("trailing bytes after SSH_AGENT_FAILURE")
		}
		return nil, ErrRefused
	case MsgIdentitiesAnswer:
	default:
		return nil, protoErr("unexpected message type %d", body[0])
	}
	c := &cursor{b: body[1:]}
	nkeys, ok := c.u32()
	if !ok {
		return nil, protoErr("truncated nkeys")
	}
	if nkeys > MaxKeys {
		return nil, protoErr("nkeys %d exceeds %d", nkeys, MaxKeys)
	}
	if uint64(nkeys)*minEncodedKeyOverhead > uint64(len(c.b)) {
		return nil, protoErr("nkeys %d exceeds remaining frame", nkeys)
	}
	ids := make([]Identity, 0, nkeys) // nkeys <= MaxKeys and fits the frame
	for i := uint32(0); i < nkeys; i++ {
		blob, ok := c.str()
		if !ok {
			return nil, protoErr("key %d: key_blob length exceeds frame", i)
		}
		comment, ok := c.str()
		if !ok {
			return nil, protoErr("key %d: comment length exceeds frame", i)
		}
		kc := &cursor{b: blob}
		kt, ok := kc.str()
		if !ok {
			return nil, protoErr("key %d: key type length exceeds key_blob", i)
		}
		sum := sha256.Sum256(blob)
		ids = append(ids, Identity{
			KeyType:     SafeText(kt),
			Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
			Comment:     SafeText(comment),
		})
	}
	if len(c.b) != 0 {
		return nil, protoErr("%d trailing bytes after last key", len(c.b))
	}
	return ids, nil
}

// SafeText decodes bytes as UTF-8, replacing invalid sequences with U+FFFD.
// Control characters (C0, DEL, C1) are also replaced with U+FFFD so that no
// terminal escape sequence can be carried in a machine string (contract §1,
// spec §11.2). See REPORT.md escalation on this interpretation.
func SafeText(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size <= 1 {
			sb.WriteRune(utf8.RuneError)
		} else if unicode.IsControl(r) {
			sb.WriteRune(utf8.RuneError)
		} else {
			sb.WriteRune(r)
		}
		b = b[size:]
	}
	return sb.String()
}
