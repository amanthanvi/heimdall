package profile

import (
	"fmt"

	"github.com/heimdall-g02/proto-go/internal/result"
)

// Parser resource bound (K15, docs/g02/slice-contract.md §9.1).
//
// BurntSushi/toml v1.6.0 needs memory that grows with the number of keys
// times the depth of their key paths, and quadratically with nesting: a
// 32 KB profile of nested inline tables needs more than 2 GB, and a 1 MiB
// file of 8-component dotted keys needs more than 256 MiB. The 1 MiB input
// bound therefore does not bound the parser. checkComplexity is a linear,
// allocation-free structural pre-scan that runs before the parser and
// rejects (SCHEMA_INVALID) any document whose key paths are deeper than
// MaxKeyDepth, whose structure has more than MaxStructureUnits units, or whose
// keys' full paths add up to more than MaxKeyPathBytes (the parser keeps a
// copy of each key's full path, so 60,000 short keys under a header of thirty
// 10 KB components need more than 2 GB). It
// never echoes input text. Any syntax it cannot follow is reported as
// malformed TOML, which the parser would also reject; TestGuardAcceptsValidCorpus
// checks that against the toml-test corpus shipped with the parser module.
const (
	// MaxKeyDepth bounds the full key path depth of every table and value:
	// table header components (+1 for an array of tables), dotted key
	// components, and inline-table/array nesting. A G02 profile needs 3.
	MaxKeyDepth = 32
	// MaxStructureUnits bounds the number of key components plus tables,
	// inline tables and arrays in the whole document.
	MaxStructureUnits = 65536
	// MaxKeyPathBytes bounds the sum, over every key component, of the byte
	// length of its full key path (source bytes, so never less than decoded).
	MaxKeyPathBytes = 2 << 20
)

type scanner struct {
	b     []byte
	i     int
	line  int
	units int
	bytes int
	err   *Error
}

func (s *scanner) fail(msg string) bool {
	if s.err == nil {
		s.err = &Error{Code: result.SchemaInvalid, Message: fmt.Sprintf("%s near line %d", msg, s.line)}
	}
	return false
}

func (s *scanner) malformed() bool { return s.fail("malformed TOML") }

func (s *scanner) eof() bool { return s.i >= len(s.b) }

func (s *scanner) peek() byte {
	if s.eof() {
		return 0
	}
	return s.b[s.i]
}

func (s *scanner) hasPrefix(p string) bool {
	return len(s.b)-s.i >= len(p) && string(s.b[s.i:s.i+len(p)]) == p
}

// ws skips spaces and tabs.
func (s *scanner) ws() {
	for !s.eof() && (s.b[s.i] == ' ' || s.b[s.i] == '\t') {
		s.i++
	}
}

// comment skips a comment up to (not including) the line end.
func (s *scanner) comment() {
	for !s.eof() && s.b[s.i] != '\n' {
		s.i++
	}
}

// newline consumes one line end ("\n" or "\r\n") if present.
func (s *scanner) newline() bool {
	if s.hasPrefix("\r\n") {
		s.i += 2
	} else if s.peek() == '\n' {
		s.i++
	} else {
		return false
	}
	s.line++
	return true
}

// wsNL skips whitespace, comments and line ends (inside arrays and, as in
// TOML 1.1, inside inline tables).
func (s *scanner) wsNL() {
	for {
		s.ws()
		if s.peek() == '#' {
			s.comment()
		}
		if !s.newline() {
			return
		}
	}
}

func (s *scanner) unit(depth int) bool {
	s.units++
	if depth > MaxKeyDepth {
		return s.fail(fmt.Sprintf("profile nesting exceeds %d levels", MaxKeyDepth))
	}
	if s.units > MaxStructureUnits {
		return s.fail(fmt.Sprintf("profile structure exceeds %d keys and containers", MaxStructureUnits))
	}
	return true
}

// str skips one string starting at the opening quote.
func (s *scanner) str() bool {
	q := s.b[s.i]
	multi := q == '"' && s.hasPrefix(`"""`) || q == '\'' && s.hasPrefix(`'''`)
	if multi {
		s.i += 3
		for !s.eof() {
			c := s.b[s.i]
			switch {
			case c == '\\' && q == '"':
				if s.i+1 < len(s.b) && s.b[s.i+1] == '\n' {
					s.line++
				}
				s.i += 2
				continue
			case c == '\n':
				s.line++
			case c == q && s.hasPrefix(string([]byte{q, q, q})):
				s.i += 3
				for n := 0; n < 2 && s.peek() == q; n++ { // up to two quotes just inside the delimiter
					s.i++
				}
				return true
			}
			s.i++
		}
		return s.malformed()
	}
	s.i++
	for !s.eof() {
		c := s.b[s.i]
		switch {
		case c == '\\' && q == '"':
			s.i += 2
			continue
		case c == '\n':
			return s.malformed()
		case c == q:
			s.i++
			return true
		}
		s.i++
	}
	return s.malformed()
}

func isKeyDelim(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '#', '=', '.', '[', ']', '{', '}', ',', '"', '\'':
		return true
	}
	return false
}

// key skips a (dotted) key below a path of depth base and baseBytes bytes,
// and returns its number of components and the byte length of its path.
func (s *scanner) key(base, baseBytes int) (int, int, bool) {
	n, pathBytes := 0, baseBytes
	for {
		start := s.i
		s.ws()
		switch c := s.peek(); {
		case c == '"' || c == '\'':
			if s.hasPrefix(`"""`) || s.hasPrefix(`'''`) {
				return 0, 0, s.malformed()
			}
			if !s.str() {
				return 0, 0, false
			}
		case !s.eof() && !isKeyDelim(c):
			for !s.eof() && !isKeyDelim(s.b[s.i]) {
				s.i++
			}
		default:
			return 0, 0, s.malformed()
		}
		n++
		pathBytes += s.i - start + 1
		s.bytes += pathBytes
		if s.bytes > MaxKeyPathBytes {
			return 0, 0, s.fail(fmt.Sprintf("profile key paths exceed %d bytes", MaxKeyPathBytes))
		}
		if !s.unit(base + n) {
			return 0, 0, false
		}
		s.ws()
		if s.peek() != '.' {
			return n, pathBytes, true
		}
		s.i++
	}
}

// value skips one value whose key path has depth components and pathBytes bytes.
func (s *scanner) value(depth, pathBytes int) bool {
	s.ws()
	switch c := s.peek(); c {
	case '"', '\'':
		return s.str()
	case '[':
		s.i++
		if !s.unit(depth + 1) {
			return false
		}
		for {
			s.wsNL()
			if s.peek() == ']' {
				s.i++
				return true
			}
			if !s.value(depth+1, pathBytes) {
				return false
			}
			s.wsNL()
			switch s.peek() {
			case ',':
				s.i++
			case ']':
				s.i++
				return true
			default:
				return s.malformed()
			}
		}
	case '{':
		s.i++
		if !s.unit(depth) {
			return false
		}
		for {
			s.wsNL()
			if s.peek() == '}' {
				s.i++
				return true
			}
			if !s.keyval(depth, pathBytes) {
				return false
			}
			s.wsNL()
			switch s.peek() {
			case ',':
				s.i++
			case '}':
				s.i++
				return true
			default:
				return s.malformed()
			}
		}
	default:
		// Number, boolean or date-time (which may contain one space).
		start := s.i
		for !s.eof() {
			switch s.b[s.i] {
			case ',', ']', '}', '#', '\r', '\n', '[', '{', '"', '\'', '=':
				goto done
			}
			s.i++
		}
	done:
		if s.i == start {
			return s.malformed()
		}
		return true
	}
}

func (s *scanner) keyval(base, baseBytes int) bool {
	n, pathBytes, ok := s.key(base, baseBytes)
	if !ok {
		return false
	}
	s.ws()
	if s.peek() != '=' {
		return s.malformed()
	}
	s.i++
	return s.value(base+n, pathBytes)
}

// endOfLine requires optional whitespace and comment, then a line end or EOF.
func (s *scanner) endOfLine() bool {
	s.ws()
	if s.peek() == '#' {
		s.comment()
	}
	if s.eof() || s.newline() {
		return true
	}
	return s.malformed()
}

// checkComplexity runs the K15 pre-scan. It returns nil when the document is
// within the bounds (it may still be rejected by the parser).
func checkComplexity(b []byte) *Error {
	s := &scanner{b: b, line: 1}
	if s.hasPrefix("\xef\xbb\xbf") {
		s.i += 3
	}
	base, baseBytes := 0, 0
	for {
		s.ws()
		if s.eof() {
			return nil
		}
		switch s.peek() {
		case '#':
			s.comment()
		case '\r', '\n':
			if !s.newline() {
				s.malformed()
				return s.err
			}
			continue
		case '[':
			s.i++
			array := s.peek() == '['
			if array {
				s.i++
			}
			n, pathBytes, ok := s.key(0, 0)
			if !ok {
				return s.err
			}
			base, baseBytes = n, pathBytes
			if array {
				base++
			}
			if !s.unit(base) {
				return s.err
			}
			s.ws()
			if s.peek() != ']' {
				s.malformed()
				return s.err
			}
			s.i++
			if array {
				if s.peek() != ']' {
					s.malformed()
					return s.err
				}
				s.i++
			}
		default:
			if !s.keyval(base, baseBytes) {
				return s.err
			}
		}
		if !s.endOfLine() {
			return s.err
		}
	}
}
