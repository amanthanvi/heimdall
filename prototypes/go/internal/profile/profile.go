// Package profile parses and validates G02 fixture profiles
// (docs/g02/slice-contract.md §2). It is shared by the CLI (`profile show`)
// and the TUI. Error messages never contain input values, only key paths.
package profile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"

	"github.com/heimdall-g02/proto-go/internal/result"
)

// MaxBytes is the contract input bound (1 MiB).
const MaxBytes = 1 << 20

// Destination is one validated destination.
type Destination struct {
	ID      string   `json:"id"`
	Alias   string   `json:"alias"`
	Host    string   `json:"host"`
	Port    int64    `json:"port"`
	Account string   `json:"account"`
	Labels  []string `json:"labels"`
}

// Profile is a validated profile. Meta is intentionally not retained.
type Profile struct {
	Name         string        `json:"name"`
	Revision     int64         `json:"revision"`
	Destinations []Destination `json:"destinations"`
}

// Error is a validation/load failure carrying a contract code.
type Error struct {
	Code     string
	KeyPath  *string
	Message  string
	Warnings []string
}

func (e *Error) Error() string {
	if e.KeyPath != nil {
		return fmt.Sprintf("%s: %s: %s", e.Code, *e.KeyPath, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func schemaErr(path string, msg string) *Error {
	p := path
	return &Error{Code: result.SchemaInvalid, KeyPath: &p, Message: msg}
}

var (
	topKeys  = map[string]bool{"schema_version": true, "name": true, "revision": true, "meta": true, "destinations": true}
	destKeys = map[string]bool{"id": true, "alias": true, "host": true, "port": true, "account": true, "labels": true}
)

// Load reads and validates a profile file. Files larger than MaxBytes are
// rejected before parsing; the read itself is bounded too (no trust in stat).
// Anything that is not a regular file (FIFO, socket, device, directory) is a
// usage error and is never read or waited on (K14): the path is checked
// before opening, opened without blocking, and the open descriptor is checked
// again so a swap between the two checks cannot make Load block.
func Load(path string) (*Profile, *Error) {
	notRegular := &Error{Code: result.UsageError, Message: "profile path is not a regular file"}
	st, err := os.Stat(path)
	if err != nil {
		return nil, &Error{Code: result.UsageError, Message: "profile file cannot be opened"}
	}
	if !st.Mode().IsRegular() {
		return nil, notRegular
	}
	f, err := openNoBlock(path)
	if err != nil {
		return nil, &Error{Code: result.UsageError, Message: "profile file cannot be opened"}
	}
	defer f.Close()
	fst, err := f.Stat()
	if err != nil || !fst.Mode().IsRegular() || !os.SameFile(st, fst) {
		return nil, notRegular
	}
	if fst.Size() > MaxBytes {
		return nil, &Error{Code: result.InputTooLarge, Message: "profile file exceeds 1048576 bytes"}
	}
	buf, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return nil, &Error{Code: result.UsageError, Message: "profile file cannot be read"}
	}
	if len(buf) > MaxBytes {
		return nil, &Error{Code: result.InputTooLarge, Message: "profile file exceeds 1048576 bytes"}
	}
	return Parse(buf)
}

// Parse validates TOML bytes against the contract §2 rules.
func Parse(buf []byte) (*Profile, *Error) {
	// K15: bound the parser's resources before it sees the input.
	if err := checkComplexity(buf); err != nil {
		return nil, err
	}
	var raw map[string]any
	if _, err := toml.Decode(string(buf), &raw); err != nil {
		// Never echo the parser message: it can quote input text.
		msg := "malformed TOML"
		var pe toml.ParseError
		if errors.As(err, &pe) {
			msg = fmt.Sprintf("malformed TOML near line %d", pe.Position.Line)
		}
		return nil, &Error{Code: result.SchemaInvalid, Message: msg}
	}

	// schema_version first: an unsupported major version is rejected
	// explicitly before any other rule (spec §11.2).
	sv, ok := raw["schema_version"]
	if !ok {
		return nil, schemaErr("schema_version", "required key is missing")
	}
	if n, isInt := sv.(int64); !isInt || n != 1 {
		e := schemaErr("schema_version", "unsupported schema_version")
		if isInt {
			e.Warnings = []string{fmt.Sprintf("unsupported profile schema_version %d (supported: 1)", n)}
		} else {
			e.Warnings = []string{"unsupported profile schema_version (not an integer; supported: 1)"}
		}
		return nil, e
	}

	for _, k := range sortedKeys(raw) {
		if !topKeys[k] {
			return nil, schemaErr(keyName(k), "unknown key")
		}
	}

	p := &Profile{Destinations: []Destination{}}
	var err *Error
	if p.Name, err = reqString(raw, "name", "name"); err != nil {
		return nil, err
	}
	rv, ok := raw["revision"]
	if !ok {
		return nil, schemaErr("revision", "required key is missing")
	}
	if n, isInt := rv.(int64); !isInt || n < 1 {
		return nil, schemaErr("revision", "must be an integer >= 1")
	} else {
		p.Revision = n
	}
	if m, ok := raw["meta"]; ok {
		if _, isTable := m.(map[string]any); !isTable {
			return nil, schemaErr("meta", "must be a table")
		}
	}

	if d, ok := raw["destinations"]; ok {
		tables, ok := asTables(d)
		if !ok {
			return nil, schemaErr("destinations", "must be an array of tables")
		}
		seenID := map[string]bool{}
		seenAlias := map[string]bool{}
		for i, t := range tables {
			base := fmt.Sprintf("destinations[%d]", i)
			for _, k := range sortedKeys(t) {
				if !destKeys[k] {
					return nil, schemaErr(base+"."+keyName(k), "unknown key")
				}
			}
			var dst Destination
			if dst.ID, err = reqString(t, "id", base+".id"); err != nil {
				return nil, err
			}
			if dst.Alias, err = reqString(t, "alias", base+".alias"); err != nil {
				return nil, err
			}
			if dst.Host, err = reqString(t, "host", base+".host"); err != nil {
				return nil, err
			}
			if dst.Account, err = reqString(t, "account", base+".account"); err != nil {
				return nil, err
			}
			dst.Port = 22
			if pv, ok := t["port"]; ok {
				n, isInt := pv.(int64)
				if !isInt || n < 1 || n > 65535 {
					return nil, schemaErr(base+".port", "must be an integer in 1..65535")
				}
				dst.Port = n
			}
			dst.Labels = []string{}
			if lv, ok := t["labels"]; ok {
				arr, ok := lv.([]any)
				if !ok {
					return nil, schemaErr(base+".labels", "must be an array of strings")
				}
				for j, l := range arr {
					s, ok := l.(string)
					if !ok {
						return nil, schemaErr(fmt.Sprintf("%s.labels[%d]", base, j), "must be a string")
					}
					if hasControl(s) {
						return nil, controlErr(fmt.Sprintf("%s.labels[%d]", base, j))
					}
					dst.Labels = append(dst.Labels, s)
				}
			}
			if seenID[dst.ID] {
				return nil, schemaErr(base+".id", "duplicate id")
			}
			if seenAlias[dst.Alias] {
				return nil, schemaErr(base+".alias", "duplicate alias")
			}
			seenID[dst.ID], seenAlias[dst.Alias] = true, true
			p.Destinations = append(p.Destinations, dst)
		}
	}
	return p, nil
}

func reqString(m map[string]any, key, path string) (string, *Error) {
	v, ok := m[key]
	if !ok {
		return "", schemaErr(path, "required key is missing")
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", schemaErr(path, "must be a non-empty string")
	}
	if hasControl(s) {
		return "", controlErr(path)
	}
	return s, nil
}

// hasControl reports a C0 (including TAB), DEL or C1 control code point
// (K2, docs/g02/slice-contract.md §9). unicode.IsControl is exactly
// U+0000-U+001F and U+007F-U+009F.
func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// controlErr never includes the value (K2): only the key path.
func controlErr(path string) *Error {
	return schemaErr(path, "string value contains a control character")
}

func asTables(v any) ([]map[string]any, bool) {
	switch t := v.(type) {
	case []map[string]any:
		return t, true
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, e := range t {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, m)
		}
		return out, true
	}
	return nil, false
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// keyName renders a key for a key path, replacing control characters so a
// crafted quoted key cannot inject terminal escapes into diagnostics.
func keyName(k string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, k)
}

// Filter returns indexes of destinations whose alias or host contains query
// (case-insensitive substring). Pure function, no I/O; used by the TUI (the
// slice's CLI has no filter command).
func Filter(ds []Destination, query string) []int {
	q := strings.ToLower(query)
	out := make([]int, 0, len(ds))
	for i, d := range ds {
		if q == "" || strings.Contains(strings.ToLower(d.Alias), q) || strings.Contains(strings.ToLower(d.Host), q) {
			out = append(out, i)
		}
	}
	return out
}
