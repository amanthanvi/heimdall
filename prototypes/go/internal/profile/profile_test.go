package profile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heimdall-g02/proto-go/internal/result"
	"github.com/heimdall-g02/proto-go/internal/testfix"
)

func TestFixtures(t *testing.T) {
	fixtures := testfix.Dir(t)
	cases := []struct {
		file    string
		code    string
		n       int
		keyPath string
	}{
		{"homelab.toml", "", 3, ""},
		{"large-100.toml", "", 100, ""},
		{"spaced dir ü/prøfile homelab.toml", "", 3, ""},
		{"invalid-forbidden-key.toml", result.SchemaInvalid, 0, "private_key"},
		{"invalid-unknown-dest-key.toml", result.SchemaInvalid, 0, "destinations[0].identity_file"},
		{"invalid-malformed.toml", result.SchemaInvalid, 0, ""},
		{"invalid-schema-version.toml", result.SchemaInvalid, 0, "schema_version"},
		{"invalid-duplicate-alias.toml", result.SchemaInvalid, 0, "destinations[1].alias"},
		{"invalid-port.toml", result.SchemaInvalid, 0, "destinations[0].port"},
	}
	// Every fixture in the directory must be covered.
	ents, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, c := range cases {
		covered[strings.SplitN(c.file, "/", 2)[0]] = true
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".toml") || e.IsDir() {
			if !covered[e.Name()] {
				t.Errorf("fixture %q not covered", e.Name())
			}
		}
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			raw, _ := os.ReadFile(filepath.Join(fixtures, c.file))
			p, perr := Load(filepath.Join(fixtures, c.file))
			if c.code == "" {
				if perr != nil {
					t.Fatalf("unexpected error %v", perr)
				}
				if len(p.Destinations) != c.n {
					t.Fatalf("got %d destinations want %d", len(p.Destinations), c.n)
				}
				return
			}
			if perr == nil || perr.Code != c.code {
				t.Fatalf("got %v want %s", perr, c.code)
			}
			if c.keyPath != "" && (perr.KeyPath == nil || *perr.KeyPath != c.keyPath) {
				t.Fatalf("key path %v want %s", perr.KeyPath, c.keyPath)
			}
			var buf bytes.Buffer
			_ = result.Write(&buf, result.Fail(perr.Code, perr.KeyPath, perr.Message, perr.Warnings...))
			buf.WriteString(perr.Error())
			if strings.Contains(buf.String(), "HEIMDALL_CANARY_") {
				t.Fatalf("canary leaked: %s", buf.String())
			}
			_ = raw
		})
	}
}

func TestHomelabValues(t *testing.T) {
	p, perr := Load(filepath.Join(testfix.Dir(t), "homelab.toml"))
	if perr != nil {
		t.Fatal(perr)
	}
	if p.Name != "homelab" || p.Revision != 3 {
		t.Fatal("name/revision")
	}
	d := p.Destinations
	if d[0].Alias != "lab-server" || d[1].Alias != "nas" || d[2].Alias != "vps-東京" {
		t.Fatal("order not preserved")
	}
	if d[1].Port != 22 || d[2].Port != 2222 || len(d[2].Labels) != 0 || d[2].Labels == nil {
		t.Fatal("defaults")
	}
}

func TestOversize(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "over size ü.toml")
	if err := os.WriteFile(f, bytes.Repeat([]byte("#"), MaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, perr := Load(f); perr == nil || perr.Code != result.InputTooLarge {
		t.Fatalf("got %v", perr)
	}
	exact := filepath.Join(dir, "exact.toml")
	body := append([]byte("schema_version = 1\nname = \"x\"\nrevision = 1\n"), bytes.Repeat([]byte("#"), 0)...)
	body = append(body, bytes.Repeat([]byte(" "), MaxBytes-len(body))...)
	_ = os.WriteFile(exact, body, 0o600)
	if _, perr := Load(exact); perr != nil {
		t.Fatalf("exactly 1 MiB rejected: %v", perr)
	}
}

func TestMissingFile(t *testing.T) {
	if _, perr := Load(filepath.Join(t.TempDir(), "nope.toml")); perr == nil || perr.Code != result.UsageError {
		t.Fatalf("got %v", perr)
	}
}

func TestMoreSchemaRules(t *testing.T) {
	cases := map[string]string{
		"missing revision":   "schema_version = 1\nname = \"x\"\n",
		"revision zero":      "schema_version = 1\nname = \"x\"\nrevision = 0\n",
		"schema string":      "schema_version = \"1\"\nname = \"x\"\nrevision = 1\n",
		"dup id":             "schema_version = 1\nname = \"x\"\nrevision = 1\n[[destinations]]\nid=\"a\"\nalias=\"a\"\nhost=\"h\"\naccount=\"u\"\n[[destinations]]\nid=\"a\"\nalias=\"b\"\nhost=\"h\"\naccount=\"u\"\n",
		"missing host":       "schema_version = 1\nname = \"x\"\nrevision = 1\n[[destinations]]\nid=\"a\"\nalias=\"a\"\naccount=\"u\"\n",
		"port zero":          "schema_version = 1\nname = \"x\"\nrevision = 1\n[[destinations]]\nid=\"a\"\nalias=\"a\"\nhost=\"h\"\naccount=\"u\"\nport=0\n",
		"nested unknown key": "schema_version = 1\nname = \"x\"\nrevision = 1\n[extra]\nsecret=\"HEIMDALL_CANARY_x\"\n",
	}
	for name, src := range cases {
		if _, perr := Parse([]byte(src)); perr == nil || perr.Code != result.SchemaInvalid {
			t.Errorf("%s: got %v", name, perr)
		} else if strings.Contains(perr.Error(), "HEIMDALL_CANARY_") {
			t.Errorf("%s: canary in error", name)
		}
	}
	// meta content is tolerated, including keys that would be forbidden elsewhere.
	ok := "schema_version = 1\nname = \"x\"\nrevision = 1\n[meta]\nprivate_key = \"whatever\"\n"
	if _, perr := Parse([]byte(ok)); perr != nil {
		t.Fatalf("meta rejected: %v", perr)
	}
}

func TestFilter(t *testing.T) {
	ds := []Destination{{Alias: "Lab-Server", Host: "lab.example"}, {Alias: "nas", Host: "NAS.example"}, {Alias: "vps-東京", Host: "x"}}
	if got := Filter(ds, "LAB"); len(got) != 1 || got[0] != 0 {
		t.Fatal(got)
	}
	if got := Filter(ds, "nas.EX"); len(got) != 1 || got[0] != 1 {
		t.Fatal(got)
	}
	if got := Filter(ds, "東京"); len(got) != 1 || got[0] != 2 {
		t.Fatal(got)
	}
	if got := Filter(ds, ""); len(got) != 3 {
		t.Fatal(got)
	}
}

// K2 (slice-contract §9): a string value outside [meta] containing a C0
// (including TAB), DEL or C1 control code point is SCHEMA_INVALID; key_path
// names the key and the message never contains the value. [meta] content is
// still tolerated.
func TestK2ControlCharactersInValues(t *testing.T) {
	const head = "schema_version = 1\nrevision = 1\n"
	dest := func(field, val string) string {
		d := map[string]string{"id": `"d1"`, "alias": `"a1"`, "host": `"h1"`, "account": `"u1"`}
		d[field] = val
		return "name = \"x\"\n[[destinations]]\nid = " + d["id"] + "\nalias = " + d["alias"] +
			"\nhost = " + d["host"] + "\naccount = " + d["account"] + "\n"
	}
	// TOML escapes decode to the control code point; a raw TAB is valid TOML.
	ctrls := []string{`\u0000`, `\u001b`, `\t`, "\t", `\u007f`, `\u0080`, `\u009b`, `\u009f`, `\u001f`}
	for _, c := range ctrls {
		val := `"HEIMDALL_CANARY_v` + c + `x"`
		cases := map[string]string{
			"name":                      head + "name = " + val + "\n",
			"destinations[0].id":        head + dest("id", val),
			"destinations[0].alias":     head + dest("alias", val),
			"destinations[0].host":      head + dest("host", val),
			"destinations[0].account":   head + dest("account", val),
			"destinations[0].labels[1]": head + dest("id", `"d1"`) + "labels = [\"ok\", " + val + "]\n",
		}
		for want, src := range cases {
			_, perr := Parse([]byte(src))
			if perr == nil || perr.Code != result.SchemaInvalid {
				t.Errorf("%q %s: got %v", c, want, perr)
				continue
			}
			if perr.KeyPath == nil || *perr.KeyPath != want {
				t.Errorf("%q: key_path %v want %s", c, perr.KeyPath, want)
			}
			var buf bytes.Buffer
			_ = result.Write(&buf, result.Fail(perr.Code, perr.KeyPath, perr.Message, perr.Warnings...))
			if strings.Contains(buf.String()+perr.Error(), "HEIMDALL_CANARY_") {
				t.Errorf("%q %s: value echoed: %s", c, want, buf.String())
			}
		}
	}
	// Non-control non-ASCII is still fine; [meta] content is still tolerated.
	ok := head + "name = \"東京 \\u00a0x\"\n[meta]\nnote = \"a\\u001bb\\tc\\u009b\"\n"
	if _, perr := Parse([]byte(ok)); perr != nil {
		t.Fatalf("unexpected: %v", perr)
	}
}
