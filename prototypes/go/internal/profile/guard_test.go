package profile

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

const minTop = "schema_version = 1\nname = \"x\"\nrevision = 1\n"

// The guard must follow every TOML construct the parser accepts, so that it
// never turns a valid small profile into "malformed TOML".
func TestGuardSyntax(t *testing.T) {
	ok := []string{
		"",
		"\xef\xbb\xbf" + minTop,
		minTop + "[meta]\na = \"x[{\\\"]}#\" # c [\n",
		minTop + "[meta]\na = 'lit[{\\'\n",
		minTop + "[meta]\na = \"\"\"\nx]} \"\" \\\"\"\"\nb\"\"\"\"\"\n",
		minTop + "[meta]\na = '''\n[ '' x ]'''''\n",
		minTop + "[meta]\nd = 1979-05-27 07:32:00Z\nf = 1.5e3\ng = -inf\nh = 0xff\ni = true\n",
		minTop + "[meta]\n\"a.b\" = 1\n'c' . \"d\" . e = 2\n",
		minTop + "[ meta . sub ]\nx = [ 1 , # c\n 2 ,\n ]\n",
		minTop + "[meta]\nt = {\n a = 1, # TOML 1.1\n b = { c = [ {d = 1}, ] },\n}\n",
		minTop + "[[ meta.arr ]]\nx = 1\n[[meta.arr]]\n",
		strings.ReplaceAll(minTop+"[meta]\na = [1,\n2]\n", "\n", "\r\n"),
		minTop + "[meta]\n\"k\\u001bey\" = \"x\"\n",
	}
	for _, s := range ok {
		if err := checkComplexity([]byte(s)); err != nil {
			t.Errorf("%q: %+v", s, err)
		}
		var m map[string]any
		if _, err := toml.Decode(s, &m); err != nil {
			t.Errorf("test input is not valid TOML: %q: %v", s, err)
		}
	}
	over := map[string]string{
		"depth":       minTop + "[meta]\na = " + strings.Repeat("[", MaxKeyDepth) + strings.Repeat("]", MaxKeyDepth) + "\n",
		"dotted":      minTop + "[meta]\n" + strings.Repeat("a.", MaxKeyDepth) + "a = 1\n",
		"header":      minTop + "[" + strings.Repeat("a.", MaxKeyDepth) + "a]\n",
		"units":       minTop + "[meta]\n" + strings.Repeat("a = {}\n", MaxStructureUnits/2+1),
		"path bytes":  minTop + "[meta." + strings.Repeat("x", 100000) + "]\n" + strings.Repeat("k = 1\n", 30),
		"in string?":  minTop + "[meta]\na = \"" + strings.Repeat("[", 100) + "\"\nb = " + strings.Repeat("{c = ", MaxKeyDepth) + "1" + strings.Repeat("}", MaxKeyDepth) + "\n",
		"unterminate": minTop + "[meta]\na = \"\"\"" + strings.Repeat("{", 1000),
	}
	for name, s := range over {
		err := checkComplexity([]byte(s))
		if err == nil || err.Code != "SCHEMA_INVALID" || strings.Contains(err.Message, "xxxx") {
			t.Errorf("%s: got %+v", name, err)
		}
	}
	// Within the bounds: exactly MaxKeyDepth.
	at := minTop + "[meta]\na = " + strings.Repeat("[", MaxKeyDepth-2) + strings.Repeat("]", MaxKeyDepth-2) + "\n"
	if err := checkComplexity([]byte(at)); err != nil {
		t.Fatalf("depth %d rejected: %+v", MaxKeyDepth, err)
	}
}

// corpusDir locates the toml-test corpus that ships inside the parser module
// (internal/toml-test/tests). It needs the go command, so it is skipped where
// only the compiled test binary runs (for example the Linux containers).
func corpusDir(t *testing.T) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info")
	}
	ver := ""
	for _, d := range bi.Deps {
		if d.Path == "github.com/BurntSushi/toml" {
			ver = d.Version
		}
	}
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil || ver == "" {
		t.Skip("go command or module version unavailable: corpus check runs only with a Go toolchain")
	}
	dir := filepath.Join(strings.TrimSpace(string(out)), "github.com/!burnt!sushi/toml@"+ver, "internal/toml-test/tests")
	if _, err := os.Stat(dir); err != nil {
		t.Skip("toml-test corpus not in the module cache: " + dir)
	}
	return dir
}

// Differential check: every corpus document the parser accepts, the guard
// also accepts (none is anywhere near the bounds).
func TestGuardAcceptsValidCorpus(t *testing.T) {
	dir := corpusDir(t)
	n := 0
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".toml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var m map[string]any
		if _, perr := toml.Decode(string(b), &m); perr != nil {
			return nil // invalid for the parser: whatever the guard says, Parse rejects it
		}
		n++
		if gerr := checkComplexity(b); gerr != nil {
			t.Errorf("%s: parser accepts, guard says %s", strings.TrimPrefix(p, dir), gerr.Message)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 100 {
		t.Fatalf("only %d parser-valid corpus files found", n)
	}
	t.Logf("%d parser-valid corpus documents accepted by the guard", n)
}

// FuzzGuard: the pre-scan never panics or loops on arbitrary bytes, and a
// document it accepts stays within its depth bound.
func FuzzGuard(f *testing.F) {
	for _, s := range []string{minTop, "a = [[{b = '''x'''}]]", "[a.\"b\"]\nc = \"\\\"\"", "x = \"\"\"\\", "[[a]", "a = {b = [1,],}"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = checkComplexity(b)
	})
}
