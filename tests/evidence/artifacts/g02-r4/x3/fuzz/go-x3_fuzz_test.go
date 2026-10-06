package profile

// X3 scratch fuzz target (not part of the frozen prototype). Property: Parse never
// panics, and returns exactly one of (*Profile, *Error).
import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParse(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join(os.Getenv("X3_SEEDS"), "*.toml"))
	for _, s := range seeds {
		b, err := os.ReadFile(s)
		if err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := Parse(b)
		if (p == nil) == (e == nil) {
			t.Fatalf("Parse returned p==nil:%v e==nil:%v", p == nil, e == nil)
		}
	})
}
