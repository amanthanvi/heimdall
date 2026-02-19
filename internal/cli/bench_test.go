package cli

import (
	"bytes"
	"testing"
)

func BenchmarkCLIRoundTrip(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		cmd := NewRootCommand(&out, BuildInfo{Version: "bench", Commit: "bench", BuildTime: "bench"})
		cmd.SetArgs([]string{"version"})
		if err := cmd.Execute(); err != nil {
			b.Fatalf("execute version command: %v", err)
		}
	}
}
