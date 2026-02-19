package debug

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteBundleWritesJSONFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "bundle.json")
	bundle := NewBundle()
	bundle.Version = map[string]any{"version": "1.2.3"}
	bundle.Daemon = map[string]any{"running": true}

	require.NoError(t, WriteBundle(path, bundle))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var decoded Bundle
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Equal(t, bundle.GOOS, decoded.GOOS)
	require.Equal(t, "1.2.3", decoded.Version["version"])
}

func TestWriteBundleRequiresOutputPath(t *testing.T) {
	t.Parallel()

	err := WriteBundle("", NewBundle())
	require.Error(t, err)
	require.Contains(t, err.Error(), "output path is required")
}
