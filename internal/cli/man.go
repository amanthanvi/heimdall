package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra/doc"
)

func GenerateManPages(outDir string, build BuildInfo) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create man output directory: %w", err)
	}

	root := NewRootCommand(io.Discard, build)
	header := &doc.GenManHeader{
		Title:   "HEIMDALL",
		Section: "1",
		Source:  "Heimdall",
		Manual:  "Heimdall Manual",
	}

	if err := doc.GenManTree(root, header, outDir); err != nil {
		return fmt.Errorf("generate man pages: %w", err)
	}

	return nil
}
