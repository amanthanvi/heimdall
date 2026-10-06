#!/bin/bash
# unsafe / cgo surface of the Go spike's non-std dependency graph (linux/arm64, compiled files only).
cd "$(dirname "$0")/go" || exit 1
export GOOS=linux GOARCH=arm64
for p in $(CGO_ENABLED=0 go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' .); do
  files=$(go list -f '{{range .GoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}' "$p")
  nf=$(echo "$files" | grep -c .)
  imp=$(echo "$files" | xargs grep -l '"unsafe"' 2>/dev/null | wc -l | tr -d ' ')
  refs=$(echo "$files" | xargs cat | grep -c 'unsafe\.')
  echo "$p compiled_files=$nf files_importing_unsafe=$imp lines_with_unsafe_ref=$refs"
done
echo "std packages with cgo files when CGO_ENABLED=1:"
CGO_ENABLED=1 go list -deps -f '{{if and .Standard .CgoFiles}}  {{.ImportPath}}{{end}}' . | grep .
echo "std pkgs in graph named net / os/user:"; CGO_ENABLED=0 go list -deps . | grep -E '^(net|os/user)$'
