#!/bin/sh
# Per linked non-std package for a GOOS/GOARCH: files compiled, imports unsafe?, count of
# "unsafe." tokens in compiled Go files, assembly files, cgo files (CGO_ENABLED as given).
cd /tmp/hm-r4/M00-T05-r4-x3/go/prototypes/go
os=$1 ar=$2 cgo=$3
CGO_ENABLED=$cgo GOOS=$os GOARCH=$ar GOFLAGS=-mod=readonly GOTOOLCHAIN=local go list -deps -f '{{if not .Standard}}{{.ImportPath}}|{{.Dir}}|{{join .GoFiles ","}}|{{join .SFiles ","}}|{{join .CgoFiles ","}}|{{range .Imports}}{{if eq . "unsafe"}}U{{end}}{{end}}|{{with .Module}}{{.Path}}{{end}}{{end}}' ./cmd/heimdall-proto | grep -v '^$' |
while IFS='|' read ip dir gofiles sfiles cgofiles u mod; do
  n=0; for f in $(echo "$gofiles,$cgofiles" | tr ',' ' '); do c=$(grep -o 'unsafe\.' "$dir/$f" | wc -l); n=$((n + c)); done
  ns=$(echo "$sfiles" | tr ',' '\n' | grep -c .); nc=$(echo "$cgofiles" | tr ',' '\n' | grep -c .)
  printf '%s\t%s\timports_unsafe=%s\tunsafe_tokens=%s\tasm_files=%s\tcgo_files=%s\n' "$mod" "$ip" "${u:+yes}" "$n" "$ns" "$nc"
done
