#!/bin/sh
# Query crates.io and proxy.golang.org for latest version/date. Usage: registry_meta.sh <outdir>
out="$1"; mkdir -p "$out"
UA="heimdall-m00-x6-research (contact: none; read-only)"
printf 'registry\tname\tlatest\tupdated_or_time\tdownloads_total\tdownloads_recent_90d\n'
for c in russh russh-keys ssh-key ssh-encoding ssh-agent-lib ssh-agent-client-rs thrussh thrussh-keys openssh ssh2 crossterm ratatui rustls age sequoia-openpgp signal-hook nix rustix sigstore cargo-audit cargo-deny cargo-fuzz libfuzzer-sys cargo-auditable cargo-vet; do
  curl -sS -A "$UA" "https://crates.io/api/v1/crates/$c" > "$out/crate_$c.json"; e=$?
  if [ $e -ne 0 ] || ! jq -e .crate "$out/crate_$c.json" >/dev/null 2>&1; then printf 'crates.io\t%s\tERROR(curl %s)\n' "$c" "$e"; sleep 1; continue; fi
  jq -r --arg c "$c" '["crates.io",$c,(.crate.max_stable_version // .crate.max_version),.crate.updated_at,(.crate.downloads|tostring),(.crate.recent_downloads|tostring)]|@tsv' "$out/crate_$c.json"
  sleep 1
done
for m in golang.org/x/crypto github.com/gliderlabs/ssh filippo.io/age charm.land/bubbletea/v2 charm.land/wish/v2 github.com/charmbracelet/wish github.com/sigstore/cosign/v3 github.com/foxboron/ssh-tpm-agent golang.org/x/vuln github.com/Microsoft/go-winio golang.org/x/sys; do
  curl -sS "https://proxy.golang.org/$(echo "$m" | sed 's/[A-Z]/!&/g' | tr 'A-Z' 'a-z')/@latest" > "$out/go_$(echo $m | tr '/' '_').json"; e=$?
  if [ $e -ne 0 ] || ! jq -e .Version "$out/go_$(echo $m | tr '/' '_').json" >/dev/null 2>&1; then printf 'proxy.golang.org\t%s\tERROR(curl %s or not found)\n' "$m" "$e"; continue; fi
  jq -r --arg m "$m" '["proxy.golang.org",$m,.Version,.Time,"-","-"]|@tsv' "$out/go_$(echo $m | tr '/' '_').json"
done
