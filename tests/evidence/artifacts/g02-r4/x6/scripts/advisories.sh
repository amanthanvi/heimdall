#!/bin/sh
# Query GitHub global advisory DB. Usage: advisories.sh <outdir> eco:pkg ...
out="$1"; shift; mkdir -p "$out"
for spec in "$@"; do
  eco=${spec%%:*}; pkg=${spec#*:}
  f="$out/${eco}_$(echo "$pkg" | tr '/' '_').json"
  timeout 60 gh api -X GET /advisories -f ecosystem="$eco" -f affects="$pkg" -f per_page=100 > "$f" 2>/dev/null; e=$?
  n=$(jq length "$f" 2>/dev/null)
  echo "== $eco $pkg exit=$e count=$n"
  jq -r '.[]|"\(.published_at[0:10])\t\(.severity)\t\(.ghsa_id)\t\(.cve_id // "-")\t\(.summary[0:100])"' "$f" 2>/dev/null | sort -r | head -16
done
