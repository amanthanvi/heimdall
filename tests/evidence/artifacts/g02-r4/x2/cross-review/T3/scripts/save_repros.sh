#!/bin/bash
# M00-T05-r4-x2-xrev-T3: save the byte-level repros of the key findings for all nine builds.
# Usage: bash save_repros.sh <bins-dir> <out-dir>
set -u
BINS=$1; OUT=$2; HERE=$(cd "$(dirname "$0")" && pwd)
PY="$HERE/../../../../../../../g02/.venv/bin/python"
ALL="base-go-pinned base-go T3-go-opus1 T3-go-opus2 T3-go-sonnet1 base-rust T3-rust-opus1 T3-rust-opus2 T3-rust-sonnet1"
mkdir -p "$OUT"
while read -r prof size keys name; do
  f="$OUT/$name.txt"
  { echo "# repro_bytes.py $prof $size \"$keys\" (screen and the bytes written for the LAST key; TERM=xterm-256color)"
    "$PY" -I "$HERE/repro_bytes.py" "$BINS" "$prof" "$size" "$keys" $ALL 2>&1 | grep -v '^  *[0-9]* |  *|$'
  } > "$f"
done <<'LIST'
homelab 5x20 /,東,京 R1-homelab-20x5-filter-東京
wide 24x80 /,- R2-wide-80x24-filter-dash
wide 10x40 /,屋,bs R3-wide-40x10-filter-屋-backspace
homelab 24x80 /,京,enter,/ R4-homelab-80x24-reenter-filter-mode
homelab 10x40 /,東,京 R5-homelab-40x10-filter-東京
homelab 24x80 /,東,京 R6-homelab-80x24-filter-東京
LIST
