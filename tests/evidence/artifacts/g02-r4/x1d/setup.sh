#!/bin/bash
# X1d setup: unpack the staged harness archive, verify input hashes, create the harness venv.
# Run from the scratch directory after `scp stage.tar` (layout: harness.tar, art/<c>/heimdall-proto, wheels/,
# inputs.sha256, scripts). Derived from ../x1c/setup.sh; adds the fallback for a host whose python3 -m venv cannot
# install pip (ensurepip missing): venv --without-pip plus wheel-install.py (hash-checked extraction of the two
# pinned wheels, staged from the Mac in wheels/). Nothing is installed outside the scratch directory.
set -u
T=$HOME/hm-m00/M00-T05-r5-x1d
cd "$T" || exit 1
tar xf stage.tar; echo "tar stage rc=$?"
sha256sum -c inputs.sha256; echo "sha256sum -c rc=$?"
mkdir -p repo && tar xf harness.tar -C repo; echo "tar harness rc=$?"
V=repo/tests/g02/.venv
python3 -m venv "$V" > venv.log 2>&1; rc=$?; echo "python3 -m venv rc=$rc"
if [ "$rc" -eq 0 ]; then
  echo "venv method: python3 -m venv + pip install --require-hashes (as X1c)"
  "$V/bin/pip" install --disable-pip-version-check --no-input --require-hashes -r repo/tests/g02/requirements.txt > pip.log 2>&1; echo "pip rc=$?"
else
  echo "python3 -m venv output (last 4 lines):"; tail -4 venv.log | sed "s#$HOME#<home>#g; s/^/  /"
  rm -rf "$V"
  echo "venv method: python3 -m venv --without-pip + wheel-install.py (hash-checked extraction, no pip)"
  python3 -m venv --without-pip "$V"; echo "python3 -m venv --without-pip rc=$?"
  "$V/bin/python" -I wheel-install.py repo/tests/g02/requirements.txt wheels > pip.log 2>&1; echo "wheel-install rc=$?"
  sed 's/^/  /' pip.log
fi
"$V/bin/python" -c 'import importlib.metadata as m, sys; print("python", sys.version.split()[0], "pyte", m.version("pyte"), "wcwidth", m.version("wcwidth"))'
"$V/bin/python" -c 'import pyte, wcwidth; print("import pyte, wcwidth: ok")'
for c in go rust; do echo "$c: $(file -b art/$c/heimdall-proto) | ldd: $(ldd art/$c/heimdall-proto 2>&1 | head -1 | sed 's/^[[:space:]]*//')"; done
