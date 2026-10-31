#!/bin/bash
# X1c WSL setup: unpack the staged harness archive, verify input hashes, create the harness venv.
# Run from the scratch directory after `scp stage.tar` (layout: harness.tar, art/<c>/heimdall-proto, inputs.sha256).
set -u
T=$HOME/hm-m00/M00-T05-r5-x1c
cd "$T" || exit 1
tar xf stage.tar; echo "tar stage rc=$?"
sha256sum -c inputs.sha256; echo "sha256sum -c rc=$?"
mkdir -p repo && tar xf harness.tar -C repo; echo "tar harness rc=$?"
python3 -m venv repo/tests/g02/.venv; echo "venv rc=$?"
repo/tests/g02/.venv/bin/pip install --disable-pip-version-check --no-input --require-hashes -r repo/tests/g02/requirements.txt > pip.log 2>&1; echo "pip rc=$?"
repo/tests/g02/.venv/bin/python -c 'import importlib.metadata as m, sys; print("python", sys.version.split()[0], "pyte", m.version("pyte"), "wcwidth", m.version("wcwidth"))'
for c in go rust; do echo "$c: $(file -b art/$c/heimdall-proto) | ldd: $(ldd art/$c/heimdall-proto 2>&1 | head -1 | sed 's/^[[:space:]]*//')"; done
