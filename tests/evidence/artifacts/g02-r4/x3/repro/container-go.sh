#!/bin/sh
set -u
cp -R /src/prototypes/go /work && cd /work && go version && sh build.sh >/out/build.log 2>&1; echo "build.sh rc=$?"
cp dist/manifest.json /out/manifest.json
