# G02 harness runner image (tests/g02/linux/run.sh).  Build context: tests/g02 (only requirements.txt is
# sent, see Dockerfile.dockerignore).  linux/arm64 only: K13 needs a native arm64 kernel, not emulation.
#
# Base pinned by the multi-arch index digest of python:3.13-slim-bookworm (resolved 2026-10-03; the
# linux/arm64 manifest is Debian 12 bookworm + CPython 3.13.16).  Debian packages are pinned by version
# (signature-verified by apt); their dependencies follow bookworm.  If a pin disappears from the mirror
# after a point release, update it and record the new image id (run.sh records it in every record).
FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed

ARG OPENSSH_CLIENT_VERSION=1:9.2p1-2+deb12u10
ARG LOCALES_VERSION=2.36-9+deb12u14
ARG ZSH_VERSION=5.9-4+b15

LABEL org.heimdall.purpose="g02-harness-runner" \
      org.heimdall.base="python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed"

# ssh-keygen (disposable fingerprints) and /usr/bin/ssh -V (version record); the en_US.UTF-8 locale the
# harness sets in LANG/LC_ALL for every binary under test; zsh for the K6e job-control forms under zsh
# (round 3; /bin/zsh, recorded as a non-gating observation).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        "openssh-client=${OPENSSH_CLIENT_VERSION}" "locales=${LOCALES_VERSION}" "zsh=${ZSH_VERSION}" \
 && sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
 && locale-gen \
 && rm -rf /var/lib/apt/lists/*

# pyte + wcwidth for the TUI checks, hash-pinned (both pure-Python wheels).
COPY requirements.txt /opt/g02/requirements.txt
RUN python3 -m pip install --no-cache-dir --no-deps --require-hashes -r /opt/g02/requirements.txt

# Non-root: the harness's unreadable-file check and the "no privileges" boundary need it.
RUN useradd --create-home --uid 10001 --user-group g02
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 HOME=/home/g02
WORKDIR /home/g02
