# The M08 benchmark and soak container (m08-plan U5a; ADR-0014 section 6). Built once with
# the network (the package install); every run then has none (`--network none`).
# It holds an OpenSSH server and client, Git, Python and two unprivileged lane accounts.
# Nothing here is a Rust toolchain or a compiler: the release archive must run as it is.
# The base is pinned by its index digest (2026-11-24). The image built before the pin,
# hm-m08-soak:1 (image ID sha256:880a9260…, created 2026-11-22), was built from the
# then-current debian:13-slim, whose digest was not recorded; a rebuild from this file gives a
# new image ID, which a run's record states.
FROM debian@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends openssh-server openssh-client git python3 procps util-linux \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash soaks && useradd -m -s /bin/bash soakl \
 && mkdir -p /run/sshd
