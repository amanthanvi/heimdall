# The M08 benchmark and soak container (m08-plan U5a; ADR-0014 section 6). Built once with
# the network (the package install); every run then has none (`--network none`).
# It holds an OpenSSH server and client, Git, Python and two unprivileged lane accounts.
# Nothing here is a Rust toolchain or a compiler: the release archive must run as it is.
FROM debian:13-slim
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends openssh-server openssh-client git python3 procps util-linux \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash soaks && useradd -m -s /bin/bash soakl \
 && mkdir -p /run/sshd
