# Heimdall M00-T03 disposable sshd fixture image (one image, role chosen at start).
# Base pinned by digest (Debian trixie, multi-arch index digest, verified by `docker pull` of the digest).
FROM debian@sha256:f324c7ff54321e8d9c588493a20244965938ce0aa50bbd1022d38010e9ffc4b1
LABEL heimdall.fixture="m00-t03"
# openssh-server version floats with the Debian archive at build time; the version
# actually installed is recorded by up.sh / smoke.sh (not pinned: see tests/fixtures/MANIFEST.md).
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /fixture \
 && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
COPY entrypoint.sh /usr/local/bin/fixture-entrypoint.sh
RUN chmod 0755 /usr/local/bin/fixture-entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/fixture-entrypoint.sh"]
