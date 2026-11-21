# SSH access by platform

Start with the SSH identity you already use. If you can enroll the remote
account, managed access is another option. It uses a short-lived SSH certificate
with a key that Heimdall manages. A jump host is a way to reach a machine. It
doesn't grant access to the machine on its own.

The support label comes from the [compatibility matrix](../compatibility/matrix.md).
`not-tested` is the product label even when a specific setup has **verified**
test results. **Blocked** means a test still needs the input named below.

## Existing access

| Setup | Support label | What was tested and what is still open | Matrix rows |
|---|---|---|---|
| OpenSSH agent on macOS arm64 | not-tested | **Verified** with a disposable agent, system OpenSSH, Git, `scp` and `sftp`. Ordinary SSH using the account's own configuration is **blocked** on a disposable macOS account. | M02-1, M02-2, M02-3, M02-4, M02-17 |
| OpenSSH agent on Linux x86-64 | not-tested | **Verified** with a disposable agent, OpenSSH, Git, `scp` and `sftp` on a headless Linux host. | M02-5, M02-6, M02-7, M02-8 |
| OpenSSH agent on Linux arm64 | not-tested | **Blocked** on a native Linux arm64 host. | M02-20 |
| OpenSSH agent on Windows x86-64 | not-tested | **Verified** with a test agent and the Windows inbox OpenSSH tools. The system agent is **blocked** on a disposable Windows host whose agent can hold test keys. Ordinary SSH using the account's own configuration needs a disposable second account. Git transport used the inbox client explicitly. Git's bundled MSYS SSH can't use the Windows agent pipe in the recorded tests. | 16, M02-9, M02-10, M02-11, M02-12, M02-13, M02-18 |
| OpenSSH agent inside WSL2 | not-tested | **Verified** with a disposable Ubuntu distribution and its own Linux agent and OpenSSH tools. | M02-19 |
| 1Password on macOS arm64, Linux x86-64 or Windows x86-64 | not-tested | **Blocked** on an authorized disposable 1Password account and vault with test keys. The Windows coexistence test also needs a disposable Windows host. | M02-14, M02-15, M02-16 |
| 1Password on Linux arm64 | not-tested | **Blocked** on native Linux arm64 and a disposable 1Password account and vault with test keys. | 5, M02-20 |

With existing access, the agent still decides when it will sign. If 1Password
requires an unlock or approval, you must provide it. The managed-certificate
guarantees below apply to Heimdall's own signer.

## Managed certificates

| Setup | Support label | What was tested and what is still open | Matrix rows |
|---|---|---|---|
| Native macOS arm64 | not-tested | **Verified** enrollment, new logins and expiry with a test build. Lock tests used a test store. Testing the real login keychain is **blocked** on a disposable macOS account. | M03-1, M03-6, M03-8 |
| Native Linux x86-64 | not-tested | **Verified** enrollment, new logins and expiry on a headless host. Testing desktop lock and key storage is **blocked** on a Linux desktop with Secret Service and a disposable account. | M03-3, M03-9 |
| Native Linux arm64 | not-tested | **Blocked** on a native Linux arm64 host. | 6, M05-5 |
| Native Windows x86-64 | not-tested | **Verified** enrollment, new logins and strict expiry with the inbox OpenSSH client. Testing the Windows protected key store across lock and signer restart is **blocked** on a disposable second Windows account. | M03-4, M03-7 |
| Managed access inside WSL2 | not-tested | **Verified** enrollment and ordinary SSH tools in a disposable Ubuntu distribution. The test set up the signing key in advance. | M03-5 |

### What Heimdall can report for managed certificates

These results apply to managed certificates through a native endpoint, where
OpenSSH talks directly to Heimdall. The OS column gives the minimum release for
each claim. Linux also needs the listed kernel flavor. The evidence comes from
debug test builds. Windows used the OpenSSH client included with Windows.
Lock continuity remains unverified in the claims table.

| Native managed-certificate platform | OS floor | OpenSSH | Heimdall signer | Evidence build | Verified behavior |
|---|---|---|---|---|---|
| macOS arm64 | 27.2.1 | 10.5p1 | 0.1.0-m01 | Debug | The signer stops new signatures at expiry. The certificate and signer stop new logins at expiry. Strict expiry closes connections Heimdall controls. Graceful expiry can leave dedicated connections open. Shared SSH connections Heimdall manages close at expiry. Remote revocation is bounded by certificate expiry. |
| Linux x86-64 | 6.8.0-147-generic | 9.6p1 | 0.1.0-m01 | Debug | The signer stops new signatures at expiry. The certificate and signer stop new logins at expiry. Strict expiry closes connections Heimdall controls. Graceful expiry can leave dedicated connections open. Shared SSH connections Heimdall manages close at expiry. Remote revocation is bounded by certificate expiry. |
| Windows x86-64 | 10.0.26300.9974 | 9.5p2 | 0.1.0-m01 | Debug | The signer stops new signatures at expiry. The certificate and signer stop new logins at expiry. Strict expiry closes connections Heimdall controls. Remote revocation is bounded by certificate expiry. |

## WSL, containers, jump hosts and shells

| Setup | Support label | What was tested and what is still open | Matrix rows |
|---|---|---|---|
| WSL2 Mode A | not-tested | **Verified** with Git in WSL calling Windows `ssh.exe` with a test SSH configuration. Testing the default configuration is **blocked** on a disposable second Windows account. The Windows elevation check needs a console observer. Windows `scp.exe` and `sftp.exe` with Linux local paths are unsupported. | M04-2 |
| WSL2 Mode B | not-tested | **Verified** with Linux OpenSSH, Git, `scp` and `sftp` through the bridge to Heimdall's Windows signer. Tests across Windows accounts are **blocked** on a disposable second account. New logins while Windows is locked need an observed Windows idle, lock and unlock cycle. | M04-3, M04-7 |
| Local Linux containers | not-tested | **Verified** with rootless Podman 4.9.3 and rootful Docker Engine 29.1.3 in a disposable WSL2 distribution, using OpenSSH in the container under the expected user ID. Native Linux container tests are **blocked** on a Linux desktop host and a native Linux arm64 host for their respective rows. Docker Desktop, devcontainers and WSL-nested containers remain untested. | M04-4, M04-8, M04-9 |
| Jump host via OpenSSH `ProxyJump` | not-tested | **Verified** with managed and existing access on macOS arm64 and Linux x86-64. Windows evidence covers the route rule only. The Windows test server lacked forwarding settings. | M04-5 |
| Bash and Zsh on macOS arm64, Linux x86-64 and WSL2 | not-tested | **Verified** loading access for a trusted project and getting personal access ready for ordinary `ssh`. Linux arm64 coverage is **blocked** on a native Linux arm64 host. | M05-1, M05-2, M05-4, M05-5 |
| Native Windows trusted-project access | not-tested | **Verified** through `heimdall run` and ordinary `ssh` in the matrix's Windows test. That test ran without a shell hook. Windows PowerShell 5.1 and PowerShell 7 have no hook evidence in the matrix yet. | M05-3 |

Mode A uses the native Windows endpoint. The managed-certificate guarantees
depend on the Windows runtime's verified client, which may differ from the
client Git calls from WSL. Mode B and container endpoints have no guarantees in
the claims table. A jump route adds no guarantees of its own.

## Limits to plan for

Programs running under the same OS account share that account's access. A
provider can still require an unlock, approval or touch. Whether unattended work
continues through screen lock, sleep or logout depends on the setup. If a remote
machine is offline, immediate revocation may be unavailable. An issued
certificate and its key can remain usable until the certificate expires.
Existing SSH connections may stay open at expiry, and detached remote work can
keep running. Use the matrix to check your exact client and setup before relying
on them.

### Known limits for managed access and trusted projects

| Where | Known limit |
|---|---|
| Managed access and trusted projects | A program running as you with a terminal can answer Heimdall's confirmation itself. <!-- same_user_agent_with_a_terminal_can_attend --> |
| Trusted projects and shell integration | A program running as you can name a trusted project's directory and activate the access already approved for that project. <!-- request_working_directory_is_a_same_user_claim --> |
| Ordinary `ssh` with personal managed access | The first `ssh` after the personal access slot goes idle may start access but fail to connect. Retry once. The tested Bash and Zsh hooks prepare access before the first `ssh`. <!-- first_ordinary_ssh_after_a_free_slot_fails_once --> |
| Trusted projects and shell integration | Heimdall refuses to match a project to saved trust if its filesystem can't report a stable identity for the project files. <!-- workspace_identity_unavailable_is_refused --> |
| Managed certificate signing during uninstall | If a signing request times out during an access check or work allowed through the uninstall pause, uninstall can proceed while the signing process is still running. A late signature can't publish a certificate. <!-- issuer_request_hold_absent_for_leader_and_lease_work --> |
| Managing a timed-out certificate signing process | If cleanup is cancelled while waiting for a timed-out signing process, it can signal that child before it verifies the child's identity. The signal is limited to the child it started, and the request leaves no certificate behind. <!-- issuer_cleanup_cancelled_kill_on_drop_signals_unreaped_child --> |

## About this page

A script checks this page against the compatibility matrix and the claims
table. It checks each setup's matrix rows, its support label and its
**verified** and **blocked** words. It checks the guarantee table and the known
limits word for word. It also holds every sentence about revocation, expiry or
a guarantee to reviewed wording. The rest of the text is written by hand,
including the details of what was tested, and the script doesn't check it.
