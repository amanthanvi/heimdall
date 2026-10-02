# Compatibility matrix

**Matrix version:** 0 (M00 initial) · **Updated:** 2026-10-02

Labels (spec §3.3): `verified`, `supported-with-limitations`, `experimental`,
`unsupported`, `not-tested`. A row changes from `not-tested` only with a cited
evidence record in `tests/evidence/`. Compilation, detection of an executable, or
container emulation never upgrades a native row.

## Provider × client × environment × mechanism

| # | Environment | Client | Provider / signer | Mechanism | Label | Versions | Observed | Evidence | Limitations |
|---|---|---|---|---|---|---|---|---|---|
| 1 | macOS arm64 | OpenSSH ssh / git / scp / sftp | native ssh-agent | existing identity, ordinary alias | not-tested | — | — | — | — |
| 2 | macOS arm64 | OpenSSH | 1Password SSH agent | existing external signer | not-tested | — | — | — | provider lock/approval behavior governs (spec §7.1) |
| 3 | macOS arm64 | OpenSSH | Heimdall managed recipe (G04) | managed execution credential | not-tested | — | — | — | recipe not selected |
| 4 | Linux x86-64 / arm64 | OpenSSH | native ssh-agent | existing identity | not-tested | — | — | — | — |
| 5 | Linux x86-64 / arm64 | OpenSSH | 1Password SSH agent | existing external signer | not-tested | — | — | — | — |
| 6 | Linux x86-64 / arm64 | OpenSSH | Heimdall managed recipe | managed execution credential | not-tested | — | — | — | — |
| 7 | Windows x86-64 | Win32-OpenSSH ssh.exe / Git for Windows | Windows OpenSSH agent service | existing identity, named pipe | not-tested | — | — | — | blocked: no native Windows host (G03) |
| 8 | Windows x86-64 | Win32-OpenSSH | 1Password SSH agent (pipe) | existing external signer | not-tested | — | — | — | blocked: no native Windows host (G03) |
| 9 | Windows x86-64 | Win32-OpenSSH | Heimdall managed recipe | managed execution credential | not-tested | — | — | — | blocked (G03, G04) |
| 10 | WSL2 Mode A | Windows ssh.exe from WSL, Git | Windows-side provider | Windows SSH authority | not-tested | — | — | — | blocked: no WSL2 host (G03) |
| 11 | WSL2 Mode B | Linux OpenSSH in WSL | scoped bridge to selected upstream | Linux-native scoped endpoint | not-tested | — | — | — | blocked: no WSL2 host (G03) |
| 12 | Local Linux container | OpenSSH in container | scoped bound endpoint | container binding | not-tested | — | — | — | Docker Desktop variants labeled separately (spec §8.5) |
| 13 | Remote Linux runner | OpenSSH | runner-held managed credential | controller-independent runner | not-tested | — | — | — | G07 |
| 14 | any | OpenSSH via ProxyJump | any | bastion route | not-tested | — | — | — | — |
| 15 | any | OpenSSH via ProxyCommand | Iroh/Pigeons | optional transport | not-tested | — | — | — | G06-gated, opt-in |

## Mechanism observations (not product support)

Rows here record OpenSSH/platform mechanism behavior observed on fixtures during
gate experiments. They inform design; they do **not** label Heimdall support.

| Observation | Client / server versions | Evidence | Status |
|---|---|---|---|
| _(populated from M00 G04/G09-preliminary experiments)_ | | | |
