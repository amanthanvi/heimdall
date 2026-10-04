# ADR-0003: Source pins for spec section 19 and G02 candidate dependencies

Status: recorded (M00-T02, revised by M00-T02-fix). Task status: implemented_unverified. The v1 pins had an independent review (`tests/evidence/artifacts/m00-wf3/review-sources.json`) that found two major and several minor defects; M00-T02-fix addresses all of them and has not been re-reviewed.
Date: v1 retrieval 2026-10-02T23:56Z; v2 baseline retrieval 2026-10-03T21:18Z (spec says sources were accessed 2026-10-01).

## Context
spec.md section 19 cites 34 mutable primary sources (S01-S34) and says dependency versions and immutable snapshots must be pinned before implementation (plan 1.4, G01, R-QU-01, R-QU-07, R-DI-08). Later decisions (G02 and others) must cite fixed snapshots rather than moving docs. This ADR also pins the G02 candidate dependencies and adjacent tools.

## Method (v2, reproducible)
- The fetch and normalization code is committed: `docs/sources/tools/fetch_pins.py` (python3 standard library, HTTP GET only, no credentials). Its docstring defines the normalizer (version 1): UTF-8 decode, drop head/script/style/noscript/template/svg content, NFC, collapse whitespace.
- For each source the script records HTTP status, raw-body sha256, normalized-text sha256, sizes, selected headers and date markers in `docs/sources/fetch-baseline.json` (retrieved 2026-10-03T21:18Z). GitHub sources are fetched at the pinned commit (`raw.githubusercontent.com/<repo>/<sha>/<path>`) and the git blob sha1 is recomputed; all 7 match the pinned blobs.
- Primary pin. 15 sources use the raw-body sha256: their raw hash from the v1 retrieval (2026-10-02T23:56Z) was reproduced about 21 h later (S01-S05, S10, S16-S19, S23, S27, S29, S30, S34). 19 use the normalized-text sha256 as primary: 13 had a changed raw hash since v1 (S06-S09, S11-S15, S20-S22, S28; page chrome or content), and 6 (S24, S25, S26, S31, S32, S33; fetched as `.md` variants) have no v1 raw hash so long-term raw stability is unknown. The raw hash is kept for all as evidence of the exact bytes fetched.
- Reproducibility proof (executed, 2026-10-03): `fetch` run twice back to back gave 34/34 identical raw hashes and 34/34 identical normalized hashes and date markers (`docs/sources/fetch-repeat.json` vs `fetch-baseline.json`, `compare` exit 0), and the 27 snapshot files were byte-identical across the two runs. Two earlier back-to-back pairs also matched 34/34. This shows stability over minutes only; the 13 sources whose raw hash moved between v1 and v2 show raw bytes do not stay stable for hours.
- v1 `text_sha256` values came from a script that was not retained. The independent review could not reproduce any of them (0/34). They remain in `pins.json` as `pin.legacy_text_sha256_unreproducible` and must not be used as drift detectors. The v1 sentence "all 34 text hashes matched on re-fetch" is withdrawn as unverifiable.
- Immutable copy. GitHub sources: commit permalink plus blob sha1. The other 27: a deterministic gzip of the normalized text in `docs/sources/snapshots/` (scope, verification and copyright note in its README; owner decision E8). Internet Archive: the read-only availability API (GET only, no save requests) returned a snapshot for 8 of 27 sources across two passes, was inconsistent between passes, and every snapshot found predates the pin; only S03 matches the pinned normalized text (`docs/sources/archive-lookups.json`). Archive URLs are recorded as hints, not as the copy of record.
- Date markers kept from v1 where they exist: OpenBSD man page footer date, openssh.org Last-Modified, Microsoft ms.date and updated_at, Smallstep "Last updated" text, 1Password embedded dateModified. They are now extracted by the script.
- Candidate versions from crates.io API, npm registry, the Go module proxy and `gh api` GET. No installs, no writes, no SSH or credential access. Download of fixtures: none.
- Claim check: each spec one-line claim compared with fetched text. "Supported" means the page text is consistent with the spec's one-line claim; it is not behavioral evidence for installed versions. The independent review checked this against live pages and confirmed all 34, apart from the misattributed S26 quote now corrected.

## Source pins (S01-S34)
Pin columns: marker (date or commit), then primary hash kind (raw or norm) with a 16-hex prefix. Full hashes, excerpts, notes, snapshot paths and archive hints are in `docs/sources/pins.json` (`pin_v2`).

| ID | URL | Marker | Primary hash | Copy | Claim |
|---|---|---|---|---|---|
| S01 | https://man.openbsd.org/ssh_config | OpenBSD-current September 20, 2026 (SSH_CONFIG(5)) | raw `3d8e498373fc78cf` | snapshot | supported |
| S02 | https://man.openbsd.org/ssh | OpenBSD-current September 5, 2026 (SSH(1)) | raw `16c3540970d44f49` | snapshot | supported |
| S03 | https://www.openssh.org/agent-restrict.html | Tue, 22 Sep 2026 19:18:50 GMT | raw `28939c425c736c78` | snapshot | supported |
| S04 | https://man.openbsd.org/sshd | OpenBSD-current September 2, 2026 (SSHD(8)) | raw `3c4c65d0221c28f1` | snapshot | supported |
| S05 | https://man.openbsd.org/sshd_config | OpenBSD-current September 17, 2026 (SSHD_CONFIG(5)) | raw `76b5b91d17571ea5` | snapshot | supported |
| S06 | https://www.1password.dev/ssh/agent/security | 2026-10-02T14:06:52.625Z (embedded page metadata) | norm `e6e8c6609fe52509` | snapshot | supported |
| S07 | https://www.1password.dev/ssh/agent/authorization | 2026-09-04T17:57:13.051Z (embedded page metadata) | norm `0c5ee2dc8039aa82` | snapshot | supported |
| S08 | https://www.1password.dev/environments/mcp-server | 2026-09-14T19:31:18.103Z (embedded page metadata) | norm `002f6741c79eb7c8` | snapshot | supported |
| S09 | https://www.1password.dev/ssh/bookmarks | 2026-10-02T14:06:52.624Z (embedded page metadata) | norm `3526471b48747058` | snapshot | supported |
| S10 | https://man.openbsd.org/ssh-keygen | OpenBSD-current October 1, 2026 (SSH-KEYGEN(1)) | raw `163d73c60b555592` | snapshot | supported |
| S11 | https://smallstep.com/docs/tutorials/ssh-certificate-login/ | February 3, 2026 ("Last updated on") | norm `b70565475abd28d0` | snapshot | supported |
| S12 | https://www.1password.dev/ssh/integrations/wsl | 2026-10-02T14:06:52.622Z (embedded page metadata) | norm `e081095a090c9c2c` | snapshot | supported |
| S13 | https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement | ms.date 2025-10-03; updated_at 2026-04-21T17:36:00Z | norm `c39cdaad6475f67f` | snapshot | supported |
| S14 | https://docs.iroh.computer/concepts/endpoints | none (hash only) | norm `16a5c1dc482cb4ec` | snapshot | supported |
| S15 | https://docs.iroh.computer/concepts/tickets | none (hash only) | norm `4929438e0c7651d5` | snapshot | supported |
| S16 | https://github.com/pingdotgg/t3code/blob/main/docs/internals/remote.md | cba7dd77817d (commit permalink) | raw `196f958196577f42` | permalink | supported |
| S17 | https://github.com/pingdotgg/t3code/blob/main/docs/internals/connection-runtime.md | 99641fd09a50 (commit permalink) | raw `2ea79169cb0f384a` | permalink | supported |
| S18 | https://github.com/pingdotgg/t3code/blob/main/docs/internals/t3-connect.md | 8d7b5e998c72 (commit permalink) | raw `4f6c365fe60836a1` | permalink | supported |
| S19 | https://github.com/n0-computer/pigeons | 7800c5207601 (commit permalink) | raw `577dbc3e19f9155a` | permalink | supported |
| S20 | https://docs.iroh.computer/concepts/security-privacy | none (hash only) | norm `e2b026250fe2ac35` | snapshot | supported |
| S21 | https://docs.iroh.computer/languages/rust | none (hash only) | norm `a96c1837085523bf` | snapshot | supported |
| S22 | https://docs.iroh.computer/languages/javascript | none (hash only) | norm `5e7ff1b110b49b91` | snapshot | supported |
| S23 | https://mitchellh.com/writing/building-block-economy | none (hash only) | raw `f29e59ef0ff58b0f` | snapshot | supported |
| S24 | https://developers.openai.com/api/docs/guides/function-calling | none (hash only) | norm `51a9bd1593d64e8a` | snapshot | supported |
| S25 | https://learn.chatgpt.com/docs/build-skills | none (hash only) | norm `6bbf6cd1028ec1d6` | snapshot | supported |
| S26 | https://developers.openai.com/api/docs/guides/latest-model | none (hash only) | norm `f6ecbbe14400b8f7` | snapshot | supported |
| S27 | https://github.com/charmbracelet/bubbletea | 96d69d2f7eb1 (commit permalink) | raw `5039b3d120bccea1` | permalink | supported |
| S28 | https://ratatui.rs/ | none (hash only) | norm `cfe35cc965427aa5` | snapshot | supported |
| S29 | https://github.com/anomalyco/opentui | de8dc97080e4 (commit permalink) | raw `6266260d556e4511` | permalink | supported |
| S30 | https://man.openbsd.org/ssh-agent | OpenBSD-current September 18, 2026 (SSH-AGENT(1)) | raw `ee873a3e04c28616` | snapshot | supported |
| S31 | https://developers.openai.com/api/docs/guides/reasoning-best-practices | none (hash only) | norm `1d11c6880da3275e` | snapshot | supported |
| S32 | https://developers.openai.com/api/docs/guides/evaluation-best-practices | none (hash only) | norm `30b9b23c5c754b05` | snapshot | supported |
| S33 | https://developers.openai.com/api/docs/guides/agent-builder-safety | none (hash only) | norm `f9b8be94ef4a431f` | snapshot | supported |
| S34 | https://github.com/pingdotgg/t3code/blob/main/docs/internals/environment-auth.md | 3b75e607eb90 (commit permalink) | raw `e743ed4c50da6603` | permalink | supported |

Result counts: supported 34, changed 0, not_found 0, could_not_fetch 0. Rows with nuance that spec owners should read: S02, S07, S17, S19, S22, S26, S27, S32. S17 has drifted on main since the v1 pin (see the contradictions list); the pin is the commit permalink and remains valid.

## Candidate dependency pins (as of 2026-10-02, re-verified by the independent review on 2026-10-03)
| Candidate | Version | Released | License | Maintenance |
|---|---|---|---|---|
| Bubble Tea (Go) module `charm.land/bubbletea/v2` | v2.0.10 (tag commit d5bfd5c) | 2026-09-24 | MIT | main head 96d69d2 on 2026-10-02 |
| Ratatui (crate `ratatui`) | 0.30.2 (rust 1.88) | 2026-06-19 | MIT | head 7767679 on 2026-09-28 |
| ratatui-crossterm | 0.1.2 | 2026-06-19 | MIT | defaults to crossterm 0.29, optional 0.28 |
| crossterm | 0.29.0 | 2025-04-05 | MIT | master head 2026-09-14; last crates.io release 18 months old |
| OpenTUI `@opentui/core` (+react, solid, keymap, ssh) | 0.5.14 | 2026-09-30 | MIT | head de8dc97 on 2026-10-02; pre-1.0 |
| Iroh (crate `iroh`) | 1.3.0 (rust 1.91) | 2026-09-28 | MIT OR Apache-2.0 | head b4c8fc6 on 2026-10-02 |
| Iroh JS `@number0/iroh` | 1.1.0 (node >=20.3.0) | 2026-07-16 | MIT OR Apache-2.0 | iroh-ffi head 3103bf5 |
| Pigeons (`iroh-pigeons`) | v0.2.1 | 2026-08-03 | MIT OR Apache-2.0 (Cargo.toml + both license files); GitHub API says Apache-2.0 | head 7800c52 on 2026-09-29 |
| Win32-OpenSSH (releases: `PowerShell/Win32-OpenSSH`; source and LICENCE: `PowerShell/openssh-portable`) | 10.0.0.0p2-Preview (all 5 latest tags are Preview) | 2025-10-27 | BSD-style `LICENCE` in openssh-portable at e581929 ("all components are under a BSD licence, or a licence more free than that"; "OpenSSH contains no GPL code"); GitHub license field NOASSERTION | source default branch `latestw_all`, head e581929 on 2026-09-25 (merge of OpenSSH 10.3p1), ahead of the newest release |
| Smallstep step-ca (`smallstep/certificates`) | v0.30.2 | 2026-03-23 | Apache-2.0 | head fdeb6fd on 2026-09-29 |
| Smallstep step CLI (`smallstep/cli`) | v0.31.0 | 2026-09-25 | Apache-2.0 | head 8301c0d on 2026-09-25 |

Win32-OpenSSH correction. v1 examined `PowerShell/Win32-OpenSSH` (default branch L1-Prod), a repository that only tracks releases and issues; its README says active development is in `PowerShell/openssh-portable`. The v1 statements "no LICENSE file" and "head 39d8050 on 2026-09-23" described the wrong repository (39d8050 is an issue-triage bot commit). The LICENCE is spelled with a C, so a check for a file named LICENSE finds nothing. One Windows-specific file sampled (`contrib/win32/win32compat/misc.c` at e581929) has a "Copyright(c) 2016 Microsoft Corp." BSD-style notice; the Windows tree was not audited file by file. Installable MSI/zip assets are attached to Win32-OpenSSH releases; the GitHub releases API shows no releases on openssh-portable.

OpenTUI native components. Source-backed: Zig implementation (private `@opentui/native` workspace) shipped as prebuilt optional npm packages `@opentui/core-{darwin,linux,win32}-{x64,arm64}` plus `linux-*-musl`; dependency `bun-ffi-structs` 0.3.1; peer `web-tree-sitter` 0.25.10; build needs Bun 1.4.1+ and Zig 0.16.0; `@opentui/core` 0.5.14 package.json lists `engines` `bun >=1.3.0` and `node >=26.4.0` as two separate keys, and its exports `.` entry has conditions `bun` (./index.bun.js), `node` (./index.node.js), `import` (./index.node.js) and `types`; full tarball integrity `sha512-tfQ+PWQyeBnYloB3diEcPqbILv14xemH5jjAEICfPuyNDtGBqrjhUtThrhbvFRuPMcj6IEeXrAk6VE8e91h0kg==` (shasum fad26be1b292d609bf9b7a09b74c0516173ccc67). Inference, not stated by any source, to be tested in G02: that native code loads through Bun FFI on every runtime (guessed from the dependency name and the `bun` condition); that the two engines keys mean "either runtime suffices" (the earlier wording "node >=26.4 or bun >=1.3" was this reading); that Node 26.4+ can load the native packages. Node 26.x exists (v26.10.0, 2026-09-21, per the review).

Iroh bindings and platforms: Rust crate (docs list iOS, Android aarch64/armv7, macOS arm64/x86_64, Linux x86_64/aarch64/armv7 glibc+musl, Windows x86_64/aarch64). JS via napi-rs: 11 prebuilt packages (android arm/arm64, darwin-arm64, linux arm/arm64/x64 gnu+musl, win32 arm64/x64), no darwin-x64. `Endpoint.bind` applies the n0 preset (public discovery plus default relays) by default (S22). Go binding is a third-party experimental repo (`git.coopcloud.tech/decentral1se/iroh-go`, Linux x86_64/aarch64 musl, no stable tag). C binding builds from source (no prebuilt). Python/Swift/Kotlin exist in iroh-ffi but were not individually version-checked. Only `@opentui/core` has a full npm integrity recorded; no other candidate package has an integrity or checksum pin yet.

Pigeons integration (S19 README at 7800c52): `pigeons roost` (server) and `pigeons add --id <endpoint id> --name <host>` writes an ssh_config `Host` entry whose `ProxyCommand` runs `pigeons fly --stdio`. Behaviors that matter for Heimdall's disclosure and fixtures:
- Telemetry is opt-in: the first setup command (`roost`, `fly`, `add`, `service install`) in a terminal asks once; nothing is sent unless `telemetry_enabled = true`. Endpoint counters (relay usage, hole-punching success, bytes moved) are sampled once a minute and pushed to iroh-services over an iroh connection, so the sending endpoint ID is visible to the collector.
- `pigeons service install` installs a system service (systemd, launchd, Windows SCM); the roost then runs as root and reads a machine-wide config (`/etc/pigeons/config.toml` or `C:\ProgramData\pigeons\config.toml`).
- `pigeons add` writes to `~/.ssh/config` (README example output) and the tool uses a dedicated `.ssh/pigeons_ed25519` keypair.
- Security model: anyone holding the endpoint ID can reach the SSH port; SSH auth still applies end to end.
- Fixture rule (inference from CLAUDE.md boundaries, not a Pigeons statement): any trial runs with HOME pointed at a scratch directory, never `service install`, telemetry answered or preset off. Release binaries: darwin aarch64/x86_64, linux aarch64/x86_64, windows x86_64. The documented install script is `curl | bash` from an S3 bucket; fixtures should use release assets or cargo instead.

## Contradictions and nuances found (escalations, not decided here)
- E1 (S06/S07 vs spec ~line 323): suggested spec clarification, not a contradiction. The spec sentence (remembered approvals do not keep private keys available after lock) is supported as written. S07 also says the timed options (4/12/24 h) keep key approvals in agent memory while 1Password is locked, with an unlock still needed for key access. A sentence distinguishing approvals from key availability would prevent misreading; wording is the owner's.
- E2 (S01/S02 vs spec ~line 488): "ssh -G ... Match exec may run commands" is an inference, labelled as such. S01 says "The exec keyword executes the specified command under the user's shell" and S02 says "-G ... after evaluating Host and Match blocks"; together they support it textually but no source says it in one sentence. Needs behavioral evidence (G07/G09).
- E3 (S27): Bubble Tea v2 path is `charm.land/bubbletea/v2`; stale if any plan text uses the github import path. The review found none in plan.md, spec.md, docs or prototypes/go.
- E4 (S22): no Intel macOS binary for Iroh JS. OpenTUI core package.json lists engines bun >=1.3.0 and node >=26.4.0 as separate keys; whether either runtime alone suffices, and how native code loads under Node, is inference until G02 tests it. Relevant to G02 hard gates (distribution, Windows/WSL).
- E5 (S32): OpenAI Evals platform deprecated (read-only 2026-10-31, shutdown 2026-11-30). Guidance claim still supported; do not depend on the platform.
- E6 (restated): the Win32-OpenSSH licence is a BSD-style `LICENCE` in `PowerShell/openssh-portable` (v1 wrongly said none). The open owner decision is the support baseline: every one of the 5 latest releases is tagged Preview (latest 10.0.0.0p2-Preview, 2025-10-27) while source head is ahead (merged OpenSSH 10.3p1 on 2026-09-25). Whether that can be a "supported" baseline is not decided here.
- E7: crossterm's last crates.io release is 2025-04-05 and its GitHub "latest" tag (0.28) lags crates.io (0.29.0); Pigeons license metadata differs between Cargo.toml and GitHub API.
- E8: 27 third-party text snapshots are committed for verification (`docs/sources/snapshots/README.md`). Copyright stays with the publishers. Keep, replace with hashes plus archive URLs, or remove before any publication: owner's decision.
- S17 drift: commit 9333509 (2026-10-03T04:42:36Z) changed `docs/internals/connection-runtime.md` on main after the v1 pin (blob 301e1e0 to 35c8b0a). The pin is the permalink at 99641fd; v2 fetches at that commit and the blob sha1 matches. The review found the quoted passages still hold in the new text.
- S26 excerpt: the v1 excerpt quoted "Be very specific about your end goal", which is on S31, not S26. Corrected in `pins.json` and `excerpts/notes.md`; the S26 claim is supported by its own text.
- S27 pin: 96d69d2 is the main head at retrieval, not the v2.0.10 release commit d5bfd5c; cite the tag for the release.
- Note: spec says sources were accessed 2026-10-01; S10 (ssh-keygen) man page carries an "October 1, 2026" footer date, so content may have changed within hours of the spec's access date. The v1 text hashes were not reproducible, so the v2 baseline of 2026-10-03 is the first reproducible record.

## Reopen conditions
- `fetch_pins.py compare` against `docs/sources/fetch-baseline.json` reports drift for a source cited by a gate that is still open; read `docs/sources/snapshots/<id>.txt.gz` to see what the pin said.
- A candidate ships a new minor/major release before the G02 selection is locked.
- Win32-OpenSSH (`PowerShell/Win32-OpenSSH`) publishes a release tag without "Preview", or `PowerShell/openssh-portable` changes its `LICENCE`; Iroh JS adds darwin-x64; Pigeons changes its ProxyCommand integration, telemetry or service behavior.
- spec section 19 is amended, or the support matrix cites a source not listed here.

## Limits
- Normalized-text hashes depend on the normalizer: a change of Python's `html.parser` or `unicodedata` data could shift a hash without a content change. The baseline was produced with Python 3.14.8; a mismatch should be checked against the snapshot before it is treated as drift.
- Stability over longer than hours is only shown for the 15 raw-primary sources (one 21 h interval).
- The Internet Archive availability API gave inconsistent answers; absence of an archive URL is not proof of absence.
- Behavioral claims (E2 Match exec under `ssh -G`, OpenTUI under Node 26.4 versus Bun, Iroh JS on Intel macOS) are not tested here; they belong to G02, G07 and G09.
