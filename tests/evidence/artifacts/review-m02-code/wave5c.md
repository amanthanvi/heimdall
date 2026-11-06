# M02-W5c-code-review — 7dd879f8 — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-06; the findings and the
validation results are kept verbatim in substance. Orchestrator resolution: ADR-0007 §12.35.

**Reviewed range:** `84a108d4..7dd879f8`, with HEAD `7dd879f8` checked before and after.

All four required checks passed. Fixture probes reproduced:
* an unknown-version evaluation that wrongly stays determined;
* a successful apply without a valid snapshot of the original file;
* two bundle-import validation gaps;
* a Windows toolchain environment that does not keep temporary files in scratch.

## Findings

### N01 — High (P1) — Unknown-version Include token expansion can select the wrong configuration as determined

**Location:** `crates/sshconf/src/client.rs:252`; `crates/sshconf/src/eval.rs:935`; the regression
expectation is at `tests/model/sshconf_eval.rs:2713`.

**Defect:** For an unknown client version, `expands_tokens` always chooses expansion. Unlike an
environment-dependent Include, a token-expanded Include is not made unresolved or opaque. The
evaluator therefore reads only the expanded path, and can report a determined state that omits
the literal path an observed client reads. Expanding `%h` is not the strictest reading: it
selects a different file.

**Scenario and evidence:** The selected client is 9.6p1 but its version query fails. The
configuration has `Include /hm/inc/inc-%h.conf`; for alias `box`, `inc-box.conf` sets port 2962
and the literal `inc-%h.conf` sets port 2965 and a ProxyCommand. An in-memory probe over the
production library gives, with 9.6p1: port 2965, ProxyCommand present, determined. With the
unknown version (`MINIMUM`): port 2962, no ProxyCommand, **determined**. The committed
`ssh-g-9.6p1-run2.txt` shows 9.6p1 reading the literal file. The new model test expects the
unknown version to return the expanded file's port. **Observed** with fixtures.

**Fix:** When the selected client's token-expansion behaviour is not established, keep both
readings or make the Include opaque, so the state is undetermined. Change the regression to
require uncertainty for unknown and unsettled versions.

### N02 — Medium (P2) — An invalid existing backup entry suppresses the required snapshot

**Location:** `crates/localenv/src/projection/apply.rs:934`, `:941`; helpers at `:251`, `:304`.

**Defect:** The writer accepts `Snapshot::Exists` as proof that the original was preserved.
`existing_snapshot` checks only the entry's name, not that it is a regular, correctly owned and
protected file. It also walks `backups` with `read_dir` before checking whether that directory
is a symlink. So a directory or symlink named `ssh_config.*.orig` suppresses the snapshot.

**Evidence:** A copy of the integration fixture ran the production `LocalProjection::apply` with
`<state>/backups/ssh_config.fake.orig` as a directory, and again with `backups` as a symlink to a
directory holding that entry. In both cases the SSH item was `Applied`, the user configuration
changed, the only matching entry stayed a directory, and no snapshot file was created.
**Observed.**

**Fix:** Validate the backup directory without following links before enumerating it. Accept an
existing snapshot only as a regular file with the right owner and mode. Refuse invalid entries
before editing the user file, and use no-follow operations for the source and backup paths.

### N03 — Medium (P2) — Bundle content checks omit metadata and obvious sensitive content

**Location:** `tests/native/m02/import-windows-bundle.py:105`, `:185`;
`tests/native/m02/run-windows-local.ps1:654`.

**Defect:** Import validation scans only the six file bodies, and only for canary prefixes, some
SIDs and IPv4 addresses. The bundle's untrusted `label` skips those checks and is copied into the
run configuration. The runner adds `$Label` after protecting the file bodies. File bodies with
private-key markers or unredacted home paths are accepted.

**Evidence:** Synthetic probes showed that a canary built at run time in `doc["label"]` survived
import into the run configuration, and that a `build.txt` with synthetic OpenSSH private-key
delimiters and a fictional `/home/...` path was imported unchanged. **Observed.**

**Fix:** Validate every bundle field that is persisted or emitted, metadata included. Protect the
runner's metadata before serializing it. Reject private-key material and unredacted personal paths
before creating any artifact file or updating the configuration.

### N04 — Medium (P2) — The bundle size limit is enforced after unbounded decompression

**Location:** `tests/native/m02/import-windows-bundle.py:74`, `:78`, `:81`.

**Defect:** `gzip.decompress(packed)` allocates the whole payload before the 64 MiB limit is
checked, and the input text and decoded data are read without a prior size bound.

**Evidence:** With the 64 MiB limit unchanged, a 66,280-byte gzip payload expanded to 68,157,440
bytes, all allocated before `Refused` was raised. **Observed.**

**Fix:** Bound the input and compressed sizes, decompress incrementally, stop at
`MAX_PAYLOAD + 1` bytes, and refuse before JSON parsing or creating any artifact.

### N05 — Medium (P2) — Toolchain installation and builds inherit temporary directories outside scratch

**Location:** `tests/native/m02/run-windows-local.ps1:325`, `:429`, `:431`, `:444`.

**Defect:** `$toolEnv`, used for the rustup installation and the Cargo builds, sets scratch
`RUSTUP_HOME` and `CARGO_HOME` but inherits `TEMP` and `TMP`. Only the later test environment pins
them to `$wtmp`.

**Evidence:** The actual `New-ChildEnvironment` function, run in PowerShell 7 with synthetic
external `TEMP`/`TMP` and the toolchain's override keys, kept both external values. **Observed.**
Writes outside scratch on Windows are **inferred**; the native branch was not run.

**Fix:** Set `TEMP` and `TMP` to `$wtmp` for installation and builds as well as tests, and override
any other temporary-directory selectors the inherited tools honour.

## Checks found sound (summary)

* `DEFAULT_IDENTITIES` is the complete union, including `id_xmss`, `id_dsa` and
  `id_mldsa44_ed25519`.
* The 9.6p1 refusals and unknown keywords are gated, and an environment-dependent Include is
  opaque.
* A normal apply snapshots before writing, at 0600 in a new 0700 directory.
* `plan_too_large` covers the aggregate diffs, with the truncation paths removed.
* The purge counts every table through a read-only store.
* The pty helpers keep their slave descriptors, pass `HEIMDALL_E2E_BIN`, and reset terminal
  signals, with a control.
* Imported file names are restricted to the six expected names, and labels reject traversal.
* The Windows runner has no elevation, service, firewall, registry, agent or `wsl --shutdown`
  operation.
* The changed-file scan found no leak.

## Commands and validation

| Command or check | Exit code | Result |
|---|---:|---|
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | 1704 passed, 0 failed, 8 ignored |
| `cargo fmt --all --check` | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | passed |
| `bash tools/validation/native-harness-selftest.sh` | 0 | 269 passed, 0 failed |
| fixture probes | 0 | reproduced N01, N02, N03, N04 and N05 |
| cleanup; final `git status`; `git diff --check` | 0 | clean |

Not checked: native harness runs against hosts; native Windows and WSL; live providers; mutation
testing.
