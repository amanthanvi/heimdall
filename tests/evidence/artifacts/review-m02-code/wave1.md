# M02-W1-code-review — f704ce93 — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Earlier attempts on three Codex instances and one Claude reviewer
failed on usage or rate limits before producing a review (progress.md). Saved by the orchestrator
on 2026-11-03. The text is verbatim except that the reviewer's absolute worktree links were
converted to repository-relative paths, because the repository is public. Orchestrator
resolution: ADR-0007 §12.16.

**Reviewer and mode:** Codex, independent READ-ONLY review on macOS. No tracked files changed; final worktree clean.

**Reviewed commit and range:** `f704ce93`, range `bd4215e2..f704ce93`, plus preparation commits `0e217bcb` and `f06a687a`. Validation ran at checkout HEAD `f06a687a`.

The required workspace checks pass, but six supported defects remain. The most consequential are consent reuse after an environment-dependent behavior change and a fixture guard that misses identities selected by non-shell invocations. The other findings concern incorrect static evaluation, Include-path interpretation, path corruption, and a Unicode panic. Items explicitly assigned to later units by ADR-0007 §12.15, including the expected preparation placeholders, are excluded from these findings.

## Findings

### Y01 — High — Environment-dependent behavior can reuse obsolete consent

**Location:** `crates/sshconf/src/eval.rs:1044`, `relevant.rs:398`, `consent.rs:103`.

**Defect:** `env_check` checks whether a variable exists but does not bind its value. The evaluator retains literal arguments such as `${HM_AGENT}`, and the behavior digest hashes those literals while `behavior_state` reports the result as determined. Different effective agent endpoints therefore produce the same consent state.

**Concrete failure scenario:** An approved restore state contains `IdentityAgent ${HM_AGENT}`, with the variable pointing to agent A. After adoption, the variable changes to agent B. Removing the managed section restores B, but its digest equals the previously approved restore digest for A, so `classify` requires no new decision.

**Evidence:** A compiled probe evaluated the same directive with two different nonempty variable values. It observed:

```text
env_digests_equal=true,both_determined=true,consent_required=false
```

The consent probe used a distinct literal managed endpoint as the current state and the old environment-dependent state as the consented restore state. This is separate from the already deferred raw-command and source-role gaps.

**Observed or inferred:** Digest equality, determined classification, and consent reuse were observed. The eventual rollback effect is inferred from those results and OpenSSH's documented `IdentityAgent` expansion.

**Fix:** Bind the effective expansion inputs or expanded values into the consent behavior state. Where effective behavior cannot be established, classify it as undetermined. Include the special environment-reference forms of `IdentityAgent`, and add a regression covering rollback after an endpoint variable changes.

### Y02 — High — The fixture guard misses keys and agents selected by exec or subsystem invocations

**Location:** `crates/testkit/src/home.rs:700`, particularly line 705; `build_client` at line 741.

**Defect:** `check_alias` always evaluates `Invocation::Shell`. The returned command can subsequently run a remote command, and SCP, SFTP, and Git use other invocation profiles. Identity and agent directives behind those profiles can be absent from the guard's evaluation.

**Concrete failure scenario:**

```sshconfig
IdentityFile "/scratch/key.pub"
Match sessiontype exec
    IdentityFile "/outside-scratch/key"
```

The guard accepts the shell evaluation. A caller then appends a remote command to the SSH command, causing OpenSSH to select the additional key. The same mechanism can hide an outside-scratch `IdentityAgent`, violating the fixture boundary against contacting the owner's agent.

**Evidence:** A compiled probe used two disposable scratch directories, with the second standing in for outside material:

```text
guard_accepts_exec_only_outside_identity=true
exec_evaluation_selects_outside_identity=true
```

No owner key or agent was used.

**Observed or inferred:** Guard acceptance and selection by the exec evaluation were observed. Contact with real owner material is an inferred consequence if such a path or endpoint appears in a fixture configuration.

**Fix:** Validate the actual invocation before returning an executable command. Where the API permits callers to append an unknown command afterward, conservatively cover every possible invocation and command condition, or require the invocation before validation. Add exec, subsystem, and Git guard regressions.

### Y03 — Medium — Quoted Include targets can load a different file through glob expansion

**Location:** `crates/sshconf/src/render.rs:487`, with path acceptance at line 154 and quoting at line 279.

**Defect:** `RenderPath` accepts glob metacharacters, and `render_include_block` only quotes the path and escapes percent signs. OpenSSH still expands globs inside a quoted Include argument.

**Concrete failure scenario:** The managed file is at `/scratch/dir[1]/managed.conf`, while `/scratch/dir1/managed.conf` also exists. The rendered Include loads the latter instead of the approved managed file. If nothing matches the pattern, the intended projection is silently omitted.

**Evidence:** A probe called the actual renderer with the bracket-containing target. The intended file set `HostName intended.example`; the other file set `HostName different.example`. Installed OpenSSH `10.3p1`, run with `-G -F` against the generated disposable configuration, exited 0 and reported:

```text
hostname different.example
```

Both keys and agents were disabled for that comparison.

**Observed or inferred:** Loading the wrong file was observed. Execution of commands from an unintended file was not attempted.

**Fix:** Define and enforce literal Include-target handling through the integrator: either escape metacharacters with behavior verified against supported clients or refuse such targets before editing configuration. Double quoting alone is insufficient.

### Y04 — Medium — `Match sessiontype` ignores an effective `SessionType` directive

**Location:** `crates/sshconf/src/eval.rs:1012`.

**Defect:** `session_type()` derives its answer exclusively from `Query::invocation`. It ignores a preceding effective `SessionType`, although that directive changes OpenSSH's condition result.

**Concrete failure scenario:**

```sshconfig
SessionType none
Match sessiontype shell
    HostName wrong.example
Match sessiontype none
    Port 2202
```

For a shell query, Heimdall selects the shell section and reports `HostName wrong.example` as determined. OpenSSH selects the `none` section.

**Evidence:** The compiled evaluator probe reported:

```text
sessiontype_none: hostname=Determined(wrong.example),invalid_count=0
```

OpenSSH `10.3p1` evaluated the disposable configuration successfully and reported:

```text
hostname box
port 2202
sessiontype none
```

**Observed or inferred:** The evaluator/OpenSSH disagreement was observed.

**Fix:** Evaluate `Match sessiontype` from the effective session type, respecting explicit invocation constraints and the applicable configuration value. Preserve uncertainty when the effective type is uncertain. Extend the invocation tests to include `SessionType none` and `SessionType subsystem`.

### Y05 — Medium — Home-relative rendering silently changes Unix paths containing backslashes

**Location:** `crates/sshconf/src/render.rs:249`, particularly line 252.

**Defect:** `home_relative` replaces every backslash with `/` before dispatching to the Unix or Windows validator. On Unix, backslash is a filename character. This bypasses the explicit Unix refusal rule and changes the selected path.

**Concrete failure scenario:** A Unix identity, agent, or managed-file path under the account home contains a component named `a\b`. The function returns `~/a/b`, referring to a different location.

**Evidence:** A compiled call to `RenderPath::home_relative` with Unix style and `/fixture/home/a\b` returned:

```text
Ok("~/a/b")
```

The direct Unix constructor rejects backslashes.

**Observed or inferred:** The path transformation was observed. Selection of a different existing key, socket, or file is inferred.

**Fix:** Normalize backslashes only for Windows style. For Unix style, preserve the original remainder and let the Unix validator refuse it. Add a regression asserting refusal without path transformation.

### Y06 — Medium — A non-ASCII pipe name can panic the renderer

**Location:** `crates/sshconf/src/render.rs:307`, particularly line 309.

**Defect:** `strip_pipe_prefix` slices a UTF-8 string at `prefix.len()` after checking only its byte length. That offset can fall inside a multibyte character, causing a panic before the prefix comparison.

**Concrete failure scenario:** Calling `RenderPath::pipe("aaaaaaaaé")` reaches a slice ending inside `é` and panics instead of returning a path or a validation error.

**Evidence:** A compiled probe wrapped that exact call in `catch_unwind` and observed:

```text
unicode_pipe_panics=true
```

The agent-client pipe parser already checks `is_char_boundary` before its analogous slice.

**Observed or inferred:** The panic was observed.

**Fix:** Use checked slicing or a character-boundary check before comparing the prefix. Add the reproducer and a small arbitrary-Unicode no-panic test for the public constructor.

## Checks found sound

- **Static evaluation executes no configuration commands.** The parser/evaluator reads through `ConfigSource`; it has no process-execution port. `Match exec` is modeled as uncertainty.
- **Agent-client message scope is narrow.** The production client writes the constant REQUEST_IDENTITIES frame. It checks the Unix peer UID before writing, clamps limits, applies a whole-call timeout, checks declared sizes before allocation, discards comments, and rejects malformed identity replies as a whole. The workspace adversarial tests passed.
- **Existing-access preparation is passive.** Native-agent and 1Password `prepare`/`renew` do not invoke the listing client or sign, add, remove, or lock keys. I found no hardcoded 1Password endpoint.
- **Consent rejects explicitly undetermined states.** The classifier requires a decision when current or after state is undetermined, and excludes consent recorded as undetermined. Y01 concerns states incorrectly presented as determined and equivalent.
- **Launch arguments remain local.** The launch code passes arguments to the child without adding them to run records. Resolution skips relative PATH entries. Unix exec-failure handling restores nonterminating SIGPIPE handling before attempting the failure record.
- **Editor byte-preservation checks are substantive.** The round-trip properties and marker-edit refusal tests passed; I found no additional byte-preservation defect in the reviewed editor paths.
- **Preparation changes preserve the planned boundary.** The `sys` split retains the existing public paths. The seven placeholder targets are expected preparation and are not counted as substantive feature validation.
- **Targeted committed-content scans** found no private-key PEM blocks, concrete generated canaries, or rooted personal home paths in the changed committed files. Synthetic fixture paths were excluded.
- **Cleanup completed.** This checkout's 3.6 GB `target/`, all review probes, and the three temporary validation logs were removed. Final `git status --short` was empty.

## Commands and validation

| Command | Exit code | Result |
|---|---:|---|
| `git status --short`; `git rev-parse HEAD`; `git log`; scoped `git diff` / `git show` | 0 | Confirmed clean checkout, requested ancestry, wave-1 range, and preparation changes. Final HEAD remained `f06a687a`. |
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | **1071 passed, 0 failed, 4 ignored.** Includes seven expected preparation placeholder tests. Ignored cases are child-process entry points. |
| `cargo fmt --all --check` | 0 | Passed; no formatting diff. |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Passed. |
| `python3 -I` with `gzip` to inspect pinned S01 text | 0 | Checked documented condition, Include, and expansion semantics. |
| `rustc --edition=2024 … -L dependency=target/debug/deps --extern …` for temporary review probes | 0 | All probe builds succeeded using this checkout's existing build output. |
| Temporary evaluator, consent, fixture-guard, and renderer probe executables | 0 | Reproduced Y01, Y02, Y05, and Y06; generated the configuration used to confirm Y03. |
| `/usr/bin/ssh -G -F <disposable-config> box` | 0 | Confirmed Y03 and Y04. Other comparisons were discarded as findings when they did not demonstrate a discrepancy. No configuration commands were included. |
| `/usr/bin/ssh -V` | 0 | Installed client: OpenSSH `10.3p1`, LibreSSL `3.3.6`. |
| `python3 -I` targeted scan of changed committed files | 0 | No matches for private-key blocks, concrete generated canaries, or rooted personal home paths. |
| `du -sh target` | 0 | Measured 3.6 GB before removal. |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | 1 | No matching prototype output directories existed. |
| Targeted cleanup, followed by `git status --short` | 0 | Build output, probes, and logs removed; worktree clean. |

## What was not checked

Native Windows and WSL behavior is **blocked** by the absence of those native test environments in this review. Batch escaping, pipe ownership/DACLs, console handling, and Windows exit behavior received source inspection only. The live foreign-UID socket case is **blocked** without a second-user fixture.

Later-wave wiring and full M02 acceptance were not exercised. No owner keys, agents, keychains, or SSH configuration were used as test material. The committed-content scan was targeted, not an exhaustive secret audit.

The passing suite does not cover the six reproduced edge cases above; consent safety and fixture isolation remain the principal risks until Y01 and Y02 are fixed.
