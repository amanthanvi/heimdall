# M02 wave 6x: independent re-check of the review fixes

Reviewer: Codex (independent re-check, read-only), over `c51b8166..c167736e`. Saved verbatim by the orchestrator, with absolute links rewritten as repository paths and the scratch directory written `<scratch>`. Rulings: ADR-0007 §12.51.

**Verdict: fix first.** Reviewed `c51b8166..c167736eb0ca4f0f1d31ca3c6a4627edd6b1aaf4`, with the checkout at that exact fix commit. R01 is resolved; R02, R03 and R04 are partly resolved. The unrelated WU-5 test port was excluded.

**W6X-R01 — resolved.**

The allowlist at `crates/testkit/src/agent.rs:102` requires the exact local-device pipe prefix, case-insensitively, followed by a nonempty suffix containing only ASCII letters, digits, hyphen, underscore or dot. The forward-slash branch at `crates/testkit/src/home.rs:375` feeds the same predicate.

- Embedded `/` and `\`, including either traversal spelling and mixed separators, are refused. A suffix containing `..` without a separator remains part of a prefixed component, rather than a parent-directory component.
- `%`, `$`, `~`, spaces, colons and other characters outside the allowlist are refused. A trailing space is refused. Trailing dots are accepted, but trimming them cannot erase the fixed `heimdall-hmtest-` prefix or select the system agent.
- A remote UNC host and `\\?\` forms do not match the accepted prefix. Case changes in the backslash prefix remain safe; some other slash/case spellings are conservatively refused.

**Win32 normalization conclusions are inferred**, not native execution results. I found no spelling accepted by the pipe branches that escapes the fixture namespace. This predicate does not establish ownership of an arbitrary pipe in that namespace.

**Regression:** `crates/testkit/src/agent.rs:1811` covers both traversal separators and token/space rejection; `crates/testkit/src/home.rs:1241` covers rendered forward and mixed spellings on Windows. These assertions directly cover the original defect by inspection. Neither Rust regression executed in this re-check; the Windows-only test supplies no observed native evidence here.

**W6X-R02 — partly resolved.**

The original stale-exclusion scenario is fixed: `tests/native/m02/m02-evidence.py:721` exposes stale entries, line 729 includes them in the coverage gap, and `tests/native/m02/m02-evidence.py:1111` refuses evidence-record writes after an evaluation error. The extended regression at `tests/native/m02/test_m02_evidence.py:776` passed: an ignored stale test makes the Windows row `in_progress`, exits 1 and writes no evidence records.

A broader inconsistency can still produce a **verified summary row**. An extra logged test absent from a wildcard inventory sets `rc = 1` at `tests/native/m02/m02-evidence.py:892`, without invalidating the affected row. The summary is written before write refusal at `tests/native/m02/m02-evidence.py:1107`. **Observed:** adding synthetic `t_wild::new_test` produced exit **1**, a Windows G1 row rated **verified**, and **zero evidence records**. This misleading summary is a remaining medium-severity gap, not a newly introduced behavior.

Unavailable platforms remain legitimate: a Windows platform marked `unavailable`, with its log/commands/facts files absent, produced exit **0**, a blocked Windows row and **four evidence records**. A blocked capability row also remains writable when its missing tests ran elsewhere, as the passing regression at `tests/native/m02/test_m02_evidence.py:1116` proves. The all-hosts-blocked case regresses, as described below.

**W6X-R03 — partly resolved.**

The rules at `tests/native/m02/import-windows-bundle.py:78` reject the three original examples: the non-fixture dot directory after a redacted root, and Unix/macOS home names beginning with `é`. The end-to-end refused-bundle regression at `tests/native/m02/test_m02_evidence.py:1271` passed, as did acceptance of the intended `.gitconfig`, `.config` and `.ssh` fixture paths.

**Remaining medium-severity leak, observed:** checksum-valid bundles containing `/home/+synthetic-review-user/key`, `/Users/+synthetic-review-user/key`, or `/home/🧪-synthetic-review-user/key` were imported and retained byte-for-byte. These are syntactically valid possible home-directory paths, but `\w` excludes their first character. The fixture-entry boundary also accepts `.ssh+synthetic-review-user` as though it were exactly `.ssh`. All examples use invented names; the parent rules accepted them too. The new regressions therefore prove the reported examples, not complete home-path rejection.

**Artifact comparison, observed:** I applied both complete `sensitive()` implementations to the same **50,138 tracked artifact files**, decoding UTF-8 with replacement for binary data, and separately compared every home-rule match span. Old rules flagged **607** files; new rules flagged **608**. The only difference was `tests/evidence/artifacts/review-m02-code/wave6x.md:24`, containing the synthetic original leak examples. That report was added by the fix commit. Thus the literal whole-current-tree claim that the scans are identical is false; the other **50,137 files** scan identically, and no additional refusal of actual harness output was observed. The newly rejected review prose contains intentional examples rather than a real personal-data leak.

**W6X-R04 — partly resolved.**

The two changed checks at `crates/localenv/src/projection/plan.rs:884` and `crates/localenv/src/projection/plan.rs:2410` now use a noncreating API. A quarantine disappearing before those opens is no longer recreated.

The underlying quarantine validation is shared: Unix `open_or_create_in` first calls `open_existing_in` at `crates/localenv/src/sys/quarantine.rs:237`, which uses the same `validated` routine; Windows `open_or_create_at` first calls `open_existing_at` at `crates/localenv/src/sys/quarantine.rs:433`, preserving directory/reparse, ownership and owner-only-DACL checks. **The public wrappers are not equivalent**, however: `open_existing` omits the parent revalidation described below.

**Remaining low-severity preview write, inferred:** `crates/localenv/src/projection/git.rs:66` still checks existence and then calls `Quarantine::open_or_create`. Preview reaches it through `crates/localenv/src/projection/plan.rs:1081` and line 1279. Removing the Git directory's quarantine between those calls still causes preview to recreate it on Unix or Windows. This is a pre-existing residual of the same defect, not introduced by this commit.

**Regression:** `tests/integration/projection.rs:6015` scans only `plan.rs`, and its behavioral case starts without a quarantine. It cannot establish the no-create property through the Git helper or exercise disappearance between check and open. Its Rust execution was blocked here.

**New defects introduced by the fixes**

1. **Medium — legitimate all-host capability blocks suppress evidence writes.** Location: `tests/native/m02/m02-evidence.py:1111`, interacting with `check_found` at line 930. **Observed:** remove `t_pre` results from every applicable host and give each host a named `missing_capabilities["t_pre"]`. Every affected row is correctly `blocked`, but `check_found` ignores those reasons and reports the tests missing from all logs. The new blanket refusal then writes zero records. On identical inputs, the parent generator also exited **1**, but wrote **four records**; the fix exits **1** and writes **none**. The amended test at `tests/native/m02/test_m02_evidence.py:1122` supplies a successful macOS log, so it misses this case. Distinguish justified capability blocks from inconsistent evidence before refusing writes.

2. **Low — the new planner calls drop the parent-validity recheck.** Location: `crates/localenv/src/projection/plan.rs:884`, also line 2410; callee `crates/localenv/src/projection/replace.rs:441`. **Inferred:** after `DirHandle::open` validates a parent containing a valid quarantine, another actor changes that parent's permissions or ownership before the quarantine check. The previous wrapper rejected it through `dir.still_valid()` at `crates/localenv/src/projection/replace.rs:426`; `open_existing` skips that check. Unix quarantine validation checks the parent's device, not its ownership/mode; Windows validates the quarantine, not its parent. Preview can therefore offer an operation the writer subsequently refuses. Restore equivalent parent validation in the noncreating path. No native race reproduction was run.

No further introduced defect was identified in the R01 or R03 changes.

**Commands, validation and changed files**

- Read-only `git show c167736e -- <scoped paths>`, `git diff c51b8166 c167736e -- <scoped paths>`, status/revision inspection, and targeted `rg`, `sed`, `nl` and `cat` reads were run. The reviewed HEAD remained unchanged.
- `TMPDIR=<scratch> PYTHONDONTWRITEBYTECODE=1 python3 -I tests/native/m02/test_m02_evidence.py`: **115 tests passed, exit 0**.
- `python3 -I <scratch>/probe.py`: final run **exit 0**, covering the mismatch, blocked/unavailable writes, parent-generator comparison, importer acceptance and artifact comparison above. Its first run exited **1** because an assertion expected identical artifact scans; the observed extra review-document match disproved that assertion. No repository source was mutated.
- `cargo test --locked -p heimdall-testkit wire_round_trips` and `cargo test --locked -p heimdall-localenv --test integration_projection preview_never_creates_a_quarantine`: both produced only a shared-build-lock wait and were interrupted, **exit 130**. Neither ran tests. Only my two exact, freshly reidentified Cargo processes, with no children, received SIGINT; other harness processes were untouched.
- Build-output inspection found `prototypes/ts/node_modules` **99M**, `prototypes/go/dist` **20M**, and `prototypes/rust/dist` **3.4M**; no prototype Rust target existed. The initial zsh glob form exited **1** because an optional glob had no matches; the corrected inspection exited **0**. No build-output deletion was needed.
- **Changed files:** only this report, `report.md` (saved here as `tests/evidence/artifacts/review-m02-code/wave6x-recheck.md`), is retained. Probe scripts, imported fixtures, copied source/diff material and scratch results were removed. Final `git status --short --untracked-files=no` was clean. No tracked edits or Git writes were made.

Not checked: native Windows execution, timing-race reproductions, mutation checks or the full Cargo suite; both requested Rust checks were blocked by the shared build lock.
Risk: unredacted home paths and a preview-time directory-creation race remain; the evidence fix also suppresses legitimate blocked records and can leave a misleading verified summary.
