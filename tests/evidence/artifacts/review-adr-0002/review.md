# Independent adversarial review of ADR-0002 draft (G02 language/TUI/distribution)

Reviewer: independent agent, 2026-10-04. Subject: `docs/decisions/0002-language-tui-distribution.md`
(untracked draft, read at HEAD `b690b8a`). Section 4 (round-3 results) was out of scope by
instruction. Nothing was rebuilt and the harness was not run; all checks below are reads of
committed/working-tree evidence plus cheap recomputation (sizes, line counts, JSON fields, grep).
Every "observed" statement names the file it came from. Items marked *inference* were not verified.

Severity: **major** = would mislead the owner's D1/D2 decision or misstates a gate; **minor** =
factual error or omission that should be corrected but does not change the picture; **cosmetic**.
No finding rises to blocker: the recommendation may well be right, but several of the reasons
given for it are stronger than, or asymmetric with, the evidence.

---

## Major

### M1. The Go child/IPC "fail" rests on rulings issued after Go's last fix round, and the ADR calls the defects "Go runtime properties" when the reviewer says one is a one-line policy fix

- ADR text (§3 Gate result): "Go fails child/IPC correctness as built. Its defects look fixable, but two of them come from Go runtime properties: no `siginfo` in `os/signal`, and a multithreaded `kill(0, SIGTSTP)`." And §8 reason 1: "the only candidate that passed every judgeable hard gate after equal fix rounds."
- Evidence:
  - `docs/g02/slice-contract.md` §9.2 (K6b, "after the round-2 fixes") and §9.3 (K6d, K6e, dated 2026-10-04, "harness coverage only, no prototype changes"). Go's last fix round is `tests/evidence/artifacts/m00-wf4/fix-go-r2.json` (round 2). The ordering rule that makes shared-mode loss a defect (K6b) and the job-control rule (K6e) both post-date it; round 3 forbids prototype changes.
  - `prototypes/go/REPORT.md` Round 2 "Remaining gaps" item 1 and `tests/evidence/g02-go-selftest.json` limitations: the producer *disclosed* the shared-mode loss before the review, as a deliberate no-duplicates choice made without K6b.
  - `tests/evidence/artifacts/m00-wf4/review2-go.json` defects[0]: "Forwarding always in modeShared would comply." The reviewer attributes the loss to a priority choice, not to a runtime limit; K6b explicitly permits documented duplicate delivery.
  - Rust satisfied K6d because its round-2 redesign happened to choose always-forward (`fix-rust-r2.json`: "Darwin limitation: … every signal is forwarded and the child sees terminal Ctrl-C twice"). Same no-siginfo situation on Darwin, opposite policy, opposite verdict.
- Why it matters: the owner reads §3/§8 as "Go cannot meet the gate without cgo." The evidence supports "Go's prototype resolved an unresolved conflict the other way, and the tie-break rule arrived after its fix round." Only the Linux Ctrl-Z/fg defect (K6e) has a plausible runtime-rooted cause, and that is marked *inference* by the reviewer (`review2-go.json` unverifiable_here).
- Suggested correction: in §3 and §8, separate (a) K6d shared-mode loss: policy choice, fixable without cgo by always forwarding (duplicates allowed under K6b); (b) K6e Linux re-stop: observed 8/9, root cause inferred; (c) K6c SIGQUIT/SIGTERM/SIGWINCH reset: non-gating stack limitation (see M2). Replace "after equal fix rounds" with "after two fix rounds each; K6b/K6d/K6e were ruled after Go's second round and Go has not had a fix opportunity under them." The "Reopen if" clause in §8 already implies this; the body should say it plainly.

### M2. K6c stack limitations are applied asymmetrically: Go's is used against it under a hard gate and in the rejection; Rust's is omitted entirely

- ADR text (§3 Go, security gate): "uncertain. … inherited-ignored SIGQUIT is reset by the Go runtime (needs cgo to fix)". §8 Go rejection: "Its signal model is limited by the Go runtime: no `siginfo`, and inherited-ignored SIGQUIT/SIGTERM/SIGWINCH are reset, so fixing that needs cgo, which costs the static, cgo-free build." Rust's §3 cell and §8 costs: no mention of any disposition reset.
- Evidence:
  - `docs/g02/slice-contract.md` §9.2 K6c: "Where a stack resets other inherited ignored dispositions (SIGQUIT, SIGTERM, SIGWINCH, SIGPIPE) … record it as a stack limitation with the production remedy … It is non-gating for G02 and goes into ADR-0002 as an input."
  - `tests/evidence/artifacts/m00-wf4/fix-rust-r2.json` limitations[1]: "Stack limitation: Rust std does not preserve an inherited ignored SIGPIPE in spawned children. The opt-out is nightly-only." `review2-rust.json` defects: "SIGPIPE ignore not preserved (confirmed with a non-Python child)" and a harness-observation defect that masks it (CPython child sets SIG_IGN itself).
  - `review2-go.json` lists Go's SIGQUIT/SIGTERM/SIGWINCH reset under "Disclosed limitations that remain … (K6c, non-gating)", not under the security gate; the reviewer's security-gate "uncertain" rests on the terminfo read only.
- Suggested correction: move Go's SIGQUIT item out of the security-gate cell into a shared "K6c stack limitations (non-gating, ADR input)" row listing Go: SIGQUIT/SIGTERM/SIGWINCH (remedy: cgo constructor) and Rust: SIGPIPE (remedy: nightly `unix_sigpipe`/manual pre-exec, not applied). Strike or qualify the §8 sentence that presents the cgo cost as a gating reason.

### M3. Rust's documented signal deviations are absent from the gate table and the costs, while the comparable Go behaviors are the headline failure

- ADR text (§3 Rust): "**pass**. 133/133 … No blocker or major. Minors are outside the contract (orphaning on SIGKILL or unforwarded signals, a thread-spawn failure path)". §8 "Costs to accept" lists none of the items below.
- Evidence:
  - Darwin double delivery: `fix-rust-r2.json` limitations[0] and summary; `review2-rust.json` refuted_claims[1] ("On darwin a terminal Ctrl-C reaches the child twice"); harness `signal_duplicates` 8/10 trials on Darwin in `tests/evidence/g02-rust-conformance.json`. Allowed under K6b only "as long as it is documented in REPORT.md"; user-visible (a Ctrl-C can interrupt a child twice).
  - Thread-spawn failure path: `review2-rust.json` defects[0] says it "breaks §4's 'waits for the child and does not exit first' on that path" and is "realistic under a pids cgroup or RLIMIT_NPROC limit". The ADR's "outside the contract" contradicts the reviewer's own wording (the reviewer rated it minor, not out-of-contract).
  - Early-SIGINT window (~0.5–1 ms, no CANCELLED JSON) and TUI left unrestored on SIGQUIT/SIGUSR1 (`review2-rust.json`), both ruled "not gated, recorded for ADR-0002" in §9.3; the ADR records neither against Rust by name (§10 lists "TUI restoration on unhandled signals" generically).
  - K6e (Ctrl-Z/fg/bg) was not probed for Rust in round 2: `tests/evidence/artifacts/g02-rust/review2/probes/` has no job-control probe; `review2-go.json` unverifiable_here explicitly says whether Rust shares the Linux job-control issue is unknown. The ADR's Rust "pass" is therefore a round-2 pass under K1–K16 only.
- Suggested correction: Rust §3 cell: "pass under K1–K16/K6a–c on both OSes. Documented deviations: terminal signals reach the child twice on Darwin (K6b-permitted); inherited SIGPIPE ignore not preserved (K6c); thread-spawn failure after spawn orphans the child (§4 error path, minor); K6d/K6e verified only in round 3 (§4)." Add the Darwin double delivery to §8 costs.

### M4. The harness's validation strength is overstated, and the independent harness review's central finding is not disclosed

- ADR text (§2): "validated against a reference implementation with injected defects: 107/107 observable mutations caught on both platforms in round 2, re-proved in round 3 (§4). It was independently reviewed twice".
- Evidence:
  - `tests/g02/SELFTEST.md` (harness 2.1.0, the version that produced every round-2 verdict cited in §3): "reference mutations caught: **120 / 120**" on each platform. 107/107 is the v2.0.0 figure (`m00-wf4/harness-r2.json`, `review-harness.json`). "Re-proved in round 3" is presented as observed while §4 says round 3 is pending.
  - `tests/evidence/artifacts/m00-wf4/review-harness.json` hard_gate_findings: "Harness discriminates realistic wrong implementations: **fail** — 21 new mutations. 1 caught … 18 missed and independently confirmed as observable defects." `harness-fix.json` then fixed 13 harness defects (v2.1.0) and lists remaining documented gaps (K16 absolute-path helpers, K11 hard-coded /tmp, repeated signals tested as two pairs only). The ADR mentions none of this.
  - "Reviewed twice": only one harness review exists (`review-harness.json`; `tests/evidence/artifacts/review-g02-harness/` is a single dir). `m00-wf3/harness-finish.json` states "No independent adversarial review". The round-3 reviewer is pending (`progress.md` line 30).
- Why it matters: "133/133 on both OSes" is the main positive evidence for Rust and for "Go passes the harness"; the owner should know the self-test mutation set was found unrepresentative once and that the fix has not yet had its own independent review.
- Suggested correction: "Harness 2.1.0: 133 checks; self-test catches 120/120 observable reference mutations per platform (SELFTEST.md). An independent round-2 review of v2.0.0 found the self-test unrepresentative (1 of 21 realistic injected defects caught); 13 harness defects were fixed in 2.1.0; the round-3 review of the added checks is pending (§4). Remaining documented blind spots: …"

### M5. The TypeScript verdict depends on two orchestrator rulings and one inference that the ADR presents as settled facts

- ADR text (§3 TS): "K8: Bun decodes argv to U+FFFD … Runtime-level environment hazards the app cannot disable … glibc only (fails on musl)". §8: "It fails gating K8 because of a Bun runtime limitation that can only be bypassed with FFI. … Following plan §3 G02 it was frozen after round 1."
- Evidence:
  - K8's FFI exclusion is a contract ruling (`slice-contract.md` §9 K8: "Reaching raw argv through FFI … counts as routing around. Record such a path as a production option"). `m00-wf3/fix-ts-2.json`: the agent "recorded it as a production option and did not take it". spec.md §10.4 only requires preservation "to the extent defined by the platform"; byte-exact argv comes from plan §3 G02 ("preserved bytes") plus K8. The owner can overrule K8's FFI clause; the ADR should say so instead of "can only be bypassed with FFI" as if that were disqualifying by nature.
  - "cannot disable": `m00-wf3/review-ts.json` defects[2]: "the program likely cannot neutralize them (inference)"; hard_gate_findings: "(inference, not tested)". No fix round tested it (TS frozen).
  - "glibc only": `prototypes/ts/build.sh` line 37 builds `--target=bun-$t` for four non-musl targets; `docs/sources/pins.json` lists `@opentui/core-linux-x64-musl`/`-arm64-musl` packages. *Inference*: Bun's `--compile` also offers `bun-linux-*-musl` targets, so this is a target choice the frozen prototype never exercised, not a stack property. Not verified here.
  - Freeze justification: `slice-contract.md` §9.1 records it, citing plan "do not keep polishing losing prototypes". In plan.md §3 G02 that sentence is the *stop condition* after a stack is chosen; applying it mid-comparison is an orchestrator interpretation. It is defensible (K8 is deterministic and unfixable within the contract: `conf-ts-r2/r3.json` 3/3 reruns) but the ADR should label it as such.
  - Consequence: TS's K6a/K14 failures in §3 and its §6 scores (2/2/1) include round-2 rulings it was never allowed to implement; Go and Rust both fixed the equivalent K6a/K14 items in round 2 (`fix-go-r2.json`, `fix-rust-r2.json`).
- Suggested correction: state that (1) the K8 failure is gating by orchestrator ruling K8 and the FFI route is an owner-level option; (2) the env-hazard "cannot disable" is a reviewer inference not tested by a fix round; (3) musl is a build-target question; (4) the freeze is an orchestrator application of a plan stop condition. Keep the rejection; make its basis explicit.

### M6. Gate verdicts stronger than, or inconsistent with, the reviewers' verdicts

- Go, Maintained dependencies. ADR: "pass, with caveats". `review2-go.json`: "**uncertain** — ultraviolet is an untagged pseudo-version (a newer pseudo-version exists), xo/terminfo is pinned to a 2022 pseudo-version (v1.2.0 exists) and has a fuzz-found panic on the linked decoder". The fuzz-found panic (also the K10 exit-2 minor) is not in the ADR.
- Rust, Practical distribution. ADR: "pass on macOS and Linux". `review-rust.json` and `review2-rust.json`: "**uncertain**" in both rounds (Windows blocked, darwin ad-hoc only, native linux-x64 not run). Go's cell says a flat "pass" on identical evidence (Windows never executed, linux-x64 emulated only, `review2-go.json`: emulated run failed rc 125). plan.md §3 G02 requires "clean Windows, macOS, and Linux machines". Either both are "pass (macOS, Linux arm64; Windows blocked; linux-x64 emulated only)" or both are uncertain.
- TS, Practical distribution. ADR: "marginal" — not one of the ADR's own verdict words (§3 defines only "uncertain"). Reviewer: "uncertain".
- Suggested correction: use one vocabulary (pass / fail / uncertain) and, where the ADR overrides a reviewer verdict, say so and why.

---

## Minor

### m1. Rust artifact sizes are round-1 figures, not the current artifacts
- ADR §3: "0.76–0.90 MB (0.39–0.46 MB gzip)"; §5: "0.76 (0.39)".
- `prototypes/rust/dist/manifest.json` and `tests/evidence/g02-measurements.json` artifact_bytes_and_sha256.rust: darwin 717,904 B (0.72 MB; tar.gz9 370,384 B = 0.37 MB); linux-arm64 806,528; linux-x64 869,648 (0.87 MB; gz 444,457 = 0.44 MB); windows 841,728. Round-1 darwin was 755,840 B (`comparison_round1_vs_round2`), which is where 0.76 comes from (`m00-wf3/review-rust.json`: "Size 0.76–0.90 MB").
- Correction: "0.72–0.87 MB (0.37–0.44 MB gzip)"; §5 "0.72 (0.37)". Go (5.2/2.0) and TS (72.7/28.0; 73–97/28–42) are correct.

### m2. TS round-2 failure list is wrong
- ADR §3: "Also fails K6a, K14 and K6c in the round-2 harness".
- `tests/evidence/g02-ts-conformance.json` (7 fail) / `-linux.json` (6 fail): `run.argv_invalid_utf8` (K8), `profile.non_regular_file` + `tui.non_regular_file` (K14), `run.k6a_pipeline_peer_not_stopped` + `run.k6a_background_script_tty` + `run.k6a_inherited_ignore` (K6a), and darwin-only `tui.resize_narrow_hides_host` (§5), which `m00-wf4/conf-ts-r2.json` classified as a harness timing race (failed 4/4 darwin, passed on Linux). No check is clause K6c.
- Correction: "K8 (1), K14 (2), K6a (3) on both OSes; plus darwin-only tui.resize_narrow_hides_host, classified as a harness timing race."

### m3. "The review found two majors" — one was producer-disclosed
- ADR §3 Go: "the review found two majors the harness did not cover".
- `prototypes/go/REPORT.md` Round 2 "Remaining gaps" 1 and `g02-go-selftest.json` limitations disclose the shared-mode loss; `review2-go.json` says "REPORT Round 2 'Remaining gaps 1' discloses the behavior, but … resolves the priority the wrong way." Only the Linux Ctrl-Z/fg re-stop was new.
- Correction: "one disclosed gap reclassified as a K6/K6b defect, and one new defect."

### m4. Evidence records do not carry the ADR's commit IDs
- ADR §2 lists Go `8bc175e`, Rust `507215e`, TS `0bd7df9`. Every conformance/measurement record has `build_commit = b44c3128…+dirty` (the G04 commit; prototypes were untracked at run time), and `g02-ts-selftest.json` has `18bb8df…`. The link from verdict to source is the artifact sha256 (manifest ⇔ record `artifact_digest`), which does hold (checked: go 20e8c5c1…/f7d38318…, rust d9838f89…/77d10192…, ts dd7a771d…/ac48d2a6…; `git diff HEAD -- prototypes` is empty).
- Also: `tests/g02/`, `tools/`, and `tests/evidence/g02-*-conformance*.json`, `g02-measurements.json` are untracked at HEAD (`git status`); `progress.md` line 31 plans to commit them after round 3. The ADR cites them as if committed.
- Correction: add one sentence: "Records carry `build_commit b44c312+dirty` (HEAD when run; prototypes were uncommitted). The binding link is artifact sha256 = `dist/manifest.json` = record `artifact_digest`. Harness, records and benchmark tooling are committed with the §4 fill-in."

### m5. Go producer self-test record is `status: blocked`, `verdict: fail` and the ADR cites it as plain evidence
- ADR §2 table: "`prototypes/{go,rust,ts}/`, REPORT.md, selftest records".
- `tests/evidence/g02-go-selftest.json`: status blocked (Windows), verdict fail with note "K6a clause for an inherited-ignored SIGQUIT … is not met" — recorded before K6c made that non-gating. `g02-rust-selftest.json`: verified/pass; `g02-ts-selftest.json`: verified/fail (round-1 commit).
- Correction: note the Go record's pre-K6c fail and that K6c supersedes it.

### m6. Harness floor stated for all latencies
- ADR §5 Limits: "Latencies include the pty and pyte harness floor, about 4 ms."
- `g02-measurements.json` limitations[1]: ~2.2 ms spawn floor for startup rows; 4.0–4.3 ms pty path for TUI rows (control rows in tables).
- Correction: "about 2.2 ms (startup rows) and about 4 ms (TUI rows)".

### m7. §6 line counts are not like-for-like
- ADR: "Go prototype 2.3k source lines; Rust 3.5k …; TS 1.4k". Recomputed: Go 2,322 non-test `.go` (tests excluded, 1,902 more); Rust 3,541 is all of `src/*.rs` including `#[cfg(test)]` modules (separate `tests/cli.rs` 1,156 excluded); TS 1,414 `src/*.ts` (tests 1,522 excluded). Rust's figure is inflated relative to Go's by its in-file unit tests.
- Correction: state the counting rule, or count Rust without `#[cfg(test)]` blocks.

### m8. Iroh evidence is registry inspection and is thinner than §8 reason 4 implies
- ADR §8 reason 4: "Iroh is native, so G06 is a configuration question rather than a second toolchain." §7 Rust row: "Not compiled."
- `prototypes/rust/REPORT.md` §10 / `m00-wf1/proto-rust.json`: 363 crates incl. `ring 0.17.14 (C and assembly; cross-compiling it is untested)`. The Rust build relies on cargo-zigbuild for musl and windows-gnu (`prototypes/rust/build.sh`). plan.md §3 G02: "published bindings are not a substitute for packaging tests." The `@number0/iroh` and iroh-go facts in §7 are correct (`prototypes/ts/REPORT.md` §Iroh, `prototypes/go/REPORT.md` §11, `docs/sources/pins.json` S22).
- Correction: in §8 reason 4 and §7, say the single-toolchain claim is untested for the ring C/asm dependency under zig cross-compilation; list it as a G06 risk.

### m9. "Embedding-versus-helper decision" is a deferral; say so and give the G02-level position
- ADR §7 "Recommendation: whatever the language, decide in G06".
- plan.md §3 G02 deliverable: "the embedding-versus-helper decision"; plan.md §3 G06: "Iroh integration versus managed helper … integration ADR". Deferring the final choice to G06 is consistent with the plan's own G06 scope, so acceptable, but the ADR should label it a deferral and state what G02 did decide: with Go a Rust helper is the only path (no usable binding); with TS the napi binding is darwin-arm64/linux only and its `.node` extraction conflicts with K11; with Rust both paths share one codebase.
- Also, plan.md §3 G02 asks for "one rejected alternative explanation per candidate"; §8 gives rejection rationales for Go and TS only. Add a short "why Rust could be rejected" (its costs list is close; title it as such).

### m10. Windows/WSL: honestly marked uncertain, but the conditionality of the recommendation should be explicit
- ADR §3 marks all three "uncertain: code review only" (matches all six review JSONs) and §11 has a G03 reopen condition. However §3 "Gate result: Only Rust passes every gate that can be judged on this host" and §8 "the only candidate that passed every judgeable hard gate" could read as a gate pass. plan.md §3 G02 lists "a viable Windows/WSL path" as a hard gate; spec.md §8.4 makes Windows/WSL non-deferrable.
- Asymmetry in the Windows cells: Go's "go-winio named pipe" is neutral while Rust's "opened with SECURITY_IDENTIFICATION" reads as a positive; `review2-go.json` notes go-winio's default is `SECURITY_SQOS_PRESENT|SECURITY_ANONYMOUS` (server cannot impersonate), i.e. at least as strict. Both lack server-identity checks, job objects, and console Ctrl-C forwarding (`review2-go.json`, `review2-rust.json`).
- Correction: add "The recommendation is conditional on G03: no candidate has executed on Windows or WSL; a G03 failure reopens D1" to §8, and make the two Windows cells list the same four items (pipe open flags, server identity, job object, console Ctrl-C) for each.

### m11. `forbid(unsafe)` wording
- ADR §6: "`forbid(unsafe)` except one query-only `sigaction`". `prototypes/rust/src/lib.rs:17` is `#![deny(unsafe_code)]` with `#[allow(unsafe_code)]` at `sigdisp.rs:58`; `main.rs:3` is `forbid`. (`unsafe-scan.log` predates the change and shows `forbid` in lib.rs.) Cosmetic; say "deny(unsafe_code) crate-wide with one allowed query-only sigaction".

### m12. §3 says verdicts are "the round-2 position" but the Go cell cites K6d/K6e
- K6d/K6e are §9.3 round-3 rulings (2026-10-04). Either cite K6/K6b (which existed at round 2) for the shared-mode loss and §4/K6a for the re-stop, or say the Go cell anticipates §4.

### m13. Statements presented as fact that the source marks as inference
- §6 "OpenTUI's selected row was drawn white-on-white": `review-ts.json` defects[4] "likely invisible … (inference from SGR semantics; observed only through pyte cell attributes)".
- §3 Go "Ctrl-Z then `fg` re-stops the job (8/9)": observed; the `kill(0, SIGTSTP)` cause in §3 Gate result is an inference from a debug build (`review2-go.json` unverifiable_here).
- Correction: keep the observations, mark the causes as inferred.

### m14. Canary hygiene (for the owner, not an ADR defect)
- `tests/evidence/artifacts/CANARY-REDACTION.md` says historical records were redacted. Re-check: only `g02-go/review/probes/profile-probes-darwin{,.full}.log` still match a full-value pattern, and the match is the reviewer-crafted key *name* `HEIMDALL_CANARY_keyname_zz` (allowed; `review-go.json` defects). No fixture value remains. The ADR could cite CANARY-REDACTION.md in §2.

---

## Verified as correct (spot checks that passed)

- §5 numbers vs `g02-measurements.json` tables: all p50/p95, RSS (MiB), 300 s idle CPU (0.3367/0.0358/0.0638), Go and TS sizes, "Linux x86-64 under emulation", cold start not measured, spec §15.1 budgets (spec.md §15.1 table) — match.
- §2 environment: Mac17,6 / M5 Max / 64 GiB / macOS 27.0 (26A428) / Docker 29.8.1 / linuxkit 7.0.14 / Go 1.27.1 / rustc 1.99.0 pinned in build.sh / Bun 1.4.2 / Bubble Tea v2.0.10 / Ratatui 0.30.2 + crossterm 0.29.0 (published 2025-04-05, pins.json) / OpenTUI 0.5.14 (335 versions) — match the records and pins.
- §2 commit IDs exist and `git diff HEAD -- prototypes` is empty (working tree = committed round-2 source).
- §3 Go: harness 133/133 both OSes; 8/8 and 8/9; hardened-runtime ad-hoc signing; MIT/BSD-3 with notices not shipped; ultraviolet untagged, xo/terminfo 2022 pseudo-version — match `review2-go.json`, `conf-go-r2.json`.
- §3 Rust: 133/133 on reviewer's bit-identical rebuild across checkout paths; notices file ships (`dist/manifest.json` notices); strace findings; UCRT imports (REPORT §3); K16 fix bypassed crossterm input/size on Unix after `tput` on Linux (`fix-rust-r2.json`).
- §3 TS: K8 cause, BUN_OPTIONS/BUN_INSPECT/BUN_BE_BUN/OTUI_STDIN_LOG, LGPL JavaScriptCore/tinycc, musl probe rc 255, 73–97 MB / 28–42 MB — match `review-ts.json` and `g02-measurements.json`.
- §7 Iroh facts (iroh 1.3.0, 363 crates, iroh-go "Highly Experimental"/cgo/musl-only, `@number0/iroh` 1.1.0, no darwin-x64, 13 MB `.node`) — match REPORTs and pins.json.
- §1/§8: plan.md §3 G02 "Do not present a prior Go preference as current approval" is honored.

## What the owner still needs that the ADR does not give

1. That Go's gate failure is partly a post-hoc tie-break (M1) and that a Go fix is "forward always" plus a job-control fix, not cgo.
2. Rust's own user-visible deviations: double terminal-signal delivery on macOS, SIGPIPE ignore not preserved, orphan on thread-spawn failure, K6e unverified until §4 (M3).
3. That the harness's discriminating power was independently found weak once and the fixed version has not yet been independently reviewed (M4).
4. That the TS rejection hinges on K8's FFI clause (an orchestrator ruling the owner may overrule) and on an untested inference about Bun env hooks (M5).
5. Risks on the Rust side not surfaced in §8: ring C/asm under zig cross-compile untested (m8); crossterm still used for Windows input/size (REPORT §7, `review2-rust.json`), so "crossterm only for rendering output" is Unix-only; project license still UNLICENSED placeholder for every candidate (`review2-rust.json`).
6. That no candidate has run natively on Windows, WSL, or linux-x64; the recommendation is conditional on G03 (m10).
