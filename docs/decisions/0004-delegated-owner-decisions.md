# ADR-0004: Decisions taken under the owner's delegation (2026-10-31)

**Status:** accepted · **Date:** 2026-10-31 · **Decided by:** the orchestrator, under the owner's
explicit delegation: "I trust your judgement on all of these and the rest of the decisions.
Continue until all open items are done and the product is ready for release."
**Scope:** every owner decision and owner question that was open on 2026-10-31 (ADR-0002 §10,
ADR-0001 §5–§6, ADR-0003 E6/E8, `docs/research/g03-windows-wsl.md` §6.1 E-3,
`docs/research/g04-managed-credentials.md` §9, `progress.md` "Still open from the owner").

The delegation covers decisions. It does not create physical capabilities the orchestrator lacks:
an operator at a locked console, an elevation (UAC) consent, an Apple Developer membership, a
disposable 1Password account. Items that need one stay `blocked` on that exact input, as
AGENTS.md requires. Publishing release packages remains a separate authorized action (plan §10.3).

## 1. G02: language, TUI and distribution (ADR-0002 §10)

| Item | Decision | Reason |
|---|---|---|
| **D1** | **Rust + Ratatui.** crossterm for output on Unix and for Windows input; the hand-written Unix key decoder from the prototype may be reused after review | ADR-0002 revision 3: all four scorings lean Rust; Iroh stays in V1 (Q-A) |
| Q-A Iroh scope | **Iroh stays a V1 target** (spec §3 default). G06 decides embedding versus a supervised helper. A G06 failure produces the recorded transport-specific preview/deferral spec §3 allows, never a fabricated claim | Spec §3; keeps the comparison where it was scored |
| Q-B Windows batch targets | **`run` must launch `.cmd`/`.bat`** (npm-installed agent CLIs are batch shims on Windows). Arguments use std's escaping; a batch script path containing `%`, `!` or another character `cmd.exe` interprets is refused with exit 127 and a message (slice-contract §9.7 M01 input). Native tests required | Agent CLIs are first-class consumers (spec §1.1, G03 E-3) |
| Q-C D4 completion | **Sufficient for D1.** The remaining G03 rows block only their own claims and continue in M04 | Plan §1.3: gates feed decisions; platform gaps stay blockers |
| Q-D shared uncertain gates | **Accepted as open for both stacks; must close before any stable-release claim** (M08-T03/T04). Not closing them makes the release `preview-only` (plan §10.3) | Same for both candidates; does not separate them |
| Q-E TUI library | Ratatui now; replaceable later only by a new ADR | Keeps the T3 finding attached to the library |
| Q-F macOS release builds | **darwin artifacts are built and signed on a macOS host.** A Developer ID signature and notarization need the owner's Apple Developer membership (G04 D3); until then darwin artifacts carry ad-hoc signatures plus documented provenance, and the release cannot claim a signed macOS build | Spec §15.3: claim only signing actually produced |
| Q-G Iroh on Windows | Decided inside G06 (M06): first remove or avoid the wildcard bind through iroh/netwatch configuration or a scoped patch; if that is not possible, run the probe while the owner can watch for and decline a firewall prompt | No firewall change, no rule added |
| D3 (a)–(l) | **All rulings stand**, including (k) contract §9.7 and (l) the X2 rubric | Recorded reasons in slice-contract §9–§9.7 and x2/RESULTS.md §5.1 |

## 2. G04: managed credentials (g04 research §7, §9)

| Item | Decision |
|---|---|
| Managed recipe | **Recipe B1** (g04 §7): per-environment protected working key `K_env` in a Heimdall-supervised signer; a separate per-user issuer key `K_ca` in its own issuer process; account-level `cert-authority,principals="hm:<destination-id>:<account>"` enrollment; certificates with one principal per destination/account, `valid_before = min(grant deadline, cutoff)`. Recipe A (managed key without certificates) ships only as a labelled fallback for destinations without OpenSSH user-certificate support. Recorded as ADR-0005 |
| Issuer under lock (owner D1 of 2026-10-06) | New grants may be created while locked, so the issuer signs from memory while the desktop is locked. `K_ca` is persisted encrypted in the platform store and loaded at login; the same-user issuer boundary is disclosed (spec §7.3) |
| P5 further real-store runs (D4 coverage) | **Covered by D4**: each run creates exactly one CTK identity and deletes it by hash, with the store compared before and after. This also covers the 2026-10-31 v3 run retroactively |
| Owner-at-console lock probes | The orchestrator may lock the macOS screen (and the Windows PC) itself **only after the console has been idle for at least 15 minutes**, so no session in use is interrupted; the owner unlocks whenever they return. Logout and reboot probes stay `blocked` on the owner, because they end running applications |

## 3. G03: Windows and WSL (g03 §6.1 and blocked rows)

| Item | Decision |
|---|---|
| E-3 upstream set | **Heimdall-held managed credentials (G04) are the Mode B path with real scope. The system agent and 1Password are filtered-convenience upstreams**, labelled as such in results and setup (no isolation or scope claim through them) |
| Disposable WSL distribution (P-B08/09/10) | **Authorized:** create one disposable distribution with `wsl --import` in the task scratch directory, and `wsl --terminate`/`--unregister` **that distribution only**. Never `wsl --shutdown`, never touch the owner's existing distributions |
| X4 Windows secure stores (DPAPI, CNG Software KSP, TPM Platform KSP) | **Authorized:** create uniquely named test keys and delete them by name in the same run; DPAPI protect/unprotect of test data only. Inventory before and after must match |
| Second Windows account (P-W05, P-W06 cross-user, P-B11) | Authorized in principle (a disposable local non-admin account, deleted afterwards), but creating it needs one elevation consent at the console: **blocked on the owner** |
| Disposable 1Password (P-W10), disposable Windows host (P-W11) | **Blocked on the owner** (an account / a machine the orchestrator does not have) |
| Console-only observations (P-A06 UAC prompt, P-W07 interactive Ctrl-C/resize) | P-W07 runs through pseudoconsoles as X1 did; P-A06's "no UAC prompt observed" needs a human: **blocked on the owner** |
| E6 Windows OpenSSH baseline | **The supported baseline is the in-box Windows OpenSSH client** of the declared Windows build (observed 9.5p2 on Windows 11 26300). The GitHub Win32-OpenSSH MSI (Preview-tagged) is `supported-with-limitations` only where a probe ran on it, never a requirement |

## 4. G01 and evidence conventions

| Item | Decision |
|---|---|
| Baseline pain-point list | Not invented. **The G01 baseline worksheet is filled from observed runs of the five template workflows** (ADR-0001 §6) on the owner's machines with a correctly configured OpenSSH/provider setup, counting real steps and prompts. Owner-described pain points remain optional input |
| Record that ran everywhere except one platform | **The lowest-row rule stands** (tests/evidence/README.md): the record is `blocked` with the missing platform named; per-platform rows and matrix cells for platforms that ran may be `verified` |
| Synthetic canary-format strings in test inputs | **Allowed** in fixtures, test inputs and harness assertions. A canary value appearing in program output, logs, arguments, artifacts or redacted evidence (other than the fixture file that defines it) is a defect |
| E8 third-party snapshots | Keep snapshots of permissively licensed sources (OpenSSH manuals, RFCs, man7, and similar). **Replace proprietary vendor text snapshots with their hashes plus archive URLs** in the tree before the release candidate (M08-T04); earlier commits keep them, as published history is not rewritten |
| G01 version floors | Set provisionally from the platforms actually tested (ADR-0001 §5): macOS 27 arm64; Windows 11 26H2 x64 with the in-box OpenSSH; WSL2 with Ubuntu 24.04; Ubuntu 24.04 and Debian 13 x86-64; Linux arm64 pending a native host. Re-confirmed on clean machines in M08 |

## 5. What this does not decide

- Authority semantics the spec fixes (scope, deadlines, revocation, custody) are not changed here.
- Publishing packages, buying infrastructure, changing a live server's authentication, and
  creating accounts on third-party services remain out of scope without a specific owner action.
- Each decision above can be reopened by the owner at any time; the affected ADR then changes.
