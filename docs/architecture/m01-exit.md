# M01 exit record — deterministic core and lifecycle substrate

**Date:** 2026-11-01 · **Build:** `b89743aeccc06cafca85dce6783cc99e3b7f4903` ·
**Decided by:** the orchestrator, under the owner's delegation (ADR-0004).
**Decision:** M01 exits. Every M01 claim that can be decided on the available platforms is
`verified` at this build. The remaining rows are `blocked` on named inputs that M01 does
not claim: native OS sleep, logout and reboot, which are M04 scope (m01-plan.md §3), and a
disposable second Windows account (ADR-0004 §3). Their records stay `blocked` under the
lowest-row rule (tests/evidence/README.md).

## 1. Exit evidence (plan §5 M01; m01-plan.md §3)

Source: `tests/evidence/m01-exit-claims.json`. Artifacts are under
`tests/evidence/artifacts/m01/exit-b89743ae/`.

| Exit claim | Status | Rows |
|---|---|---|
| A06/A07/A08/A19/A29 model and local-runtime variants pass | `blocked` | macOS arm64 ✓, Linux x86-64 ✓, Windows 11 ✓; native sleep/logout/reboot (M04) blocked; Windows second account blocked |
| Revocation races fail closed | `verified` | macOS ✓, Linux ✓, Windows ✓ |
| No external side effects needed to verify core semantics | `verified` | macOS ✓, Linux ✓, Windows ✓ |
| Crash recovery cannot reset a deadline, revive a pause, or change environment identity | `verified` | macOS ✓, Linux ✓, Windows ✓ |
| Time rule of ADR-0005 §3.6 holds under sleep, restart, reboot and rollback | `blocked` | macOS ✓, Linux ✓, Windows ✓ (model and local-runtime); native sleep/logout/reboot (M04) blocked |
| G08 contract baseline recorded (ADR-0006 revision 2) | `verified` | macOS ✓ |
| Model portions of G05/G09 | `verified` | macOS ✓, Linux ✓, Windows ✓ |
| N06 exit cases (m01-plan U10 r2.1) | `verified` | macOS ✓, Linux ✓, Windows ✓ |

The case records:

| Record | Status | Notes |
|---|---|---|
| `m01-a06-idempotency` | `verified` | All three platforms |
| `m01-a07-revocation` | `verified` | All three platforms |
| `m01-a17-local-restart-recovery` | `verified` | All three platforms; restarts are in-process, not native process crashes |
| `m01-a19-operations` | `verified` | All three platforms |
| `m01-a08-time` | `blocked` | Platform rows verified; the native sleep/logout/reboot row waits on M04 |
| `m01-a29-local-hostile-input` | `blocked` | Platform rows verified; the cross-user Windows pipe row waits on the second account |

## 2. Native runs at the exit build

| Platform | Run | Result |
|---|---|---|
| macOS 27.0.1 arm64 | `bash tools/validation/check.sh`, all 9 steps | exit 0; 735 passed, 0 failed, 2 ignored (child-process re-exec entries) |
| Linux x86-64 (devbox, label linux-a) | `tests/native/m01/run-linux.sh`: 22 test binaries plus the e2e suite through the CLI | exit 0; 670 passed, 0 failed, 2 ignored; canary scan 0 |
| Windows 11 (non-elevated) | `tests/native/m01/run-windows.sh`: 22 test binaries plus the e2e suite through `heimdall.exe` | exit 0; 629 passed, 0 failed, 1 ignored; canary scan 0; no leftover pipes or processes |

The second Linux host, vps1-edge, was not used. The owner's Tailscale SSH policy refuses
the configured user (ADR-0006 §13.6 item 9).

## 3. Independent review

All reviews were by Codex GPT-6.1 Sol, independent and read-only, each in a separate
worktree. Their records are under `tests/evidence/artifacts/`.

| Review | Commit | Verdict | Findings → resolution |
|---|---|---|---|
| Design review (`review-m01-design/review.md`) | f5616784 | proceed after fixes | F01–F10 → design-fix round, ADR-0006 rev 2 |
| Design re-review (`review-m01-design/round2/review.md`) | f9ed3454 | proceed after fixes | N01–N06 → §13.4–§13.5 |
| Code review areas A/B/C (`review-m01-code/area-{a,b,c}.md`) | 93c60d3b | fix first | A01–A08, B01–B09, C01–C03 → §13.6–§13.7 |
| Rounds 2–7 (`review-m01-code/round{2..7}.md`) | 10414f10 … 250a029d | fix first | R01–R09, S01–S05, T01–T02, U01–U02, W01–W02 → §13.8–§13.19 |
| Round 8 (`review-m01-code/round8.md`) | b89743ae | **ship M01** | none |

Automated security reviews of two pushed commits found four issues: one at 6230acf9 (the
cleanup guard) and three at 8d17ace9. The orchestrator had already ruled on one of the
three, the in-flight round, in §13.18 item 2. All four were fixed under §13.17–§13.18
and re-reviewed in rounds 7 and 8.

## 4. Known limits carried forward

Each item names the ruling it comes from and the milestone that takes it over.

* **Trusted synchronized time.** A clock that reports itself synchronized while wrong
  by d can admit up to d past the true bound. This is a named limitation test (§13.15
  item 5). Native evidence that the synchronization signal is reliable belongs to
  M04/G09.
* **At-least-once cleanup.** Competing processors may call an adapter's revoke more than
  once (round 8). That is safe for idempotent revocation. Real adapters must tolerate it.
* **Adapter call timeouts.** A preparation that hangs after its effect gets its cleanup
  only at restart in M01. Real adapters (M02/M03) need bounded call timeouts (§13.20
  item 3).
* **Configurable revocation cap.** If the cap becomes configurable (M08), it must reach
  `Operations` through `OperationsConfig` before recovery (§13.18 item 5).
* **Windows handle inheritance.** Handles beyond the null standard handles can still be
  inherited by the detached runtime. An explicit handle-list spawn is M04 work (§13.9
  item 7).
* **Windows state-directory ACL.** M01 makes no claim that it is owner-only. An explicit
  check is M04 work (§13.12 item 4).
* **Crash evidence.** All restarts here are in-process reconstructions. Native
  process-crash and lifecycle evidence is M04 and M08 work.

## 5. Physical owner inputs still open

ADR-0004 §5 records these inputs. They block only their own rows:

* an operator at the console for the logout and reboot probes;
* one elevation, to create a disposable second Windows account;
* a disposable 1Password account and a disposable Windows host;
* an Apple Developer membership;
* a Tailscale SSH policy that lets the configured user reach vps1-edge (optional);
* for M02:
  * a disposable macOS user account;
  * Windows Developer Mode, or one elevation (ADR-0007 B10).

## 6. Next

M02, the existing-access vertical slice (plan §5 M02; `docs/architecture/m02-plan.md`;
ADR-0007). Wave 0 (U0 + U0b phase 1) starts after the design review rounds close.
