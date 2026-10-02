# ADR-0001 — Initial release contract (G01 draft)

**Status:** proposed — draft frozen as the M00 working baseline; version floors and
the baseline worksheet are `blocked` (see §5, §6). Owner confirmation is needed
only where marked.
**Date:** 2026-10-02 · **Gate:** G01 · **Task:** M00-T06
**Affects:** R-QU-01, R-QU-07, R-DI-08 and, through scope, every requirement.

## 1. Context

spec.md v0.1.0 defines V1 obligations; plan.md v0.1.0 defines gates and
milestones. G01 must make scope, support labels, defaults, and the baseline
explicit before production architecture is locked. Nothing in this ADR is
evidence that anything works.

## 2. Decision: release tiers

Releases are named by what has been verified, never by milestone number alone
(plan §2.3):

| Tier | Requires | May not claim |
|---|---|---|
| Existing-access preview | M01–M02 exit evidence | managed/unattended access, lock continuity |
| Managed-work preview | M03–M05 exit evidence on the declared matrix | controller-independent runner, Iroh |
| Cross-environment beta | M06–M07 exit evidence | stable public-contract guarantees |
| Stable V1 candidate | M08–M09 and every applicable required case (spec §17) executed | anything the claim audit (A36) has not passed |

A required capability that fails its gate blocks the stable-V1 label; it is not
converted into documentation-only support (spec §3.1). The only scope-eligible
deferral is the transport-specific Iroh flow (spec §3.1, G06), and only through a
recorded ADR.

## 3. Decision: V1 scope is spec §3.1 verbatim

The V1 scope is the spec §3.1 table without modification. For tracking, each
row maps to its gate and accountable milestone:

| Capability (spec §3.1) | V1 | Gate(s) | Milestone |
|---|---|---|---|
| Existing-access adoption, ordinary SSH/Git | required | G01, G08 | M02 |
| CLI + TUI on shared operations | required | G02, G08 | M02, M07 |
| Native agent + 1Password reference integrations | required (declared matrix) | G01, G03 | M02 |
| ≥1 end-to-end managed execution-credential recipe | required | G04 | M03 |
| Trusted-project automatic activation | required | G05 | M05 |
| Desktop/vault-lock continuity (managed recipe) | required | G04, G09 | M03, M04 |
| Windows native, WSL Mode A, scoped opt-in WSL Mode B | required, real hosts | G03 | M04 |
| Linux and macOS workflows | required | G01 | M04 |
| Remote Linux runner independent of controller | required | G07 | M06 |
| Local Linux-container binding + expiry | required | G03/G09 (platform parts) | M04 |
| Multiple routes + bastion flow | required | G06 (routes), G09 | M04, M06 |
| Iroh/Pigeons reference flow | V1 target, G06-gated | G06 | M06 |
| Operation IDs, status/events, cancellation, idempotent preparation | required | G08 | M01, M07 |
| Delegation model + one tested narrower binding | required | G05, G09 | M05 |
| SDKs, MCP adapter, hosted-account enrollment | later | — | — |
| Managed Windows remote runner, full OCI, multi-owner | later | — | — |

## 4. Decision provenance: confirmed vs proposed

Confirmed by the owner (spec §2.1): **C01–C13**. They are not reopened here.

Proposed defaults (spec §2.2), each with the gate that validates or revises it.
None is confirmed by the owner; changes require an ADR with reasons and tests.

| ID | Draft default | Validating gate / evidence | Status |
|---|---|---|---|
| P01 | Small supervised per-user runtime | G03 (Windows endpoint/process shape), G04 (store availability), M01-T05 | proposed |
| P02 | Single owner; per-environment identity/authority | G07 | proposed |
| P03 | Environment-level convenience + explicit bindings for concurrent work | G05 | proposed |
| P04 | 12-hour max window for new trusted work, disclosed at setup | M09 normal-week study (plan §8.4) | proposed |
| P05 | Opt-in automatic access at first trust; silent same-authority renewal | G05, A02 | proposed |
| P06 | Graceful expiry for dedicated sessions; owned masters stop admissions or close | G09 (A23); preliminary mechanism experiments in M00 | proposed |
| P07 | OpenSSH as reference client; no new SSH client | adapter conformance (M02) | proposed |
| P08 | Transactional local store; SQLite starting candidate | M01-T03 + Windows file-semantics tests (M04) | proposed |
| P09 | No telemetry, no public relay without opt-in, no auto plugin install | A26, A33 | proposed |
| P10 | Human-editable TOML + generated JSON schema | M01, G08 | proposed |

Gated technical choices that are **not** settled: language/TUI (G02, owner
decision), session-default number, storage engine, OS floors, managed credential
recipe (G04), local IPC (G08), remote control transport (G07).

## 5. Platform and version floors — blocked

Initial validation targets (spec §3.2): Windows x86-64, WSL2 Linux x86-64,
macOS arm64, Linux x86-64 and arm64. Floors are chosen only from clean-machine
tests (plan §3 G01), so none are declared yet.

| Target | Floor | Status | Blocked on |
|---|---|---|---|
| macOS arm64 | TBD | blocked | clean-machine install test of a selected-stack build; current dev host observed: macOS 27.0, OpenSSH 10.3p1 (observation, not a floor) |
| Linux x86-64 / arm64 | TBD (distribution list TBD) | blocked | real Linux desktop/user-session and headless hosts; container runs are supplementary only |
| Windows x86-64 | TBD (Windows build + Win32-OpenSSH version) | blocked | native Windows host |
| WSL2 x86-64 | TBD (WSL version + distributions) | blocked | native Windows host with WSL2 |
| 1Password SSH agent | TBD | blocked | owner-authorized test account/vault with disposable keys on each OS |

## 6. Baseline-friction worksheet — blocked on owner input

The baseline (plan §3 G01, §8.3) is a correctly configured OpenSSH + provider
setup per environment, with each required step and prompt recorded. It must use
the owner's real (redacted) pain points; inventing them is prohibited.

Template rows (to be filled from observed runs):

| Workflow | Environment | Steps (count, list) | Human prompts | Interruptions by class¹ | Evidence |
|---|---|---|---|---|---|
| `ssh lab-server` after reboot | | | | | |
| Git push over SSH from project | | | | | |
| Long agent job across desktop + vault lock | | | | | |
| WSL Git over SSH | | | | | |
| Remote runner onward SSH after laptop leaves | | | | | |

¹ new authority / provider-required human action / unrecoverable error / avoidable ceremony.

**Needed from owner:** redacted descriptions of the recurring pain points and
which machines/providers form the baseline. Status: `blocked`.

## 7. Support labels

Exactly the spec §3.3 labels: `verified`, `supported-with-limitations`,
`experimental`, `unsupported`, `not-tested`. Every label in
`docs/compatibility/matrix.md` cites versions, observation time, test IDs and
limitations. Claims use `docs/templates/claim.md`.

## 8. Release-time checks not yet performed

Project name / package-name availability and license selection are explicit
release decisions (spec §15.3); they are `not_started` and are not needed before
M08. Nothing is published without separate owner authorization.

## 9. Consequences and reopen conditions

- Reopen §3 only through a spec amendment (mandatory scope) or the G06 deferral
  process (Iroh only).
- Reopen §4 rows when the validating gate produces contrary evidence.
- §5 and §6 close when the blocked inputs exist; until then no platform is
  labeled beyond `not-tested`.
