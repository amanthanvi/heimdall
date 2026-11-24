# ADR-0015: The Iroh transport's release scope in V1

**Status:** accepted (2026-11-23) · **Milestone:** M06 (T04), gate G06.
**Decided by:** proposal of the M06 integrator at the M06 exit; the orchestrator adopted option (c) on 2026-11-23 (ruling E2). This is spec §3.1's recorded release-scope decision for the Iroh transport.
**Requires:** spec §3.1 ("An Iroh research failure requires a recorded release-scope
decision; it may produce a named transport preview or defer the integration, but never a fabricated assertion that it is
supported"), plan §2 ("a named experimental transport module only through the spec's explicit scope process") and plan §3 G06's
failure action.
**Inputs:** ADR-0012 §1, §2.2, §2.6, §2.7 and §12; m06-plan §3 (A26, the `n0-public` rows, the G06 closure row), §5 and §7;
the M06 exit records (`tests/evidence/m06-*.json`, written at the exit build).
**Amended:** ⟨2026-11-24⟩ the M06 exit review's finding M06-X-R03 (`tests/evidence/artifacts/review-m06/exit.md`): what a
build without `iroh` refuses, narrowed in §1 and §3 to what the build does. The add-time refusal is follow-up M06-F7.

## 1. What the evidence supports today

| Question | State at the M06 exit | Source |
|---|---|---|
| The integration itself | Built: `heimdall-transport-iroh` (iroh `=1.4.2`, `tls-ring`, no portmapper), the supervised `transport serve` child, the route helper's Iroh leg, exposure policy and admission. Behind the cargo feature `iroh`, off by default. Without it the `transport` forms refuse `driver_unavailable`; route commands accept and record Iroh legs, and using such a leg is recorded `driver_unavailable` and failed over (an all-Iroh route refuses `driver_unavailable`; contract 6.6) ⟨2026-11-24, M06-X-R03⟩. Direct and jump routes are unaffected | `crates/heimdall/Cargo.toml` `[features]`; ADR-0012 §1 |
| A26 on loopback (routes, serve restart, failover before the identification line, exposure refusals, host pins, removal) | Runs in `e2e_exit_m06_iroh` on loopback only | the A26 record (status from the exit run) |
| Relay through a private relay | Mechanism rows in containers (`iroh-relay --dev`); the devbox reaches it relay-only by construction | the A26 record (status from the exit run) |
| `n0-public` (n0's relays and lookup) | The bounded capture row has not run, so the profile stays outside V1 (ADR-0012 §2.2) | m06-plan §3 |
| A direct path across real NATs | Deferred: needs an authorized public UDP endpoint (m06-plan §5, §7) | m06-plan §7 |
| Windows | No path qualified: W1 (loopback bind trace) not qualified without a capture tool or admin rights; W3 and W4 not run; W4 needs the owner at the console (ADR-0012 §2.6) | ADR-0012 §2.6 |
| A headless persistent endpoint | Unavailable in V1: §2.7 not adopted. A serving endpoint needs a verified store (the macOS Keychain; a Linux desktop Secret Service) | ADR-0012 §2.7 |
| Supply chain | iroh's tree passes the RustSec gate; one recorded licence exception (`webpki-roots`, ADR-0014 §4.6) | `tools/validation/check.sh` `audit`, `iroh-check` |

So the transport works in the conditions tested (loopback, a private relay in containers), but none of the things that make it
useful to a typical owner is qualified: a public relay, a real NAT, Windows, or a headless server.

## 2. The options

| Option | What ships in V1 | For | Against |
|---|---|---|---|
| **(a) Opt-in supported feature** | Release builds enable `iroh`; Iroh routes carry a support label on the qualified platforms | The full V1 target of spec §3.1 | Not allowed by the evidence: no platform has a qualified path beyond loopback and a private relay; ADR-0012 §2.6 gives a path with no evidence no label; spec §3.1 forbids a fabricated assertion |
| **(b) Named preview in the release build** | Release builds for macOS and Linux enable `iroh`; every Iroh form says "Iroh transport preview: not supported"; Windows builds without it | Users can try it; the feature stays exercised | Every V1 binary links iroh's network stack (a larger attack surface for everyone, including owners who never enable it); M08's 72-hour run, artifact inventory and licence review then cover the feature; a preview inside the default artifact is easy to read as support |
| **(c) Out of the V1 default build; a named preview from source** | Release artifacts are built without `iroh`. The preview exists only as a source build with `--features iroh`, documented as "Iroh transport preview", with the limits of §1 | No iroh code in any shipped binary; nothing to label wrongly; M08's artifacts, soak and licence review stay smaller; direct and jump routes are complete either way (G06's failure action); the code and its tests stay in the tree, so a later release can promote it | Owners who want Iroh must build from source; the preview gets less use |

## 3. Decision: (c)

- **V1's release artifacts are built without the `iroh` feature.** Their `transport` forms refuse `driver_unavailable` as today, and the
  refusal's message says the transport is a preview available only in a source build. ⟨2026-11-24, M06-X-R03⟩ Route commands
  (`route add --iroh`, with its attended exposure consent) accept and record an Iroh leg in any build; in a build without `iroh`
  using that leg is recorded `driver_unavailable` and failed over to the route's other legs, and a route whose legs are all Iroh
  refuses `driver_unavailable` with the same preview message (ADR-0006 §18.10, ruling Q-B). Nothing leaves the host. Refusing
  the add itself in such a build is follow-up M06-F7, a contract change for revision 7 (U3).
- **The preview** is a source build with `--features iroh`, named "Iroh transport preview" in its help, `doctor` and docs. It keeps
  every default of ADR-0012 §2 (no public infrastructure, loopback bind, each widening a recorded local decision), offers only the
  `none` and `custom` profiles, and carries no support label on any platform.
- **Gates stay on:** `check.sh`'s `iroh-check` step and the feature-enabled A26 targets keep running on macOS and Linux, so the
  preview does not rot.
- **What would promote it to (a) in a later release:** the `n0-public` capture row (if that profile is wanted); a direct path across
  real NATs with an authorized public UDP endpoint; the Windows W1, W3 and W4 paths and the in-box OpenSSH journey; and a verified
  headless store (§2.7) for server use. Each is a recorded scope change, not an amendment of this decision.
- **What this changes elsewhere:**
  - `docs/compatibility/matrix.md` and `docs/user/limitations.md` say Iroh is "preview, source build only", with no platform
    row and no support label;
  - M08's release artifacts stay on default features (its deny self-test may keep `--features iroh`, to check the source build's
    licences);
  - revision 7's command tree keeps the `transport` and Iroh route names, and a release build reports the capability unavailable
    (`driver_unavailable`, whose message names the preview and how to build it; the code and reason are unchanged).

## 4. Consequences

- G06 closes as a recorded transport-specific preview (source build only), not as support.
- A26's private-relay container rows are `deferred_with_decision` under this ADR; none of them gates a release claim. The
  `n0-public` capture stays `blocked` on the owner's authorization, and the Keychain dialer persistence journey on B3.
- A26's release rows are the preview's evidence only; no A26 row widens a release claim.
- Native/direct and bastion paths are complete without Iroh (plan §3 G06's failure action).
