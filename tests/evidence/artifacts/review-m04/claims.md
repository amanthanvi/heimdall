FIX FIRST — M04-CL-R01, retained non-native results still return native claims on replay.

Reviewed `8f18a6bd..212f290a` against I-28, ADR-0008 D12, ADR-0010 §2 and ADR-0009 §2.1.

## Findings

1. **M04-CL-R01 — High, blocking under ADR-0009 §2.1.** An ordinary same-key
   retry returns an unsupported attestation from a durable operation record. A Mode B
   or container ensure prepared before I-28 on a qualifying host can have stored
   `new_signing_expiry: signer`, bounded remote revocation and claim-table evidence.
   `respond_work` returns that payload as `ACCESS_READY` with `next: use_binding`.
   It bypasses the gate and can keep presenting those guarantees for the lifetime
   of the retained result, including after an upgrade. The scratch probe seeded one
   pre-I-28 claim into a real container fixture's settled result and confirmed that
   the same request returned the claim, its evidence and the same binding ID.
   Preserve the original history and idempotency. In the current ensure response,
   classify the binding's environment from the store and strip positive claim
   fields and claim-table evidence for non-native or unclassified environments.
   Reuse `without_claimed_values` for enforcement and handle lock and remote
   revocation in the same step. The committed tests exercise new outcomes, so add
   a retained-result replay regression. `crates/app/src/operations.rs:9125`,
   `crates/app/src/operations.rs:9175`, `crates/app/src/operations.rs:13598`.

2. **M04-CL-R02 — Low, nonblocking.** Endpoint classification defaults to native
   for an absent managed-environment row or an unhandled realization.
   `GrantTerms::default()` also produces native. An unclassified grant reaching
   this lookup could therefore become claim-eligible on a qualifying host.
   Current production admission rejects missing foreign rows, and normal removal
   retains the row and its realization. I found no ordinary live path to this
   fallback. Require an explicit match to the runtime's own environment for native
   and fail closed for every other missing or unrecognized placement. Require
   explicit endpoint construction in grant terms. The existing missing-terms test
   covers an absent cache entry. Add a missing-foreign-row case for classification.
   `crates/runtime/src/managed_store.rs:320`,
   `crates/adapters/src/managed/prepare.rs:48`,
   `crates/store/src/ext_m04.rs:128`.

3. **M04-CL-R03 — Medium, nonblocking for endpoint classification.** Mode A is
   correctly native under ADR-0010 §2. Its Git setup uses System32's in-box
   `ssh.exe`, while runtime claim facts prefer a configured `[clients].ssh`.
   On a qualifying Windows release, a configured 9.5p2 can justify claims even
   when the in-box client used by Mode A has another version. Where a claim covers
   Mode A, judge it against verified in-box client facts and withhold it when those
   facts are unavailable. Use a two-client fixture with distinct versions. The
   new WSL fixture covers Mode B only. This is inherited client-selection behavior
   and was assessed from source. `crates/wsl/src/host.rs:68`,
   `crates/runtime/src/service.rs:2625`, `crates/localenv/src/clients.rs:350`.

4. **M04-CL-R04 — Medium, nonblocking wire compatibility.** ADR-0006 §9 allows
   an optional field and a new variant on a non-exhaustive enum at major 1, and
   the regenerated schema matches the Rust model byte for byte. The old typed
   reader accepts the optional `endpoint_kind` key and rejects the new
   `source` value. Consequently, an older typed client can reject an otherwise
   successful new-runtime result for a Mode B or container binding. If mixed
   versions are supported, put the reason in an optional field older clients
   can ignore, or negotiate the new variant before emitting it. The baseline
   decoder probe confirmed the rejection. A mixed-version fixture would cover
   delivery, while schema regeneration alone cannot. `crates/contract/src/managed.rs:316`,
   `crates/heimdall/src/activate_cmd.rs:181`,
   `schemas/public-api/envelope.ensure.schema.json:1143`.

5. **M04-CL-R05 — Low, nonblocking until a lock-continuity claim ships.**
   `lock_continuity_from` feeds host-level adapter advertising. A fresh prepare
   also checks the binding's report, but a same-environment follower of an
   ordinary request skips prepare. Its commit minimums omit `required.unattended`.
   With a future matching native lock row, a Mode B follower requiring unattended
   access could pass adapter selection and commit without a verified binding
   outcome. The compiled table has no lock-continuity row today. Require
   binding-scoped verified continuity at follower commit when unattended is
   requested. Add a coalesced follower test with a synthetic native lock row and
   an ordinary non-native leader. Existing tests cover report values and fresh
   minimums. `crates/adapters/src/managed/mod.rs:97`,
   `crates/app/src/operations.rs:3908`, `crates/app/src/operations.rs:6965`,
   `crates/app/src/operations.rs:2115`.

## Checks

- `git fetch origin m04/claims main`, ref resolution and `git diff --check 8f18a6bd 212f290a` exited **0**.
- Offline, locked adapter integration tests for qualifying Windows/Mode B and Linux/container
  host facts exited **0** (2 passed). Native positive, absent-terms and unattended controls
  exited **0** (3 passed).
- Offline, locked `heimdall-runtime --lib` tests filtered by
  `result_names_its_endpoint_kind_for_the_claim_table` exited **0** (2 passed).
  These are a local container fixture and a fake Mode B bridge.
- Offline, locked `heimdall-app --lib` history test
  `ensure_data_carries_managed_facts_only_from_this_process_outcome` exited **0**.
  Fresh prepare and reissue use `report::compute`. `owned_multiplexing` gates
  `closed_at_deadline` and retains configured `disabled` and platform
  `unavailable`. Followers and binds built from history strip the positive
  enforcement values. Successful operation replay is the separate path in R01.
- Store trace confirmed that terms are in-memory and rebuilt from the stored grant
  and runtime environment realization. Caller input can select an admitted
  environment ID. It cannot supply that realization. A grant's stored environment
  and the managed row's realization are fixed. A wholly missing terms entry
  refuses fresh prepare with `grant_terms_unavailable`.
- Offline, locked `heimdall-contract --test contracts schema_export::` exited
  **0** (10 passed, including byte-for-byte public schema agreement).
- Repeated the artifact's two exact test filters at the reviewed head in a scratch
  snapshot. Removing only the early return in `report::claim` exited **101**.
  Both tests failed with `Signer` versus `Unknown`. Restoring it exited **0**
  (2 passed). The restored SHA-256 prefix was `f703913d552eb01f`, matching the
  committed artifact's stated head hash. The proof isolates the fresh report gate.
- The offline, locked legacy replay and baseline typed-reader scratch probes each
  exited **0** (1 passed each, confirming R01 and R04).
- Local verification used macOS fixtures. Native Windows, WSL and Linux execution
  and the full workspace suite were outside this review.
