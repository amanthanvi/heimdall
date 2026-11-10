# M03 wave 0: B2 (ipc signing, U0b row 1) questions and decisions taken

1. **`SigningSession.peer` type.** m03-plan U0b row 1 (docs/architecture/m03-plan.md:491) names
   `peer: PeerInfo`. The only `PeerInfo` is `heimdall_contract::ipc::PeerInfo` (crates/contract/src/ipc.rs:63-70):
   the program name/version from the control hello, "informational only, never authority". The SSH agent
   protocol has no hello, so there is nothing to fill it with. The transport-authenticated principal is
   `heimdall_ipc::endpoint::PeerIdentity` (Unix uid/gid/pid, Windows SID/pid), which the accept loops already
   return (crates/runtime/src/service.rs `serve_signing`). Options: (a) `PeerIdentity` (taken); (b) a new
   ipc type named `PeerInfo`; (c) contract `PeerInfo` with placeholder values. Taken: (a), the field name
   `peer` kept. The plan text should say `PeerIdentity`.

2. **Guard drop on the expiry path.** Row 1 says the guard is dropped "only after that enqueue". On the
   expiry path (ADR-0008 D2 item 3a step 6, last bullet) the signature is discarded and a failure is sent
   once room frees within the same window. Taken: the guard is dropped **at the expiry**, before waiting
   for room for the failure. Reason: after expiry nothing of the signature can be released, so the gate
   protects nothing, and holding it up to 2 s more would exceed `signing_holder_max` (5 s = 2 + 1 + 2,
   m03-plan §5 item 17), which `signing_gate_max_wait` (H) is derived from. On the normal path the guard
   is dropped strictly after `Permit::send` (tested). Alternative: hold it until the failure is queued.

3. **A signature frame with no permit.** RULED (ADR-0008 §17.15) and applied: a permit-less signature is
   sent only when the signer declares the grant ungated (`SignOutcome::ungated_signature`, i.e.
   `SigningGates::contains` is false; U2 must decide it from the gates). Any other permit-less type-14
   frame is replaced by `SSH_AGENT_FAILURE`, counted in `SigningSession::refused_permitless`, and logged
   with a `tracing` warn (endpoint kind and count only). M01 fixtures declare themselves ungated.

4. **`Signer::session_bind` shape.** Plan: `session_bind(&mut SigningSession, payload) -> bool`. Taken: a
   synchronous `fn` with a default body returning `false` (fail-closed; `NoIdentities` and the M01
   fixtures refuse every bind, as M01 did). `payload` is the extension contents after the name string.
   `SessionBindRecord` is plain data (`host_key`, `session_id`, `signature`, `is_forwarding`); I added a
   structural-only `SessionBindRecord::parse` (lengths, bool 0/1, no trailing bytes; verifies nothing).
   U1 owns real verification and may ignore the helper.

5. **Belt and braces at the release check.** `serve` releases only if `Instant::now() < expires_at()`
   **and** `may_release()`; both are non-waiting. `may_release()` remains the authority (both clocks,
   `Safe` time, pending mark).

6. **Replies without a permit** (identities, failures, session-bind answers) use the same queue; their wait
   for room is bounded by the idle timeout (30 s), as the M01 per-reply write was. Each socket write by
   the writer is also bounded by the idle timeout (M01 behaviour). Default queue capacity:
   `OUTBOUND_QUEUE_FRAMES = 4` frames (≤ 1 MiB per connection at the 256 KiB frame limit).

7. **For the integrator (paths I do not own):** `crates/ipc/src/lib.rs` crate docs list the test targets
   hosted by ipc; add `integration_ipc_signing_m03` there (I did not edit lib.rs: no re-export needed).
   The row's plan text and ADR-0006 rev 4 should name the final API (see the B2 report).
