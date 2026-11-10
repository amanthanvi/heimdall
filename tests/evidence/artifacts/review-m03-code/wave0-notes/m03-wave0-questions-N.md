# Questions from subagent N (new crates, dependencies, testkit `managed`), M03 wave 0

Each question names the default N took (the most fail-closed or least-committing choice) and where.

## N1. `IssuerRefusal` wire form (frozen `heimdall-issuer/1`)

- ADR-0008 D3 item 3 shows `{"t":"refused","request_id":"…","reason":"<IssuerRefusal>"}` (one string), and
  m03-plan §5 item 20 says the variants are the `IssuanceRefusal` and `VerificationRefusal` sets plus six.
  The two domain sets share names (`wrong_principal`, `unknown_subject_key`, `time_uncertain`), and
  `IssuanceRefusal::GrantNotIssuable(GrantState)` carries data.
- A2 defined the variant set as `heimdall_app::ports::IssuerRefusal` with a derived, externally tagged serde
  (`{"issuance":{"reason":"stale_generation"}}`, `"entry_stale"`), which is not a one-string form.
- **Default taken:** the protocol reuses A2's type (re-exported from `heimdall_issuer::protocol`) and
  freezes its own wire form through `#[serde(with)]` on `Response::Refused.reason`: own reasons as their
  snake_case names; `issuance.<reason>` / `verification.<reason>` (the domain enums' own serde names);
  `issuance.grant_not_issuable.<grant_state>`. Fixed in `tests/contracts/golden/issuer-protocol.golden.json`
  (38 refusal strings). A refusal without a wire name fails to encode (closed).
  `crates/issuer/src/protocol.rs` (`refusal_to_wire`, `refusal_from_wire`, `is_generation_only`).

## N2. Golden file name

- m03-plan U3 acceptance and the `app::ports::IssuerRefusal` doc comment say
  `tests/contracts/golden/issuer-protocol.json`; N's task packet says `issuer-protocol.golden.json`
  (the existing `*.golden.json` convention). **Default taken:** `issuer-protocol.golden.json`. The plan
  line and A2's doc comment in `crates/app/src/ports.rs` should be aligned (N does not own them).

## N3. `SecretStore` signature details (frozen trait, `crates/issuer/src/store/mod.rs`)

- m03-plan U4 lists `kind() -> StoreKind`, `delete(&StoreItemRef)` (no result) and `list() -> Vec<…>`.
- `StoreKind` has no test variant (F23), so `ScratchSecretStore` cannot return one. **Default taken:**
  `kind() -> SecretStoreKind { Product(StoreKind) | Test(&'static str) }` (testkit names `scratch_test`;
  `product()` is `None` for it); `delete` and `list` return `Result<_, StoreError>` (an unavailable store
  cannot list, and an empty list would hide orphans). `put` never overwrites (`AlreadyExists`).
- `domain::claims::product_store_kinds` / the claims validator should treat any `SecretStoreKind::Test` as
  fixture custody (integrator check).

## N4. HM1 value shapes not fixed by ADR-0008 D5 §6.3

- The ADR fixes the key names and "decimal, a fixed token, or lowercase hex", but not the tokens of the
  boolean keys (`dir_owner_self`, `owner_self`, `last_byte_newline`, `group_listed`), the mode strings
  (`dir_mode`, `mode`), `status`/`reason`, or `remote_now`'s unit.
- **Default taken** (`crates/registry/src/hm1.rs`): booleans `yes|no`; modes as the `ls -ldn` 10 characters
  plus an optional `+`/`@`/`.`; `status`/`reason` `[a-z0-9_]+`; `remote_now` decimal (remote epoch seconds,
  matching `RemoteStep.not_after_remote`); `lock_holder` `hm1-[0-9a-z-]*`; `fence_signals` `""|TERM|TERM,KILL`.
  If U5 needs other tokens this is an ADR-0008 revision (the grammar is frozen).
- Related inconsistency (A1's file): `domain::verification::AttemptResult.remote_now` doc says "the `HM1 now=`
  reading"; §5 item 21's key is `remote_now`.

## N5. Signatures that return a `Result` where the plan shows a bare value

- `enroll::remote::SshStepRunner::run(&RemoteStep, TtyMode) -> Result<StepReport, StepRunError>` (plan:
  `-> StepReport`). A wave-0 bare `StepReport` would have to invent an exit status for a step that never
  ran. **Default taken:** `Result`, wave 0 `Err(Unavailable)`, nothing spawned.
- `registry::plan::plan_digest(&EnrollmentPlan) -> Result<PlanDigest, PlanRefusal>` (wave 0
  `DriverUnavailable`), `registry::line::expected_line(..) -> Result<String, LineError>`.

## N6. `child::run` parameter types

- Plan: `child::run(stdin, stdout, store: Box<dyn SecretStore>, db: &Path, clock: Arc<dyn Clock>) -> i32`; it
  must refuse a terminal stdin. **Default taken:** `run<R: Read + IsTerminal, W: Write>(stdin: R, stdout: W,
  …) -> i32` (std's `Stdin` and `File` satisfy it); wave 0 returns `EXIT_UNAVAILABLE` (69) touching nothing.

## N7. Field-less protocol requests are empty struct variants

- serde ignores `deny_unknown_fields` for unit variants of an internally tagged enum, so `{"t":"load","x":1}`
  was accepted. **Default taken:** `Request::{Load {}, Status {}, Shutdown {}}`; the wire form is unchanged
  (`{"t":"load"}`), and an unknown field is refused for every kind. `MAX_FRAME_BYTES` (65 536) bounds the
  JSON body; the 4-byte length prefix is not counted.

## N8. Runtime's own third-party lines

- `.m03-wave0-deps.md` §2 lists `zbus` (Linux) and `core-foundation`/`core-foundation-sys` (macOS) for
  `heimdall-runtime`. N added them (they add no lock package; the U9 session-lock source uses them). If the
  integrator meant the runtime unit to add them, they are three lines in `crates/runtime/Cargo.toml`.

## N9. `SecretCaKey` created in U1's file

- The frozen `SecretStore` trait names `SecretCaKey`, which m03-plan U1/U4 place in `heimdall-credential`
  (`cert::build_and_sign(.., ca: &SecretCaKey)`). **Default taken:** `crates/credential/src/cert.rs` defines
  `SecretCaKey { key: ssh_key::PrivateKey }` with only `from_private_key` and `public_key` (no `Clone`,
  `Debug`, serde). U1 adds the rest; U4's backup needs an accessor U1 must add.
