# M03 wave 4, round 2 — worklog R2-E (cross-cutting end-to-end tests)

Goal: §17.21 items 1 and 11's cross-cutting plan tests: `enroll_preview_apply_verify_setup_apply_ensure_ssh`
(setup-apply, ensure, ssh legs), both `a10_narrow_certificate_refused_on_other_host_*`,
`issuer_crash_blocks_reissue_not_signing`.

## Decisions
- Harness (`tests/e2e/enroll_m03.rs`): `WorldOptions.managed` builds R2-C's `live_tests` construction from
  public items (no runtime file touched): `StoreSources`, `SignerTable`, `ManagedEffectsImpl` over a late
  `EndpointRegistry` (test-local `LateRegistry`, forwarding all three `BindingEndpoints` methods),
  `ManagedCertificateAdapter::with_cleanup(StoreCleanup)`, `OpsInstallView`; registry with a test-only
  `SignHook` (`SignLog`) recording each request's `Admitted`/`Signed` step per endpoint. Runtime dir = the
  harness's scratch `rt` (owner-only); slot data dir scratch `state` (owner-only, created explicitly).
  Profile `dev` + standing policy over the world's pair seeded only in managed worlds.
- `TestIssuer` gains a grant-table branch: reads the stored issuance entry, takes the grant's live K_env from
  the signer table (the driver's `subject` must equal that key's line), signs exactly the reserved bounds with
  the entry's CA (`heimdall_credential::cert::build_and_sign`, the child's code path, the enrolled `TestCa`).
- Setup-apply leg: **recorded, not run** (`World::record_projection_applied`): the harness has no projection
  writer and no production path records a managed pair's projection `applied` (grep: only `catalog.rs` and the
  E5 hook write `pending`; `Applied` is written only by tests). R2E-Q1.
- Ensure leg: **interactive** (as R2-C's live tests): a non-interactive one needs an `exclusive` observation,
  which needs the runtime's `sources::Observing` over a projected config; `StoreSources` observes nothing.
- ssh leg: system `ssh` with the fixture home's isolation args (`-F` scratch config, scratch known-hosts,
  `BatchMode=yes`, `HOME` scratch, `SSH_AUTH_SOCK` decoy) + `managed_identity_options` (selected form
  `CertificateAsIdentityFile`) + `PreferredAuthentications=publickey`, remote `echo <marker>`. The fixture's
  default-identity guard (`check_alias`) is not run: it reads the config file only, where the alias has no
  identity directives (they are on the command line), so it refuses (`DefaultIdentities`, observed); isolation
  holds through `HOME`=scratch + `IdentitiesOnly=yes` + the binding endpoint as agent.
- A10: h2 enrolled through the real flow under the same CA (account form: own `cert-authority,principals=
  "hm:dst_e2e2:<acct>"` line; system form: `TrustedUserCAKeys` + principals file `hm:dst_e2e2:<acct>`, via new
  `add_destination_with(n, System)` + `system_verified_on`). Oracle for the refusal: exit 255 + `Permission
  denied (publickey)` + h2's log `Refusing certificate ID "<grant key id>" … does not contain an authorized
  principal` + no accepted cert on h2 + no `Signed` step on the binding signer; control: h1 accepts again.
- Crash test: `tests/integration/runtime_m03.rs` (`issuer_crash` module, target `integration_runtime_m03`),
  fixture `IssuerPort` (`FlakyIssuer`, `crashed` + `Unavailable("issuer_unavailable")` while down) over the
  same production pieces; real agent-protocol sign request on the binding endpoint (list → sign userauth for
  the cert); restart = new `Operations` + new vault over the same store; `Supervisor::managed_reissue_pass`.
- "issuer_supervision_pass degrades the dependent pairs `issuer_unavailable`": **not implemented anywhere and
  not ruled** (ADR D3 item 7 lists only: new activations/re-issues fail, existing grants keep signing, lost K_env
  → `credential_reissue_pending`; the pass's doc says it degrades nothing). Test asserts the ruled part (grant
  keeps signing authority: `active`, or `degraded` for a reason that permits signing). R2E-Q2.

## Defect fixed
- `crates/app/src/operations.rs` `prepare_error`: a managed preparation whose driver could not get its
  certificate signed (`AdapterError::Unavailable(ISSUER_SIGN_FAILED)`) answered `SERVICE_UNAVAILABLE` with no
  reason; ADR-0008 D3 item 7 rules `CAPABILITY_UNAVAILABLE`, reason `issuer_unavailable`. Now mapped so (one
  guarded early return, managed mechanism only; existing-access paths untouched). The issuer's own store reason
  (`issuer_store_locked`/`_unavailable`) is not propagated (the driver drops it): R2E-Q3.

## Commands (real exit codes)
- baseline `cargo test -p heimdall --test e2e_enroll_m03 enroll_preview_apply_verify_setup_apply_ensure_ssh` → 0
  (before any change; the old test).
- `cargo test -p heimdall --test e2e_enroll_m03 -- a10_narrow enroll_preview_apply_verify_setup_apply_ensure_ssh`
  → 3 passed (exit 0).
- `cargo test -p heimdall-runtime --test integration_runtime_m03 issuer_crash` → 1 passed (exit 0).
- Revert proof (prepare_error guard made `false && …`): same command → exit 101, `left: (ServiceUnavailable,
  None) right: (CapabilityUnavailable, Some("issuer_unavailable"))`; restored → exit 0.
- Whole touched targets: `cargo test -p heimdall --test e2e_enroll_m03` → 62 passed (exit 0);
  `cargo test -p heimdall-runtime --test integration_runtime_m03` → 38 passed (exit 0). Because of the
  `operations.rs` fix also: `cargo test -p heimdall --test e2e_managed_m03` → 16 passed (exit 0);
  `cargo test -p heimdall-adapters --test integration_managed_adapter` → 46 passed (exit 0).
- `cargo fmt --all --check` → 0 (after `rustfmt` of the two test files, which were the only diffs).
- `cargo clippy -p heimdall --all-targets -- -D warnings` → 0; `-p heimdall-runtime` → 0; `-p heimdall-app` → 0.
- `bash tools/validation/linux-xcheck.sh -p heimdall` → 0; `-p heimdall-runtime` → 0.
- `bash tools/validation/clippy-windows.sh` → 0 (then `target/x86_64-pc-windows-gnu` removed, as its header says).
- `python3 -I tools/validation/crate_graph.py` → 0 (dev-deps only; no production edge added).
- After formatting, reran the four tests: e2e 3 passed (exit 0), crash 1 passed (exit 0).
- `Cargo.lock`: only `heimdall`'s dependency array gained `"heimdall-adapters"`, `"heimdall-credential"`
  (diffed against a pre-change copy); package set unchanged.
- No `HEIMDALL_CANARY_` in any run log; no `sshd` process left after the runs (`ps -axo pid,ppid,comm`).
- Left: `target/debug` (68 GB, the shared dev build the integrator still uses).
