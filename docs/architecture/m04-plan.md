# M04 plan: native, WSL, container and bastion realization

**Status:** draft for the ADR-0009 §2.8 cycle (one draft, one independent review, one ruling pass).
**Sources:** plan.md §5 M04, §6; spec §3, §6.4, §8.4, §8.5, §10.3, §13.2, §14; ADR-0010 (the decisions).
**Base:** `main` at `3e75c2f9`, with M03 waves 0–5 merged. M04's exit build waits for the M03 exit.

**What M04 builds on, unchanged:**
- per-binding Windows pipes and Unix endpoints, with their peer checks (ADR-0006 §2, ADR-0008 D10);
- the managed signer, the issuer and re-issue (ADR-0008);
- the projection and Git transactions (ADR-0007);
- `EnvironmentKind::{WslDistribution, Container}`, which is declared but never created today;
- the enrollment plan's `route_unsupported` refusal.

**The G03 starting point:** the mechanisms are proved; the product is not. The prototype harnesses
verified every executed Mode A mechanism row (P-A01–P-A05) and most Mode B rows (P-B02–P-B06,
P-B08–P-B10) on the owner's PC (`docs/research/g03-windows-wsl.md` §0). The blocked and inconclusive
rows (P-A06, P-B01, P-B07, P-B11) are covered by §4.

## 0. Ground rules

M04 follows m03-plan §0.1–§0.5 (owner paths, test-target convention, disposable fixtures, evidence
discipline, build hygiene) and ADR-0009. It adds the following:

- **Tests:** a test is listed below only if it covers a behaviour no existing test covers. A unit reuses
  an existing test when one already asserts the property, and says which.
- **Owner material:** none, beyond ADR-0004 §3 (and Q3).
  - WSL work uses only disposable distributions, created with `wsl --import` and unregistered by name.
  - The owner's distributions are observers only, as in P-B08: client actions, no writes.
  - Nothing touches the owner's Run key, LaunchAgents or systemd user units. Login-entry tests use
    scratch roots. The one exception is U1's macOS row, which loads a scratch plist into the owner's
    launchd session and unloads it in the same run.
- **Shared files:** the files shared with M05 (§6) change only through the integrator. Contract
  changes go through the contract owner (Q5).

## 1. Units

### U0: Wave-0 integration (contract revision 5, migration, types, skeleton)

- **Owns:**
  - `Cargo.toml`, `Cargo.lock` (new member `crates/wsl`);
  - the §5 contract delta in `crates/contract/**`;
  - `crates/domain/src/{environment,catalog,resource}.rs`;
  - `crates/store/migrations/0007_*.sql` and a new `crates/store/src/ext_m04.rs`;
  - the endpoint-target seam in `crates/app/src/ports.rs`;
  - the setup-item dispatch in `crates/app/src/setup.rs`, where each new item calls a handler its unit
    implements in its own files;
  - the stub modules `crates/localenv/src/sys/{spawn,lxss}.rs`;
  - `crates/credential/src/endpoints.rs`, converted to `endpoints/mod.rs` with stub submodules
    `container.rs` and `wsl.rs`;
  - `crates/wsl/**` (skeleton, plus the frozen `heimdall-wsl/1` message types in `proto.rs`);
  - the arms in `crates/runtime/src/dispatch.rs`;
  - the subcommands in `crates/heimdall/src/cli.rs` (`wsl`, `container`, `service autostart`);
  - `tools/validation/crate_graph.py`;
  - the `[[test]]` declarations for every M04 suite (`windows_m04`, `wsl_m04`, `container_m04`,
    `route_m04`) in their host crates, each starting with one fail-closed test so the zero-test guard
    holds;
  - the regenerated `schemas/public-api/`.
- **Builds:**
  - **Domain:**
    - `EnvironmentRealization` (`native`, `wsl {guid, name, account}`, `container {label, dir_tag}`);
    - the WSL distribution record (owned items, modes);
    - `DestinationDefinition::Managed.jump: Option<DestinationId>` (serde default `None`);
    - `ResourceKind::LoginEntry`.
  - **Endpoint target:** an `EndpointTarget` (`Native`, `Container`, `WslBridge`) on binding-endpoint
    creation.
  - **Crate graph:** `wsl ──► credential, localenv, ipc, app (ports), domain, contract`;
    `runtime ──► wsl`; `heimdall ──► wsl`.
  - **Fail closed:** every new body fails closed until its unit lands, the M03 wave-0 pattern.
- **Tests:**
  - the schema export and diff (existing);
  - the migration round trip from schema 6 (existing pattern);
  - `crate_graph` mutants for the new edges.
- **Accept:** `check.sh` passes; no request reaches a new body; every M01–M03 envelope and hash is
  unchanged.

### U1: Runtime platform layer (T01 service part, T04)

- **Owns:**
  - `crates/runtime/src/autostart/{mod,windows,macos,linux}.rs` (new);
  - `SystemTimeSync` and the time probes in `crates/runtime/src/platform.rs`;
  - the state-directory check in `crates/runtime/src/paths.rs`;
  - `crates/heimdall/src/service_cmd.rs`;
  - the login-entry seam in `crates/heimdall/src/uninstall_cmd.rs`.
- **Builds (ADR-0010 §1 items 1, 2 and 7; §6):**
  - **Login entries:** the Run value, the LaunchAgent and the systemd user unit, each a setup item
    with preview, apply and uninstall.
  - **`service run --login`:** yields to a running instance.
  - **Time source:** the Linux `adjtimex` sync source, with systemd's `NTPSynchronized` rule
    (`maxerror` below 16 s).
  - **Probe:** a read-only probe on macOS and Windows for a documented sync interface (an observation
    record only).
  - **Windows state directory:** the owner-only DACL check.
  - **Windows boot ID:** an observation of the BootId value (the reboot row is B12).
- **Tests:**
  - `login_entry_install_remove_round_trip`, per platform, against a scratch root. On Windows the root
    is an injected scratch registry key. On macOS the plist is bootstrapped from scratch, then booted
    out; nothing is written under `~/Library`. → A31
  - `login_mode_yields_to_running_instance` (exit 0, one instance) → A31
  - `uninstall_removes_only_the_owned_login_entry`, with a foreign value of a similar name → A31
  - `adjtimex_status_maps_to_sync_status` (unit), plus the native devbox and WSL observation → A08
  - `windows_state_dir_not_owner_only_is_refused` (native, PC) → A14
  - `linux_login_entry_starts_runtime_at_next_login` (disposable distribution with systemd: install,
    `wsl --terminate`, log in again, runtime present) → A31, A08
- **Accept:** every login entry installs and uninstalls without elevation and leaves the owner's state
  byte-identical. The headless report names `issuer_store_unavailable`, `lock_signal_unavailable` and
  `on_demand` where they apply.

### U2: Windows integration (T01)

- **Owns:**
  - `spawn_with_handle_list` in `crates/localenv/src/sys/spawn.rs`;
  - the issuer-child spawn seam in `crates/issuer/src/client.rs` (an injected spawner);
  - the `git_client_cannot_reach_pipe` finding in `crates/localenv/src/doctor.rs`;
  - `tests/e2e/windows_m04.rs`.
- **Builds (ADR-0010 §1 items 4–6):**
  - explicit handle lists for runtime children;
  - the doctor finding for Git's bundled client.
- **Tests:**
  - `runtime_child_inherits_only_listed_handles` (native: a concurrent inheritable canary handle is
    absent in the child) → A14, A13 (channel privacy)
  - `a14_no_global_agent_takeover_inventory_identical` (native, before and after setup, managed
    `ensure`, login entry, Mode A enable and uninstall). The inventory covers:
    - `\\.\pipe\` names, listed without opening;
    - `ssh-agent` service config and SDDL, read-only;
    - `HKCU\Environment`;
    - Git global and system config;
    - the `%USERPROFILE%\.ssh` digest.
  - `a14_git_bundled_client_reported_not_claimed` (native, Git for Windows) → A14
  - `a14_managed_alias_never_contacts_inherited_ssh_auth_sock`: a decoy pipe gets no connection → A14.
    Added only if no `e2e_*_m03` test asserts it.
- **Reused:** pipe owner, DACL, SID and first-instance tests (M01 windows-ipc, M03 endpoints); the
  Windows interactive ConPTY rows (M03 U13).
- **Accept:** A14's runnable rows pass on the PC. The cross-user, clean-host and UAC rows are blocked
  (§4).

### U3: WSL discovery, helper file work, Mode A (T02)

- **Owns:**
  - `crates/wsl/src/{discover.rs, helper/mod.rs, helper/files.rs, modea.rs}`;
  - the read-only Lxss registry read in `crates/localenv/src/sys/lxss.rs`;
  - `crates/heimdall/src/wsl_cmd.rs` (created here; U4 extends it);
  - the `internal wsl-helper` entry in `crates/heimdall/src/main.rs`;
  - `tests/e2e/wsl_m04.rs` (created here).
- **Builds (ADR-0010 §2):**
  - **Discovery:** distributions from Lxss (GUID, name, version, default uid), the running set from
    `wsl.exe --list --running --quiet` (UTF-16), and interop and `appendWindowsPath` read by the
    helper.
  - **The helper:** spawn, hello, then the file actions: apply and roll back the distribution Git item,
    the projection, and materialize.
  - **Mode A:** enable and disable.
- **Tests:**
  - `lxss_entries_parse_to_guid_identity` (unit) → A13 identity
  - `wsl_running_list_utf16_parse` (unit)
  - `a12_git_clone_push_through_windows_ssh_on_managed_alias`, into a spaced and Unicode Linux path and
    a `/mnt/c` path → A12
  - `a12_exit_status_stderr_and_binary_bytes_preserved` → A12, A27
  - `a12_interrupt_leaves_no_ssh_exe_and_reports_status` → A12, A27
  - `a12_reissued_certificate_used_on_next_run` → A12
  - `a12_enable_disable_leaves_distribution_git_config_identical` → A12, A31
  - `a12_interop_child_medium_integrity` → A12, A14. The UAC observation is B5.
- **Accept:** A12 passes on Windows 11 with the in-box 9.5p2 client and a disposable Ubuntu 24.04
  distribution.

### U4: WSL Mode B (T03)

- **Owns:**
  - `crates/wsl/src/bridge/{windows,linux}.rs`;
  - `crates/credential/src/endpoints/wsl.rs`;
  - the bridge-supervisor wiring seam in `crates/runtime/src/{service,supervisor}.rs`;
  - the Mode B half of `wsl_cmd.rs`;
  - the Mode B tests in `tests/e2e/wsl_m04.rs`.
- **Builds (ADR-0010 §3):**
  - the Windows supervisor (spawn with the U2 handle list, the running check, the no-background-start
    rule, respawn);
  - the stream service over the binding's `ManagedSigner`;
  - the Linux endpoint (peer uid, `classify`, limits);
  - `Realize` and `Withdraw` with generations;
  - enable and disable, and the unregistered-distribution path.
- **Tests:**
  - `wsl_proto_bounds_and_unknown_frames_refused` (pure) → A13
  - `helper_withdraw_of_old_generation_keeps_replacement` (Unix unit) → A13
  - `a13_lists_only_binding_identities_and_refuses_unlisted_key` → A13
  - `a13_git_over_linux_ssh_through_bridge` → A13, A27
  - `a13_control_hello_on_bridge_socket_fails` → A13 (the M04 exit's "no management API" clause)
  - `a13_other_distribution_sees_no_endpoint`, with the owner's distribution as observer: no path, no
    abstract or `/mnt/wsl` socket, no TCP → A13
  - `a13_two_enabled_distributions_get_disjoint_endpoints` → A13 (needs Q3)
  - `a13_other_linux_user_refused` (a second user inside the disposable distribution). Its probe of the
    `wsl.exe -u` bypass is recorded in `RESIDUALS` → A13
  - `a13_terminate_then_user_restart_recreates_endpoint_without_background_start` → A13
  - `a13_deleted_socket_recreated` → A13
  - `a13_binding_end_refuses_then_withdraws_endpoint` → A13
  - `a13_runtime_stop_helper_exits_and_removes_endpoints` → A13
  - `a13_unregistered_distribution_releases_bindings` → A13
  - `a03_mode_b_fresh_logins_while_windows_locked`: a release profile on the DPAPI store, under the
    ADR-0004 §2 idle rule (P-B07) → A03
- **Accept:** A13 passes on the PC with disposable distributions; the other-Windows-user row is blocked
  (B2).

### U5: Container binding recipe (T05)

- **Owns:**
  - `crates/credential/src/endpoints/container.rs`;
  - `crates/localenv/src/container.rs` (new: in-container rendering through `sshconf::render`). It
    makes no change to `render.rs`: container paths are ordinary Unix `RenderPath`s;
  - `crates/heimdall/src/container_cmd.rs`;
  - `tests/e2e/container_m04.rs` (`cfg(target_os = "linux")`, `platform_only`).
- **Builds (ADR-0010 §4):**
  - `container add` and `remove`;
  - the stable directory;
  - one binding per environment;
  - the mount instructions and the UID rule;
  - generation-checked teardown.
- **Tests:**
  - `container_files_use_in_container_paths_and_never_name_host_agent` (golden over the rendered config
    and the mount arguments) → A15
  - `container_dir_holds_only_signing_endpoint_and_public_files` → A15
  - `a15_rootless_root_admitted_and_subuid_refused` (Podman) → A15
  - `a15_rootful_mapped_user_admitted_and_root_refused` (Docker Engine) → A15
  - `a15_container_lists_only_binding_identities_and_control_hello_fails` → A15
  - `a15_binding_end_then_replacement_visible_at_same_path` → A15
  - `a15_container_remove_cleans_only_owned_entries` → A15, A31
- **Accept:** A15's container rows pass on the disposable distribution with a test-configured runtime.
  This is mechanism evidence, and it is valid for exposure claims (ADR-0010 §4 item 7). The devbox rows
  are B8, the product row B11.

### U6: Bastion routes and forwarding (T06)

- **Owns:**
  - the jump rules in `crates/domain/src/catalog.rs`;
  - `extension_profile` in `crates/domain/src/issuance.rs`;
  - the `ProxyJump` and `ForwardAgent <path>` fields in `crates/sshconf/src/render.rs`;
  - `crates/adapters/src/managed/route.rs` (new: the route-dependency check);
  - the jump-alias argument in the managed-alias call of `crates/localenv/src/projection/content.rs`;
  - `catalog destination set --jump` in `crates/heimdall/src/catalog_cmd.rs`;
  - `crates/testkit/src/bastion.rs` (two `LoopbackSshd`s, the bastion with `PermitOpen`);
  - test-CA trust for the M00-T03 bastion and target containers in `tests/fixtures/ssh/`;
  - `tests/e2e/route_m04.rs`.
- **Builds (ADR-0010 §5):**
  - single-hop `ProxyJump` through catalog destinations;
  - the access rule for the jump hop;
  - `permit-port-forwarding` only on jump pairs;
  - explicit agent forwarding of the binding endpoint.
- **Tests:**
  - `extension_profile_port_forwarding_only_for_jump_pairs_in_scope` (unit) → A15
  - `managed_alias_renders_proxyjump_and_never_forwardagent_by_default` (golden) → A15
  - `route_chain_and_out_of_scope_jump_refused` (unit) → A15
  - `a15_proxyjump_through_managed_bastion` and `a15_proxyjump_through_existing_access_bastion` → A15
  - `a15_final_host_key_substitution_refused_through_jump` → A15 (R-SE-04)
  - `a15_non_jump_pair_cannot_open_forwarding` (`-W` and `-L` administratively prohibited) → A15
  - `a15_user_dash_a_refused_without_capability` → A15
  - `a15_forwarded_endpoint_bounded_to_binding`: it lists only the binding's identities, an unmapped
    host refuses the forwarded identity, and signing stops at the deadline → A15 (spec §14.3)
  - `a15_binary_roundtrip_through_jump` → A27
  - all e2e tests also run on Windows (`ssh.exe` to the WSL fixture sshds). A client that cannot do
    `-J` or `ForwardAgent <pipe>` is recorded and labelled `unsupported`.
- **Accept:** A15's bastion and forwarding rows pass on macOS, the devbox and Windows.

### U7: Exit suite, records, matrix and claims (T06's matrix refresh)

- **Owns:**
  - `tests/native/m04/**`, which reuses the M03 U13 harness libraries and the ConPTY harness;
  - `tests/evidence/m04-*.json` and `tests/evidence/artifacts/m04/**`;
  - the M04 section of `docs/compatibility/matrix.md`: rows 10, 11, 12 and 14 updated, a login-entry
    row per platform added, and Docker Desktop, devcontainers and WSL-nested containers kept
    `not-tested`;
  - `docs/architecture/m04-exit-draft.md`;
  - the claims update in `crates/domain/src/claims.rs` (a separate commit after the records are
    verified).
- **Harness additions:**
  - two disposable distributions (Q3);
  - Podman and Docker Engine inside the disposable distribution;
  - the Windows lock run;
  - the owner-digest and before/after inventories;
  - canary scans over every artifact.
- **Tests:** harness self-tests only:
  - `wsl_harness_unregisters_only_its_distributions`;
  - `container_harness_removes_only_its_images_and_containers`.
- **Accept:** §3's records are generated and valid; the matrix and the exit draft are written.
- **Depends on:** every unit and the M03 exit.

## 2. Waves

```text
W0  U0 (integrator; the contract delta lands through the contract owner)
W1  U1 runtime platform   U2 Windows   U3 WSL + Mode A   U5 containers   U6 bastion   (parallel; disjoint paths)
W2  U4 Mode B (needs U2's handle-list spawn and U3's helper and file actions)
W3  U7 exit suite (after the M03 exit), native exit runs, records, matrix, claims
```

- **Review:** each wave gets one independent review and one scoped re-check (ADR-0009 §2.1).
  - Plan §6.7's security review covers W1 (U2, U5) and W2 (U4): the Windows and WSL exposure and the
    container boundary.
- **Native runs** happen at each wave's merge candidate:
  - the PC and the devbox;
  - plus the disposable-distribution run for W1 (U3, U5) and W2.

  In between, targeted runs use `HM_ONLY`.
- **File disjointness** comes from U0's stubs and declarations:
  - in W1, U2 and U3 meet only in their own `localenv/src/sys/*.rs`;
  - U5 (W1) and U4 (W2) meet only in their own `endpoints/*.rs`;
  - U3 creates `wsl_cmd.rs` and fills `wsl_m04.rs`, and U4 extends them only in W2;
  - U1 and U4 both touch `runtime/src/service.rs`, in different waves.

## 3. Exit mapping (plan §5 M04)

| Case | Proved by | Platforms (runnable now) | Blocked rows |
|---|---|---|---|
| **A12** WSL Mode A | U3 | PC + disposable distribution, in-box 9.5p2 | UAC observation (B5) |
| **A13** WSL Mode B | U4 | PC + disposable distributions; the owner's distribution as observer | other Windows user (B2) |
| **A14** native Windows | U2, U1; M01/M03 pipe tests | PC, Medium integrity | other user (B2); clean host with a real `ssh-agent` (B4); UAC observation (B5); 1Password coexistence (B1) |
| **A15** containers, bastion, forwarding | U5, U6 | containers: disposable distribution (Podman, Docker Engine); bastion: macOS, devbox, PC | devbox containers (B8); product container host (B11); arm64 (B9) |
| **A03** (applicable: Mode B under host lock) | U4 | PC under the ADR-0004 §2 idle rule | Linux desktop (B11); the native A03 rows are M03's |
| **A08** (applicable) | U1; M01/M03 virtual-clock and restart tests | process restart on every host; the Linux sync signal on the devbox and WSL; login after `wsl --terminate` | sleep, logout, reboot (B12); the macOS product store (B3) |
| **A27** (applicable) | U3, U4, U6; M03 U13 ConPTY rows | interop, bridge and jump byte paths on the PC, devbox, macOS | none beyond M03's |
| **A31** (applicable: setup and uninstall of every M04 integration, unelevated) | U1, U3, U4, U5 | all four | real-account login after logout (B12, with B2/B3 for disposable accounts); packaging, update and rollback are M08 |

## 4. Platform evidence plan

"Runnable" means it runs with no owner input. The B-IDs are m03-plan §7's; M04 adds none.

| Property | macOS arm64 (build host) | Linux devbox (Ubuntu 24.04, headless) | Windows 11 PC (Medium integrity) | Disposable WSL distributions |
|---|---|---|---|---|
| Login entry | Runnable: scratch-root round trip and scratch bootstrap. Real login: B3, B12 | Runnable: transient `systemd-run --user` only. No unit is installed in the owner's account | Runnable: scratch registry root. Real Run value at login: B12 (B2 for a disposable account) | **Runnable end to end** (systemd user unit, terminate, log in again) |
| Time sync signal | Probe observation | Runnable (`adjtimex`) | Probe observation | Runnable (expected `unknown`; recorded) |
| Windows non-takeover, Git client, handle lists, state DACL | — | — | Runnable | — |
| Cross-user refusal (pipes, Mode B) | B3 | B8 | B2 | other Linux user: runnable |
| Mode A | — | — | Runnable with a disposable distribution | Runnable |
| Mode B (scope, restart, socket loss, teardown, unregister) | — | — | Runnable | Runnable (two distributions need Q3) |
| Mode B under host lock | — | — | Runnable under the ADR-0004 §2 rule | — |
| Containers (rootless, rootful, teardown) | Docker Desktop: `not-tested` by decision | B8 | — | Runnable (Q3) |
| Bastion and forwarding | Runnable: loopback, and Docker bastion and internal target | Runnable: loopback | Runnable: `ssh.exe` to the WSL fixture sshds | — |
| Sleep, logout, reboot | B12 | B12 | B12 | `wsl --terminate` as the restart row |
| Linux desktop (product container host, logind) | — | B11 | — | — |
| Linux arm64 | — | B9 | — | — |

**Disposable WSL rules:** the M02 and M03 rules apply, plus these:
- **Naming:** the harness names each distribution it creates, and unregisters only those names.
- **The owner's distributions:** never written to, terminated or shut down.
- **Installs:** packages for Podman and Docker Engine are installed only inside a disposable
  distribution, and the harness removes images and containers before unregistering.

## 5. Contract deltas: ADR-0006 revision 5 (additive)

1. **Capability:** `environments/1`.
2. **Owner requests:**
   - `wsl_enable {distribution_guid, account, mode_a, mode_b}` and `wsl_disable {distribution_guid}`;
   - `container_add {label}` and `container_remove {environment_id}`.

   Mode B and containers create an environment record and are decision-recorded (ADR-0006 §3.1),
   because they add a place where authority can be realized. Mode A alone creates a distribution record
   and goes through the setup confirmation only.
3. **Setup items** (ADR-0007 preview, apply and uninstall):
   - `login_entry`;
   - `distribution_git {guid}` (Mode A);
   - `distribution_projection {guid}` (Mode B).
4. **`inspect environments`** lists every environment, not only the caller's. Each `EnvironmentView`
   has `kind`, `label`, `state` (`active`, `not_running`, `removed`, `gone`) and a realization:
   - `wsl {name, guid, account, modes, helper}`;
   - `container {label, directory, in_container_path}`.
5. **`ConsumerIntegration.realization`** (optional): `environment_kind`, the in-environment `endpoint`
   and `config` paths, `mount {source, target, read_only}`, and in-environment variables.
6. **`PairIntegration` fields:**
   - `route` (optional): `{jump, jump_alias, jump_access: managed | existing}`;
   - `agent_forwarding: bool`, omitted when false.
7. **Readiness conditions:** `wsl_distribution_running` and `route_dependency`.
   **`inspect capabilities`:** `login_start {kind: run_value | launch_agent | systemd_user | none,
   installed}`.
8. **Reasons:**
   - `wsl_unavailable`, `wsl_interop_disabled`, `wsl_distribution_unknown`,
     `wsl_distribution_not_running`, `wsl_helper_unavailable`;
   - `environment_busy`, `environment_removed`;
   - `route_chain_unsupported`, `route_dependency_out_of_scope`;
   - `git_client_cannot_reach_pipe`, `state_dir_unsafe`, `login_entry_conflict`.
9. **Schema version:** a minor bump. Every M01–M03 document and request hash is unchanged.

## 6. Crate ownership against M05

**The boundary:** M04 owns **where and how** a binding is realized: environments, endpoints outside
the native session, routes, login start and platform signals. M05 owns **whether and when** a binding
exists: manifests, trust, activation, policy review, pinned bindings, delegation, and pause, expiry and
cutoff. They meet at `binding.environment_id` (already present) and at the `EndpointTarget` seam.

| Area | M04 | M05 |
|---|---|---|
| `crates/wsl` (new) | owns | — |
| `runtime/src/autostart/**`, `runtime/src/platform.rs`, `runtime/src/paths.rs` | owns | — |
| `domain/src/{environment,catalog,resource}.rs` | owns | reads `EnvironmentId` only |
| `domain/src/{policy,binding,decision,scope,authority,grant,delegation*}.rs`, a new trust module | — | owns |
| a new manifest crate, if M05 makes one | — | owns |
| `app/src/{trust,activation,delegation}*.rs` (new), `singleflight.rs`, `holders.rs` | — | owns |
| `launch`, `localenv/src/git.rs`, shell integration | — | owns |
| `sshconf/src/render.rs` (`ProxyJump`, `ForwardAgent`) | owns | asks M04 for any render change |
| `localenv/src/container.rs`, the `localenv/src/sys` additions, `doctor.rs` findings | owns | — |
| `adapters/src/managed/route.rs` | owns | — |
| `heimdall/src/{wsl_cmd,container_cmd,service_cmd}.rs` | owns | — |
| `heimdall/src/{run_cmd,trust_cmd*}.rs` | — | owns |
| `tests/native/m04`, `tests/evidence/m04-*` | owns | — |
| `tests/native/m05`, `tests/evidence/m05-*` | — | owns |

**Files both tracks must change** (integrator-only; first come, first served: the wave that merges
later rebases):

1. **The contract:** `crates/contract/**` and `schemas/public-api/**`, through the single contract owner
   (ADR-0009 §2.6; Q5).
2. **The store:**
   - `crates/store/migrations/`: the first track to merge takes `0007`, and the second renumbers to
     `0008` when it rebases (mechanical);
   - `crates/store/src/lib.rs`: module lines only. Each track writes its `Txn` methods in its own
     `ext_m04.rs` or `ext_m05.rs`.
3. **The application:**
   - `crates/app/src/ports.rs`: M04 adds the endpoint target, M05 its activation ports;
   - `crates/app/src/operations.rs` and `ensure.rs`: dispatch arms and one call each. M04's logic lives
     in `app/src/environments.rs` (new); M05 keeps its logic in its own modules.
   - `crates/app/src/setup.rs`: the item dispatch. M04 adds three items; M05 adds its first-trust
     items.
4. **The adapter and credential layer:**
   - `crates/adapters/src/managed/*` and `crates/credential/src/endpoints/mod.rs`: M04 only adds
     the target seam; M05's concurrent bound contexts (M03 Q15) change binding creation in the same
     files.
   - `crates/domain/src/issuance.rs`: M04 changes only `extension_profile`.
5. **Projection and runtime wiring:**
   - `crates/localenv/src/projection/content.rs` and `materialize.rs`: M04 passes the jump alias; M05
     adds bound contexts.
   - `crates/runtime/src/{dispatch,service,supervisor}.rs`: wiring seams.
6. **The CLI and test fakes:**
   - `crates/heimdall/src/cli.rs`, `setup_cmd.rs` and `uninstall_cmd.rs`;
   - `crates/testkit/src/lib.rs` and `crates/heimdall/src/testcfg.rs`.
7. **Shared records:** `crates/domain/src/claims.rs`, `docs/compatibility/matrix.md` (separate M04 and
   M05 sections), `progress.md`, `Cargo.toml` and `Cargo.lock`.

## 7. Questions (recommended answer first)

1. **Mode B upstreams.** **Recommended:** managed bindings only in M04.
   - Existing access inside WSL uses Mode A.
   - A filtered existing-access relay (ADR-0004 E-3 convenience) waits until B1 or B4 can verify its
     attribution change.
2. **Enrollment and verification through a jump route.** **Recommended:** defer to M06-T03 (routes),
   keep `route_unsupported`, and document the workaround (enroll while directly reachable).
   - A15 asks only to connect through a bastion.
   - Pinning both hops in the enrollment steps changes the registry and enrollment code that M03 just
     closed.
3. **Disposable WSL scope.** **Recommended:** extend ADR-0004 §3 to two disposable distributions at once,
   and allow Podman and Docker Engine packages inside them, removed with the distribution.
   - This makes A13's multi-distribution row and A15's container rows runnable without owner hardware.
   - Without it, A13's two-distribution row stays blocked on this ruling, and the container rows on B8
     and B11.
4. **Time after a reboot.** **Recommended:** trust only Linux `adjtimex` in M04.
   - macOS and Windows stay `unknown` unless U1's probe finds a documented, locale-independent interface.
   - Until then the first re-issue after each reboot waits for one attended time confirmation
     (disclosed).
5. **Contract owner and migration order.** **Recommended:** the orchestrator holds ADR-0006 revision 5.
   - M04 and M05 each deliver their wave-0 delta as a patch.
   - The first merged takes migration `0007`.
6. **Items m03-plan §8 handed to M04 that no M04 task or exit case needs** (Recipe A; hardware K_env
   through the Secure Enclave or per-grant TPM). **Recommended:** re-defer them, with a decision, to a
   later candidate. Reopen Recipe A if the G01 inventory finds a target without certificate support.

## 8. Not in M04

- **Filtered existing-access relays** for WSL or containers (Q1).
- **Routes:** enrollment through jump routes, multi-hop chains and alternative routes (M06-T03), and
  `permitopen` restrictions on registry lines (a later candidate, ADR-0010 §5).
- **Container variants:** Docker Desktop, devcontainers and containers inside WSL distributions
  (labelled `not-tested`).
- **Windows variants:** a Windows-side sshd fixture (no M04 claim needs one) and a Task Scheduler
  login entry (ADR-0010 §1).
- **Release work:** packaging, update and rollback, which are M08 parts of A31.
- **Re-deferred items:** Recipe A and hardware K_env (Q6).
