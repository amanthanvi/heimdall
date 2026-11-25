<!-- Archived independent review (Claude Opus 5.5, a review sub-agent), the M06 exit series (0cffdead..842044c7: C2, C4, C7/C8, C9), 2026-11-24: MERGE (five findings, none blocking). Verbatim, except: the reviewer's scratch and output directories outside the repository are shown as <reviewer scratch>, the synthetic home paths in two self-test inputs as <synthetic home path>, and the canary-shaped fixture tokens as HEIMDALL_CANARY_<fixture>. -->
# M06 exit series review: `0cffdead..842044c7` (C2, C4, C7/C8, C9; C5, C9.1 and the inventory commits for context)

Reviewer: independent review sub-agent (Claude Opus 5.5). Review only: no commits, no pushes, nothing written outside
`<reviewer scratch>/`. Worktree detached at `842044c7` after `git fetch origin`.

## Verdict: MERGE

No finding blocks under ADR-0009 §2.1. None combines a lasting effect on remote trust, recovery records or owner data
(or a consent bypass) with a trigger Heimdall must withstand. The Windows paths (C2, C7, C8) were reviewed by reading
only; their native evidence is the exit PC run, which has not happened yet for `842044c7`. R01 goes to `RESIDUALS`.
R02, R03 and R05 are one-line or one-function fixes worth folding into the next commit. R03 needs a contract-owner
ruling before code changes.

## Findings

### M06-X-R01: the fill and the guard trust any inherited `ProgramData`, and the "from the OS" values follow Heimdall's own environment

- **Severity:** Low (defence in depth; a residual).
- **Blocks under §2.1:** no.
  - **Trigger:** the environment of the process that starts Heimdall. That is the user's own action or a same-user
    program (spec P03).
  - **No gain:** that program can already write `~/.ssh/config`, `~/.ssh/known_hosts` or `HKCU\Environment` as the
    user. It gets no privilege, no other user's data and no authority beyond the owner's.
  - **Disposition:** record in `RESIDUALS` with the probe below.
- **What happens:**
  1. **An inherited value is never checked.** `fill_openssh_environment` sets only variables the child would lack.
     "a variable the child already has is never changed": `crates/localenv/src/sys/openssh_env.rs:41`, `:137-143`.
     The M06 guard checks only that `ProgramData` is non-empty (`crates/app/src/remote_env_ssh.rs:585`). So a parent
     environment with `ProgramData=\\host\share` or `ProgramData=D:\anything`:
     - passes the guard on all four M06 launches;
     - reaches every other product launch unchanged (`connect` and `run` in `crates/launch/src/env.rs:163-165`, enroll,
       verify, the runtime's owned connections, local queries).
     Win32-OpenSSH resolves its system-wide files through `%ProgramData%\ssh` (the module's own docs,
     `openssh_env.rs:6`). It then reads `%ProgramData%\ssh\ssh_config` wherever no `-F` is given (an
     existing-access `connect <alias>`). It also reads its default `GlobalKnownHostsFile` (`__PROGRAMDATA__\ssh\ssh_known_hosts`)
     wherever that is not pinned. Heimdall's own launches pin it (`GlobalKnownHostsFile=none` in
     `remote_env_ssh.rs:175` and in the rendered sections); an existing-access alias does not.
  2. **The "operating system" values follow Heimdall's own variables.** The module says the values are set "from the
     operating system, never from another variable" (`openssh_env.rs:15`). In fact:
     - its own docs say `FOLDERID_ProgramData` expands `%SystemDrive%` from the calling process (`:27-30`);
     - ADR-0006 §18.9 item 13's limit (1) says `FOLDERID_Windows` relies on the caller's `windir`;
     - so a hostile `SystemDrive=D:` gives the child `ProgramData=D:\ProgramData` on any path when that folder
       exists, the WSL path included. The WSL path (`inherits=false`, `crates/wsl/src/spawn.rs:92`) is meant never to take the parent's value.
     - With `KF_FLAG_DEFAULT` the shell checks that the folder exists. So a UNC `SystemDrive` makes Heimdall's own
       process touch that share before `is_usable_folder` (`:127`) rejects the result.
  3. **`windir` is passed through unvalidated.** `value_of("windir")` returns the known folder without the
     `is_usable_folder` check that `ProgramData` gets (`openssh_env.rs:220`).
  4. **A doc claim the code does not keep.** "A known folder that does resolve (a relocated `ProgramData`) always
     wins" (`:37`) is not what the code does. A resolved but unusable value (UNC, `\\?\`) is dropped. Then, only
     without `SystemDrive`, `<drive>\ProgramData` is derived instead (`:203-213`).
- **What is sound here:** the derived path is always `X:\ProgramData` with `X` an ASCII letter. `drive_of_windows_dir`
  rejects UNC, `\\?\`, relative and `C:x` forms (`:107-115`), and the test at `:269-293` pins each one. I ran that
  test on macOS, exit 0 (below).
- **Fix (hardening, optional for this merge):**
  - In `windows_client_environment_refusal`, refuse `ssh_client_not_started` unless the effective `ProgramData`
    satisfies `is_usable_folder`. That rejects UNC, `\\?\`, relative and unexpanded values, whether they were inherited
    or filled.
  - Apply `is_usable_folder` to `windir` too.
  - Reword `openssh_env.rs:15` and `:37` to say the known folders expand from this process's `SystemDrive` and `windir`.
  - Record the residual (a same-user parent environment chooses `%ProgramData%\ssh`) with
    `sys::openssh_env::tests::missing_openssh_vars_reads_inherited_set_removed_and_cleared` as its probe. That test
    shows an inherited value counts as present.

### M06-X-R02: two product launches of `ssh` get neither the fill nor the guard

- **Severity:** Low.
- **Blocks under §2.1:** no. Both fail closed, and the only visible effect is a misleading warning. No record,
  trust or owner data changes.
- **What happens:**
  1. **`routes::verify::effective_config`** (`crates/app/src/routes_verify.rs:66-78`) starts `client -G …` with only
     `SSH_*` removals. It serves two callers:
     - the route helper's pin check (`alias_pin_defeat`, `crates/heimdall/src/m06_cmd.rs:1060-1100`);
     - `setup apply`'s after-apply check `verify_projected_helper_aliases` (`m06_cmd.rs:1240-1266`, called at
       `crates/heimdall/src/setup_cmd.rs:825`).
  2. **The jump leg's `ssh`** (`crates/app/src/routes_legs.rs:101-111`).

  The helper is a `ProxyCommand` child of an `ssh.exe` that needed `ProgramData` to start at all, so the helper's two
  launches inherit it. But `setup apply` is run directly. From a Windows process without `ProgramData`, every helper
  alias's `ssh -G` exits 255, and each alias is reported as a `HOST_PIN_DEFEATED` warning, "`unreadable`". That
  contradicts ADR-0006 §18.9 item 13 ("like every other product launch of `ssh`") and the series' premise that every
  product launch is filled.
- **Related, and existing behaviour:** the guard backstop exists only on the four M06 launches (preflight, bootstrap
  session, management session, probes). These launches fill and then start `ssh.exe` even when the fill could not
  supply `ProgramData`:
  - `connect` and `run`;
  - enroll (`crates/enroll/src/remote.rs:331`, `:489`) and verify (`crates/enroll/src/verify.rs:509`);
  - the runtime (`crates/runtime/src/connections.rs:1129`, `crates/runtime/src/service.rs:3942`);
  - the local queries (`crates/localenv/src/local_query.rs:222`);
  - the WSL helper.

  This is documented (`openssh_env.rs:41-43`), but the brief's "a guard refuses to start the client otherwise" holds
  only for M06.
- **Fix:** pass an `OpensshEnvFill` into `routes::verify::effective_config` (and so `verify_projected_alias`,
  `effective_alias_config`, `verify_jump_leg`) and into `TokioLegDialer`, as C2 did for `BootstrapSsh`. Wire
  `OPENSSH_FILL` at `m06_cmd.rs:1085`, `:1255` and `:1315`. Otherwise, narrow the ADR's sentence to the launches that
  have the fill.

### M06-X-R03: a release build accepts and records `route add --iroh`, including its exposure widening; the release-scope docs say every Iroh form refuses

- **Severity:** Low (docs overclaim and a misleading consent prompt; no bypass).
- **Blocks under §2.1:** no.
  - **Trigger:** the owner's own `route add`.
  - **Consent:** the widening still goes through the attended approval.
  - **Effect:** nothing leaves the host. The stored route and consent are inert, because the helper records the leg
    `driver_unavailable` and fails over (C4).
- **Evidence:**
  - **The CLI does not check the build.** `route_request` builds `RouteSpec::Iroh` with no check of
    `ROUTE_IROH_IN_BUILD` (`crates/heimdall/src/m06_cmd.rs:588-598`).
  - **`routes_ops::add` has no driver check.** Only the transport forms reach `check_policy`, at
    `crates/app/src/transport.rs:629`, `:994` and `:1035`.
  - **A default-feature build accepts it.** `dispatch::tests::a_relay_urls_path_is_stored_and_never_shown`
    (`crates/runtime/src/dispatch.rs:2842`) is not feature-gated, and it passed in a default-feature (`iroh` off)
    build here, exit 0 (below). The test takes an Iroh `route.add` with a custom relay through `ApprovalRequired`, then
    `Decide Approve`, then the route and its consent stored.
  - **The docs say otherwise.** These all say every Iroh form refuses, or refuses "as today":
    - `docs/compatibility/matrix.md:610`: "every Iroh form in them refuses `driver_unavailable` with a message naming
      the preview";
    - ADR-0015 §1, row 1: "without it every Iroh form refuses `driver_unavailable`";
    - ADR-0015 §3: "Their Iroh forms refuse `driver_unavailable` as today".
- **Fix:** this needs a ruling from the contract owner, because ruling Q-B only covers the helper. Choose one:
  - **(a) refuse in code:** refuse `route.add` of an Iroh route in a build without the driver.
    - Return `CAPABILITY_UNAVAILABLE`/`driver_unavailable` with `IROH_PREVIEW_UNAVAILABLE`, before any decision is
      recorded.
    - Keep C4's failover for Iroh rows that already exist (a database from a source build).
  - **(b) narrow the docs:** in `matrix.md:610` and ADR-0015, say that transport forms refuse, `route add` records the
    route, and the helper fails its leg over as `driver_unavailable`.

### M06-X-R04: the C7 Windows child test passes whether or not the fallback ran

- **Severity:** Nit (test precision).
- **Blocks under §2.1:** no.
- **What happens:** `the_fill_supplies_system_drive_and_program_data_without_the_callers_system_drive`
  (`openssh_env.rs:306-404`) asserts only the outcome: the filled values equal the parent's. If
  `FOLDERID_ProgramData` resolved in the child, the test would pass without exercising the derivation it is named for.
  PC job 53 observed the failure (`0x80070003`), so today it does exercise it, but the test does not pin that.
- **The C8 fix itself is sound:**
  - the marker starts its own line;
  - the parent requires both a zero exit and a line ending with the marker;
  - a filter that matches no test prints no marker, so the parent fails.
- **Related gap:** the failover arm `Err(DialFailure::DriverUnavailable)` after `dial()` (`routes_failover.rs:632-636`)
  has no test. The product dialer cannot reach it, because `driver_unavailable()` answers first.
- **Fix:** in the child, print whether `os::known_folder(&FOLDERID_ProgramData)` was `None`, for example
  `openssh-fill-child: ok derived=1`, and have the parent require it (or report it as an observation).

### M06-X-R05: `ordinary_login`'s option set does not pin `CheckHostIP`, so "whatever alias" overclaims

- **Severity:** Nit (test only).
- **Blocks under §2.1:** no. Every current caller passes a projected helper alias, for which no `known_hosts` write can
  happen (below).
- **What happens:** `ALIAS_PINS` (`tests/e2e/exit_m06/routes.rs:79-88`) pins `GlobalKnownHostsFile=none`,
  `StrictHostKeyChecking=yes`, `UpdateHostKeys=no` and `IdentitiesOnly=yes`. Its comment says this keeps the client
  from writing a known-hosts file "whatever alias this is called with".
  - **OpenSSH's own path** (from upstream `sshconnect.c` `check_host_key`, read from memory and not re-checked in this
    review): with `CheckHostIP yes`, a known host whose IP is new is added to `user_hostfiles[0]` even under
    `StrictHostKeyChecking=yes`. Without a `UserKnownHostsFile`, that file is the account database's
    `~/.ssh/known_hosts`.
  - **The current callers:** `routes.rs:162` and `iroh_alias.rs:304`, `:379` and `:416` all pass `exit1`, a helper
    alias. Its section sets `ProxyCommand`, which turns `CheckHostIP` off. It also renders `CheckHostIP no` and a
    scratch catalog pin file as `UserKnownHostsFile` (`crates/sshconf/src/routes.rs:164-168`). So no write is possible
    today.
- **Fix:** add `"-o", "CheckHostIP=no"` (the section's own value) to `ALIAS_PINS`, or limit the comment to helper
  aliases.

## Answers to the brief's questions

### 1. C2 and C7: the fill

- **Starting without `ProgramData`:**
  - **M06 launches:** no. The preflight (`remote_env_ssh.rs:800`), the bootstrap session (`:867`), the management
    session (`:941`) and the probes (`:1177`) each run `prepare_launch`, which applies the fill and then the guard. A
    refusal stops the launch before `spawn` (a refused probe reads as inconclusive).
  - **Other launches:** yes. If the OS fill fails they start without it, and the route helper's two launches have no
    fill at all (R02).
- **A hostile `ProgramData`:** an inherited one is accepted unchecked everywhere, and the known folders follow
  Heimdall's own `SystemDrive` and `windir` (R01). This is a same-user residual.
- **Validation of the derived path:** yes. It is always `<A-Z>:\ProgramData`. UNC, `\\?\`, relative and `C:x` are
  rejected, and the known-folder value is filtered by `is_usable_folder`. `windir` is not filtered (R01).
- **Coverage of launch paths:**
  - **The fill:** every product launch site that names `ssh` has it, except `routes_verify.rs:67` and
    `routes_legs.rs:101` (R02).
  - **The guard:** M06 launches only (R02).
- **Windows API use:** correct.
  - `SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, null token, &mut path)` is called with a valid GUID and out-pointer.
  - `hr >= 0` is the success test.
  - The NUL scan is bounded at 32,768 units, and the slice is built only from the units before the NUL.
  - `CoTaskMemFree` runs exactly once, on success and on failure, as the API requires (null is allowed).
  - The C7 rewrite removed the old `Component::Prefix` derivation, which would have accepted a verbatim `\\?\C:` or a
    UNC prefix as `SystemDrive`. That is a tightening.
- **Do the tests cover what they claim:** mostly.
  - `every_m06_launch_carries_the_fill` proves each of the four launches applies the injected fill (I ran it: exit 0).
  - `the_os_fill_reaches_an_m06_launch_without_program_data` covers the real fill on Windows, and the forced guard
    elsewhere. I did not run it: it needs the `heimdall` binary crate's test build.
  - The Windows child test does not prove the fallback branch (R04).

### 2. C4

- **Can `driver_unavailable` hide a real failure?** No.
  - It is decided statically: the leg is Iroh, there is no Iroh dialer, and `iroh_in_build` is false
    (`routes_legs.rs:256-259`).
  - `ROUTE_IROH_IN_BUILD` is `cfg!(feature = "iroh")` of `heimdall-runtime`, and `route_iroh_leg` returns `None` in
    exactly that build.
  - The leg is skipped before the client is read and before anything is dialed (`routes_failover.rs:575-581`).
  - In a build with `iroh` but no key store, the leg still reads `refused`.
  - The other `driver_unavailable` producers (the serve child at `supervise_transport.rs:2006-2019`, `availability()`
    behind `check_policy`) are also compiled only without the feature, so the new preview message cannot appear in an
    `iroh` build.
- **Can failover take a route the policy does not allow?** No. Failover still iterates only `plan.routes`, the approved
  and usable routes. A `driver_unavailable` leg has the same failover semantics `refused` had, and nothing is added.
  The terminal check runs only when `usable` is non-empty (`routes.rs:640`), so an empty plan cannot become
  `driver_unavailable`.
- **Code, reason and exit class:**
  - `CAPABILITY_UNAVAILABLE` with `driver_unavailable` matches the existing pairing (`envelope.rs:265-267`, `:318`).
  - The helper exits 5 (`m06_cmd.rs:1376-1382`) where the code's CLI class is 4 (`code.rs:226-234`). That is
    consistent with ADR-0012 §1.5 R08: helper exit codes are internal, `ssh` reports its own 255, and the other helper
    refusals already exit the same way.
  - The attempts are recorded before the refusal, as the test pins.
- **Is 6.6 purely additive?** Yes. The three schema files each gain one `const: "driver_unavailable"` alternative, and
  nothing else changes. That follows the precedent of rev 6.1 (`authentication_or_trust`) and U56 (`admission_refused`).
- **Release-scope wording:** overclaims for `route add` (R03).

### 3. C9

- **Every fixture `sshd` running as the account:** covered. I searched every file that writes an sshd configuration
  or starts `sshd`.
  - **What I searched:** `ListenAddress`, `sbin/sshd`, `hm2_sshd_*` and `LoopbackSshd` across `crates/`, `tests/` and
    `tools/`, excluding `prototypes/`.
  - **Covered, with `SetEnv HOME= ZDOTDIR= BASH_ENV=` and `PermitUserRC no`:**
    - the testkit's local `LoopbackSshd` on macOS and Linux (`crates/testkit/src/sshd.rs:772`, the only `Extras` built
      outside tests, always `Some(session_home)`);
    - `remote-lib.sh`'s `hm2_sshd_config`. That covers macOS `run-macos.sh`, the WSL runs `run-windows.sh`,
      `run-windows-local.ps1`, `lock-windows.ps1` and `run-mode-b-windows.ps1`, the Linux and devbox scenarios, the
      M03 system form (whose wrapper appends after the `SetEnv`), and `tools/benchmarks/m08`;
    - `windows-controller-runner.sh` mgmt and dest, which `crosshost-runner.sh` delegates to;
    - the `credential_cert.rs` and `enroll_verify.rs` fixtures;
    - the M05 spike driver, which also gains `PermitUserRC no`.
  - **Not the owner's account:** `target-root.sh` serves a disposable user inside the disposable distribution, and
    `tests/fixtures/ssh` and `g04_lock_probe_selftest.sh` run in containers.
- **Startup files, `~/.ssh/rc` and writes under the real `~/.ssh`:**
  - **Startup files:** no, for zsh, bash (including Debian's `SSH_SOURCE_BASHRC`, which reads `$HOME/.bashrc`), sh,
    fish and tcsh. All resolve their startup files from `HOME` or `ZDOTDIR`, which sshd's `SetEnv` overrides after it
    sets `HOME`.
  - **`~/.ssh/rc`:** no. sshd reads it relative to the working directory, which is still the real home, and every
    configuration sets `PermitUserRC no`.
  - **Remaining limits:** these stay as stated, and none is new.
    - The working directory is the account database's home, so a relative remote path would land there. I found
      none: the fixtures' `scp` and `sftp` use `$S/…` absolute paths.
    - An OpenSSH client or a `heimdall` started inside a session reads `~/.ssh` from the account database, not `HOME`.
      AGENTS.md's `-F` and `HEIMDALL_TEST_SSH_HOME` rules cover them.
- **Does `ordinary_login` rule out every `known_hosts` write?** For the aliases it is called with, yes. As stated, no
  (R05).

### 4. Regressions

The product code changes are confined to C2, C4, C7 and C8. Each changes live behaviour only as stated:

- **C2:**
  - Windows M06 launches now get `ProgramData`, `ALLUSERSPROFILE`, `SystemDrive` and `windir` when missing.
  - The interactive bootstrap session gains the guard.
  - A refused probe is inconclusive, as a silent 255 was before.
- **C4:** these apply only in a build without `iroh`.
  - The Iroh leg's class is `driver_unavailable` instead of `refused`.
  - The leg is skipped before the client's identification is read. Before, it opened the client window and then
    failed over.
  - An all-Iroh destination ends with a typed refusal and the preview message instead of `Ok` with no route. Both exit 5.
  - The serve-child and `check_policy` `driver_unavailable` messages now name the preview.
- **C7:**
  - It derives `<drive>\ProgramData` only when this process lacks `SystemDrive` and the known folder fails.
  - It now rejects an unusable known-folder value that it used to pass through.
- **C9 (tests only):** sessions now see a scratch `HOME`. A runner-side test that compares the work's `HOME` (from the
  account database, ADR-0012 §4) with the session's can now tell them apart, where before it could not.
- **`service_login_m04`:** now cleared. On Windows it keeps only `SystemRoot`, `SystemDrive`, `windir`, `ComSpec`,
  `PATHEXT`, `PATH`, `TEMP` and `TMP`, plus a scratch `HOME` and `USERPROFILE` (`tests/e2e/service_login_m04.rs:131-160`).
  It no longer has `LOCALAPPDATA`, `APPDATA` or `USERNAME`. Whether the Windows row still passes is unverified until the
  exit PC run.

### 5. Secrets and personal data in added lines

None found. The only hits are synthetic redaction-test inputs:

- in `tests/native/m06/selftest_synthetic.py`: `HEIMDALL_CANARY_<fixture>`, `S-1-5-21-1-2-3`, `<synthetic home path>`,
  `192.0.2.7` (a private-range address when reviewed, replaced 2026-11-25 by this documentation address) and `<synthetic home path>`;
- in `record-windows-controller.ps1`'s self-test: `HEIMDALL_CANARY_<fixture>`, `10.1.2.3`, `2001:db8::5` and `Some One`;
- the SHA-256 of `abc` and an all-zero commit.

No home paths, host names, addresses, emails, keys or tokens of the owner's appear.

## What I found sound

- **The C2 seam:** one `prepare_client_environment` for all four M06 launches. The guard runs over the launch
  environment the child will actually get (`launch_env_value`, last change wins, Windows case-insensitive), and
  `heimdall-app` still does not depend on `heimdall-localenv`.
- **C7's derivation:** strict drive parsing, no change to this process's environment, and the fallback only without
  `SystemDrive`.
- **C4's skip:**
  - It records the attempt with a duration and never dials.
  - It is reported per route, and the terminal refusal comes only after the attempts are recorded.
  - The preview prefix is pinned by a test across the transport and the helper.
- **C9:** one `SetEnv` line everywhere (sshd keeps the first), `enroll_verify.rs` folds a caller's `SetEnv PATH=` into
  it, and `PermitUserRC no` is in every account-run configuration.

## Commands run (macOS, this worktree at `842044c7`; real exit codes)

| Command | Exit |
|---|---|
| `git fetch origin`; `git checkout --detach 842044c7` | 0 |
| `cargo test -p heimdall-localenv -p heimdall-app --lib --no-run` | 0 |
| `heimdall_localenv-… openssh_env` (2 tests: `missing_openssh_vars_reads_inherited_set_removed_and_cleared`, `the_system_drive_and_default_program_data_derive_from_the_windows_directory`) | 0 |
| `heimdall_app-… the_fill_supplies_what_the_parent_environment_lacks without_the_fills_source_the_guard_still_refuses every_m06_launch_carries_the_fill an_iroh_leg_without_the_driver a_destination_whose_every_leg_is_iroh every_iroh_preview_refusal_shares_one_prefix` (6 tests) | 0 |
| `heimdall_app-… routes::` (21 tests, including all 12 `routes::failover::tests`; no real `ssh`) | 0 |
| `cargo test -p heimdall-runtime --lib --no-run` (default features, `iroh` off) | 0 |
| `heimdall_runtime-… a_relay_urls_path_is_stored_and_never_shown` (scratch `HOME`, `HEIMDALL_HOME`, `HEIMDALL_TEST_SSH_HOME` and fixture stores; R03's evidence) | 0 |
| `cargo test -p heimdall-testkit --features fixtures --test integration_testkit_fixtures --no-run` | 0 |
| `<reviewer scratch>/probe/sshd_t_setenv.sh` (after 15:50Z). It runs `sshd -T` over scratch configurations shaped like the fixtures', with a per-run host key; it binds nothing and serves no session. The first run printed no keys: its `awk` matched lowercase keys, and this sshd (`OpenSSH_10.5p1`) prints `SetEnv`. Re-run with case-insensitive matching | 0 |
| An inline `sshd -T -f <scratch config>` with two `SetEnv` lines, to see the key spelling, plus `sshd -V` (`OpenSSH_10.5p1, LibreSSL 3.3.6`) | 0 |
| `integration_testkit_fixtures-… fixture_sshd_session_has_a_scratch_home_and_no_account_startup_files --exact --nocapture` (after 15:50Z; scratch `HOME` and the fixture stores; the fixture's own isolated client, `-F`, scratch known-hosts files and a decoy agent) | 0 |
| `ps -U <uid> -o pid=,ppid=,lstart=,comm=`, filtered to `sshd` (pid, ppid and comm printed): no leftover fixture `sshd` | 0 |
| `git diff 0cffdead..842044c7`, added lines only, grepped for home paths, emails, keys, tokens, SIDs, canaries, IPv4 addresses and host names | 0 |

**Probe results (observed):**

- **`one`, the fixture's single `SetEnv` line with quoted paths containing a space, and `BASH_ENV=`:** `sshd -T` shows
  `SetEnv HOME=<scratch>/session home`, `SetEnv ZDOTDIR=<scratch>/session home` and `SetEnv BASH_ENV=`, along with
  `PermitUserRC no` and `PermitUserEnvironment no`.
- **`two`, a second `SetEnv PATH=` line after it:** the same three variables, and no `PATH`.
- **`rev`, the `PATH` line first:** only `SetEnv PATH=/x:/usr/bin`. `HOME`, `ZDOTDIR` and `BASH_ENV` are gone.

This confirms the series' premise that sshd keeps only its first `SetEnv` line. The consequence is that any future
caller that writes a `SetEnv` before the fixture's silently restores the account's `HOME`. `enroll_verify.rs` guards
against that by asserting a single `SetEnv` line; `remote-lib.sh` and the testkit rely on being the only writer. A
guard of the same kind in `hm2_sshd_start`, such as `grep -c '^SetEnv' "$dir/sshd_config"` = 1, would make the
convention checked rather than commented. That is optional and not a finding.

**Fixture test (observed):** `m06 observation: fixture-sshd-env home=scratch zdotdir=scratch bash_env=empty
login_shell=zsh`. On this Mac the account's login shell (zsh) ran the command with the scratch `HOME` and `ZDOTDIR` and
an empty `BASH_ENV`. Afterwards no `sshd` owned by this user was left running (`ps`, selected fields only).

## What I did not check

- **Anything on Windows.** I could not run Windows code here. C2's and C7's Windows paths, the `SHGetKnownFolderPath`
  behaviour without `SystemDrive` and `windir`, C8's child test, and `service_login_m04` under its new cleared Windows
  environment were reviewed by reading only. They are `blocked` on the Windows PC, the exit PC run of `842044c7`.
- **WSL and the devbox.** I did not run C9's `remote-lib.sh` and `windows-controller-runner.sh` configurations there.
  On macOS, the testkit path and `sshd -T` parsing were run.
- **Linux bash's `SSH_SOURCE_BASHRC` behaviour.** I took it from bash's build option and did not run it. Both cases
  read `$HOME`, which is now scratch.
- **`m06_cmd::tests::the_os_fill_reaches_an_m06_launch_without_program_data`.** It needs the `heimdall` binary crate's
  test build. I did not build it, to keep load down. On macOS it asserts only the forced guard, which
  `without_the_fills_source_the_guard_still_refuses` already covers, and I ran that one.
- **Whole-workspace runs:** `check.sh`, the `iroh`-feature targets, `transport_supervise_m06` and the M06 e2e suites.
- **Two claims taken from upstream knowledge, not re-checked here:**
  - the OpenSSH `CheckHostIP` behaviour in R05;
  - Win32-OpenSSH's `__PROGRAMDATA__\ssh\ssh_known_hosts` default in R01.
- **C5 (`6f2cc7eb`), C9.1 (`509b234a`) and the inventory commits** (`a10eec63`, `9399e768`, `842044c7`): read for
  context only. Their product-code footprint is nil (`git show --stat`). C9.1 changes only the observation line's
  prefix, which matches the output above.
- **`7db78298`** (harness `Protect-Reason`): skimmed only.

## Cleanup

- **Build output:** the worktree's `target/` was 4.6G (`du -sh target`) and has been removed. `du -sh target` now
  reports `No such file or directory`.
- **Scratch and the worktree:** each scratch directory (`<reviewer scratch>/hm-rev-*`) was removed in the command that made it, and
  none remains. `git status --short` in the worktree is clean.
