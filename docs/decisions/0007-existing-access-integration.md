# ADR-0007 — Existing-access integration (M02): managed OpenSSH projection, nonexecuting discovery, existing-access adapters, and the process contract

**Status:** proposed · **Date:** 2026-11-01 · **Task:** M02-T00-design
**Gates:** the existing-access portions of G03 and G08 (plan §5 M02).
**Affects:** R-UX-01, R-UX-04, R-CR-01, R-CR-08, R-SS-01, R-SS-02, R-SS-03, R-SS-04,
R-AP-06, R-RT-04, R-RT-05, R-SE-04, R-DI-04, R-DI-06. Exit cases A01, A11, A21, A22, A27
and A35 (spec §17).
**Companion:** `docs/architecture/m02-plan.md` (units, tests, evidence plan). The contract
additions in §10 are proposed as **ADR-0006 revision 3 deltas**. This ADR does not edit
ADR-0006; the integrator applies the deltas after the rulings in §12.
**Not decided here:** anything §12 lists as a question. Authority semantics fixed by the
spec, ADR-0004, ADR-0005 or ADR-0006 are not changed.

**Evidence labels.** `[S01]`…`[S34]` are spec §19 sources, read from the pinned snapshots
in `docs/sources/snapshots/` (ssh_config(5) footer "OpenBSD-current September 20, 2026";
ssh(1) "September 5, 2026"; ssh-agent(1) "September 18, 2026"; 1Password pages by
`dateModified`, `docs/sources/pins.json`). `[G03-Sxx]` are the G03 source pins
(`docs/research/g03-windows-wsl.md` §1). `[O P-Wxx]` / `[O P-Axx]` are G03 native
observations (§0.1/§0.2 there). `[I]` is this author's inference and `[U]` unknown: each
names the test that settles it. Quoted fragments are verbatim from the snapshot.

## 1. Context

M02 delivers the existing-access vertical slice (plan §5 M02, T01–T06). Ordinary `ssh`,
Git, SCP and SFTP must work after setup without a mandatory launcher (spec §10.3,
R-UX-01). Adoption must be previewed, atomic, reversible and must preserve unrelated
configuration (spec §10.1, C12, R-SS-01). Default diagnostics must be passive (spec §10.2,
R-SS-02). The native agent and 1Password must be usable without exporting keys and with
their own controls intact (R-CR-01, R-CR-08). `run` must keep child streams byte-clean
(spec §10.4, R-SS-04).

M01 supplies the substrate this design reuses: journaled operations with recovery intents,
effect tokens and stage receipts (ADR-0006 §14.1); server-issued decision records completed
only on attended sessions (ADR-0006 §3.1); generation-tagged managed resources; the
supervisor's single cleanup executor over `ResourceCleaner` (m01-plan U8); idempotency
(ADR-0006 §7); and the `CredentialAdapter` port (`crates/app/src/ports.rs`).

OpenSSH facts this design depends on:

| # | Fact | Source |
|---|---|---|
| F1 | "Unless noted otherwise, for each configuration directive, the first specified value will be used"; sources are read in the order command line, user file, system file | [S01] |
| F2 | "Multiple IdentityFile directives will add to the list of identities tried"; CertificateFile likewise accumulates | [S01] |
| F3 | "Include directive may appear inside a Match or Host block to perform conditional inclusion"; relative Include paths resolve under `~/.ssh` (user) or `/etc/ssh` (system); globs expand "in lexical order" | [S01] |
| F4 | "The exec keyword executes the specified command under the user's shell"; ProxyCommand, LocalCommand (with PermitLocalCommand) and KnownHostsCommand also execute commands | [S01] |
| F5 | `-G` prints the configuration "after evaluating Host and Match blocks"; so `ssh -G` runs `Match exec` | [S02], [S01], spec §10.2 |
| F6 | `-F`: "If a configuration file is given on the command line, the system-wide configuration file … will be ignored" | [S02] |
| F7 | Tokens "are expanded without quoting or escaping of shell characters"; `%%` is a literal `%`; `${VAR}` expands in CertificateFile, ControlPath, IdentityAgent, IdentityFile, Include, KnownHostsCommand and UserKnownHostsFile, and an unset variable makes that setting ignored | [S01] |
| F8 | IdentityAgent "overrides the SSH_AUTH_SOCK environment variable"; `none` disables the agent | [S01] |
| F9 | A public-key path in IdentityFile selects "the corresponding private key that is loaded in ssh-agent(1)"; IdentitiesOnly limits the offered identities to the configured ones | [S01] |
| F10 | ProxyJump "will compete with the ProxyCommand option - whichever is specified first will prevent later instances of the other from taking effect" | [S01] |
| F11 | ssh "exits with the exit status of the remote command or with 255 if an error occurred" | [S02] |
| F12 | An agent socket "is easily abused by root or another instance of the same user" | [S30] |
| F13 | Windows: the in-box client sets `SSH_AUTH_SOCK` to `\\.\pipe\openssh-ssh-agent` when unset; `Match exec` and ProxyCommand run through `system()` | [G03-S02] [S] (G03 Q03, Q19) |
| F14 | Windows: in IdentityAgent, `\\.\pipe\x` reaches nothing; `//./pipe/x` (also quoted, with spaces or non-ASCII) selects exactly that pipe; in SSH_AUTH_SOCK any non-ASCII pipe name fails | [O P-W03], [O P-W02] |
| F15 | Windows: a path containing `%` works only in `%%` form | [O P-W08] |
| F16 | Windows: Git's bundled MSYS ssh cannot use Windows named pipes; `GIT_SSH_COMMAND` > `core.sshCommand` > `GIT_SSH` | [O P-W02/P-W04], [G03-S13] |
| F17 | 1Password asks "for your consent before an SSH client or terminal session can use your key"; when locked it "will prompt you if an SSH client tries to use one of your keys" and "doesn't keep your private keys in memory"; approvals are wiped when it locks (default) | [S06], [S07] |
| F18 | 1Password on Windows takes over `\\.\pipe\openssh-ssh-agent` after the OpenSSH agent service is disabled | [G03-S12] |
| F19 | OpenSSH resolves `~` and the user configuration from the account's home directory, not `$HOME` | [I]; settled by test `integration_doctor::home_resolution_matches_ssh_g` (m02-plan U3) |

## 2. D1 — One Heimdall-owned include file, referenced by one marked Include block

Heimdall's OpenSSH projection consists of exactly two owned artifacts per environment:

1. **P, the managed file**, wholly owned by Heimdall: `<config_dir>/ssh_config` from the
   M01 `Paths` (on Unix the XDG location `~/.config/heimdall/ssh_config`, which is spec
   §10.1's representative path; on Windows the Known Folder that `Paths` resolves, rendered
   as an absolute forward-slash path, spec §10.1 "not a universal Windows path").
2. **B, the include block**, three lines in the user's own configuration file (Unix
   `~/.ssh/config`; Windows `%USERPROFILE%\.ssh\config` [G03-S08]). Heimdall owns only these
   lines:

   ```sshconfig
   # >>> heimdall managed include (id hm-<16 hex>); remove with `heimdall setup rollback`
   Include "<path of P>"
   # <<< heimdall managed include (id hm-<16 hex>)
   ```

Heimdall never edits any other line of the user's files, and never writes the system-wide
configuration (spec §5.2 "Permission to adopt is not permission to rewrite unrelated
configuration"; R-DI-02). Public-key files used for identity selection (F9) are
materialized under `<config_dir>/keys/<SHA256 fingerprint, base64url>.pub`. They are public
data (spec §7.3) and owned artifacts of the same projection.

**P contains only `Host <literal alias>` sections.** It has no wildcard or negated patterns,
no `Match`, no `Include`, and no directive that executes anything (ProxyCommand,
LocalCommand, PermitLocalCommand, KnownHostsCommand; F4). It never weakens host
verification: no StrictHostKeyChecking, UserKnownHostsFile, GlobalKnownHostsFile or
CheckHostIP (spec §9.1, §14.4). It never enables forwarding (ForwardAgent and the forward
directives; spec §8.5). The M02 directive set is closed: HostName, Port, User,
IdentityAgent, IdentityFile (public-key paths only) and IdentitiesOnly. CertificateFile
(M03) and ProxyJump between managed aliases (M04) join later through a revision of this
list.

**Two alias kinds.** A destination is either **managed** (Heimdall renders its section in
P) or **observed**, which is adopt-in-place: the user's configuration defines it and
Heimdall records it but renders nothing for it. Adoption never converts an observed alias
by editing the user's sections.

## 3. D2 — Placement and precedence

**B is inserted before the first `Host`/`Match` line and before any top-level directive**
of the user file. Only leading comment and blank lines, and a UTF-8 BOM if present, stay
above it. Two reasons:

* An Include after any `Host`/`Match` line is conditional on that section (F3). An
  appended block would silently apply only to the last section of the file.
* For directives P sets, the first obtained value wins (F1). At the top, a managed alias
  therefore gets exactly the values Heimdall rendered, whatever the user's later `Host *`
  defaults say. This includes a user-wide `IdentityAgent` that would otherwise override
  the intended agent (F8; the A35 "configuration that overrides SSH_AUTH_SOCK" fixture).
  Directives P does not set fall through to the user's configuration. The preview shows
  them as **inherited**, with file and line.

**Consequences that the evaluator (§6) proves for each preview:**

1. **Unmanaged names are unaffected.** P's patterns are literal managed aliases, so a name
   that equals none of them matches no section of P. Its effective configuration is
   byte-for-byte what it was (A01 "unaffected existing aliases still work"). There is one
   exception, found and reported: a canonicalization pass (CanonicalizeHostname) can
   rewrite a name into a managed alias. The evaluator marks such names undetermined
   instead of claiming them unaffected.
2. **Managed values are static.** Every directive P sets for a managed alias is determined
   statically, even when the user's later configuration contains `Match exec`. The user's
   file can reach those values only through command-line `-o`, which is the caller's
   explicit choice (F1).
3. **Accumulating directives merge.** A user `Host *` IdentityFile is appended after
   Heimdall's (F2). The preview lists the full identity order. Doctor reports the finding
   `inherited_identities` when the inherited entries could exceed the destination's
   authentication-attempt budget.
4. **Collisions are refused.** A managed alias must not equal a name that a *literal* user
   pattern matches. Such an apply is refused with `CONFIG_CONFLICT` and next action
   `review_config` (adopt the alias as observed, or rename it). A match by a user wildcard
   is allowed and shown as inherited.

**The include restores the containing file's state** after the included file is read, so
a `Host` section ending P does not capture the user lines below B. This is
`[I]`: the behaviour is consistent with F3, but no pinned excerpt states it. The corpus
test `integration_sshconf_vs_ssh_g::include_state_is_restored_after_included_file` settles
it against each target client (macOS 10.3p1, the Linux devbox client, Windows in-box
9.5p2) with `ssh -G -F <inert corpus>`.

**Command-line `-F` drops both the user and the system files (F6).** Heimdall therefore
never uses `-F` for ordinary or bound use; tests use it for the reason in §9.

## 4. D3 — Rendering rules

Rendering is a pure, deterministic function of the projection spec: P's bytes depend only
on its inputs. Aliases are sorted bytewise, directives come in a fixed order, the newline
is LF on every platform, there is a trailing newline, and no timestamp or generation
number appears. The newline choice is `[I]` for Win32-OpenSSH; the Windows run of
`integration_projection::rendered_file_loads_on_target_client` settles it. In B, the
newline style follows the user file (LF or CRLF), detected from its first line ending.

| Value | Rule | Source |
|---|---|---|
| alias | `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; no `*`, `?`, `!`, `,`, whitespace or `%` | patterns [S01] |
| HostName | DNS name `[A-Za-z0-9.-]`, IPv4, or IPv6 literal; no `%` (token expansion) | F7 |
| User | the contract `AccountName` token rule; no `%` | F7 |
| Port | 1–65535 | [S01] |
| paths (Include, IdentityFile, IdentityAgent) | always double-quoted; `%` is written `%%`; refused if they contain `${`, `"`, a control character or a newline; on Unix also refused with `\`; on Windows written with `/` separators | F7, F15, [O P-W08] |
| Windows pipes | written `//./pipe/<name>`; never `\\.\pipe\…` | F14 |
| home-relative paths | `~/…` when under the account home (F19), otherwise absolute | F3 |

A value that breaks a rule is refused with `USAGE_ERROR` before anything is written. A
label containing shell metacharacters is either refused or written as inert data; P never
places a label in a directive that is executed (spec §14.3).

## 5. D4 — Adoption, rendering and rollback: journaled, CAS-guarded, never restored from a snapshot

**Preview** is read-only (no operation ID; like `inspect`). It loads the user configuration
tree, the current P and the catalog, and renders the new P and the new user-file bytes. It
evaluates the relevant behaviour of every literal alias name in the tree plus every managed
alias, before and after (§6). It returns the diff, the inherited values, the findings and
`plan_digest` = SHA-256 over the canonical plan. The plan includes the base digests of
both files. Preview runs in the runtime, which reads the files through `heimdall-localenv`,
the same user's process.

`setup preview --evaluate` adds a cross-check: it runs `ssh -G -F` on temporary copies of
the user file before and after the change. Because this executes `Match exec` (F5), it is
labelled with the `evaluate` level (§6) and is never part of the default preview. The
`-F` copies drop the system file on both sides (F6). The system file is read after the
user file (F1), so it can only fill directives that neither side sets. The comparison
records this limit.

**Apply** is a journaled operation (ADR-0006 §14.1). Whether apply needs a decision record
is question **Q1** (§12). Steps:

1. Recompute the plan. If `plan_digest` differs from the request's, refuse with
   `CONFIG_CONFLICT` ("preview is stale").
2. Persist the recovery intent, mint the effect token, and write the `Attempted` receipt.
3. Write P: temporary file in the same directory (exclusive create, mode 0600 on Unix),
   fsync, then a compare-and-swap check: the current P must have the digest recorded for
   generation N, or be absent at first adoption. Then rename over P and fsync the
   directory.
4. Write B the same way, comparing against the user-file digest in the plan. Unix: a
   temporary file with the original's permission bits, then rename. Windows: `ReplaceFileW`,
   which keeps the original's ACL and attributes (`[I]` from the Win32 contract; settled
   natively by `integration_projection::windows_replace_preserves_dacl`).
5. Record `ConfigProjection` resources for P, B and the key files at generation N+1, with
   the content digest and the file identity (Unix device and inode; Windows file ID). Write
   the `Confirmed` receipt.

P is written before B, so B never points at a file that is not yet written. Rollback
removes B first, then P.

**Concurrent edits.** Every write compares the content digest twice: against the plan,
and again immediately before the rename. A mismatch is `CONFIG_CONFLICT`: nothing is
overwritten, and the result names the conflict kind:

| Kind | Meaning |
|---|---|
| `user_config_changed` | the user file changed since the preview |
| `managed_file_edited` | P no longer has the recorded digest |
| `marker_edited` | lines inside B were changed |
| `marker_duplicated` | B occurs more than once |
| `include_conditional` | the user moved B below a `Host`/`Match` line |
| `unmanageable_file` | the user file is a symlink, has a hard-link count above 1, is not a regular file, is owned by another user, or is not writable |

Each kind has a targeted `setup repair` resolution and never a blanket restore (spec §10.1
"A stale backup cannot overwrite a subsequently edited configuration"). For
`unmanageable_file`, Heimdall prints the exact block in **manual mode**, and doctor
afterwards verifies that the block is present and placed correctly. A write cannot be made
atomic against an editor that does not cooperate: the window between the last digest check
and the rename remains. It is disclosed and kept to one comparison (`[I]`; neither POSIX
`rename` nor `ReplaceFileW` compares content).

**Snapshots.** Before the first edit, the original user file is copied to
`<state_dir>/backups/ssh_config.<UTC timestamp>.orig` (0600; owner-only ACL on Windows).
Heimdall never restores it automatically. It exists for manual recovery, `setup status`
lists it, and only `uninstall --purge-state` deletes it.

**Rollback** removes B only when its bytes equal the recorded block. If they differ, the
result is `marker_edited` and Heimdall shows the exact lines to remove. P is removed only
when its digest matches; otherwise it is renamed to `ssh_config.hm-conflict-<generation>`.
Lines the user added anywhere else survive. `remove(insert(x)) == x` holds byte-for-byte
when nothing else changed (property test, m02-plan U2).

**Crash recovery and stale cleanup.** Every step can be observed locally. `reconcile(token)`
therefore never leaves a local projection in `outcome_unknown`. It reports applied, not
applied, or partial (P written, B not), and the operation finishes forward under the same
plan, or settles `failed` with `CONFIG_CONFLICT` when the base changed. Deleting P or a
key file goes through the supervisor's single cleanup executor with the generation check of
M01 (R-RT-04): a cleanup for generation N never deletes the content of generation N+1.

**Uninstall** = rollback of every projection, removal of the key files, a graceful runtime
stop (`Request::Shutdown`), and removal of the runtime endpoints and `instance.json`. It
reports what remains: the state store, the backups, and from M03 any remote enrollment
(spec §7.7, R-DI-04). Whether the state store is kept by default is **Q6**.

## 6. D5 — Nonexecuting discovery and the probe ladder

**Static evaluation is the default and executes nothing from configuration** (spec §10.2;
F4, F5). `heimdall-sshconf` is a pure parser and evaluator. It follows the OpenSSH ≥ 8.7
tokenizer [G03-S04]. Clients older than the M02 floor of 9.5 (the lowest target, in-box
Windows [O P-W01]; ADR-0004 E6) get the finding `client_unsupported_version`. It evaluates
in three values:

* every directive is `Unset`, `Determined(value, provenance)`, or `Undetermined(candidate
  values with provenance)`;
* a section whose condition cannot be decided statically makes every directive it sets
  that is still `Unset` `Undetermined`, with the section's value as one candidate and every
  later candidate added;
* accumulating directives (F2) carry ordered candidate lists with per-entry conditions;
* **soundness property**, tested by proptest: for every assignment of the undecidable
  conditions, the concrete evaluation is one of the candidates.

**Match criteria classification:**

| Criteria | Static treatment |
|---|---|
| `all`, `host`, `originalhost`, `user`, `localuser`, `version`, `tagged` (tags from `Tag` directives seen so far) | decided |
| `command`, `sessiontype` | decided per invocation profile: interactive shell, exec (Git), subsystem `sftp` (SFTP and SCP) |
| `canonical`, `final` | the final pass is modelled; decided when CanonicalizeHostname is `no`, otherwise undetermined (canonicalization needs DNS) |
| `exec` | **never run**; undetermined, reason `match_exec` |
| `localnetwork` | undetermined at the static level, reason `match_localnetwork` |
| unknown criterion or unknown directive (not covered by `IgnoreUnknown`) | ssh itself rejects the file; reported as `config_invalid` |

**Reading files is bounded and hostile-input safe** (R-SE-05, spec §14.3):

* only regular files, checked with `fstat` after a non-blocking open, so a FIFO or device
  never blocks;
* at most 1 MiB per file, 8 MiB in total, 256 files, an include depth of 16, 256 glob
  results and 4096 bytes per line;
* include cycles are detected;
* glob order is bytewise (F3 "lexical order");
* `${VAR}` and tokens in Include paths expand per alias (F7);
* private-key files are never opened. An identity whose `.pub` is missing is reported as
  "public key unknown".

**The probe ladder.** The levels are those spec §10.2 lists. Each explicit level states
what it executes, and the report names every level performed and every level declined.
Explicit levels need `--active-probe <level>[,…]` (or the TUI equivalent).

| Level | Does | Never does | Default |
|---|---|---|---|
| `static` | parse and evaluate the configuration; stat agent sockets; list `\\.\pipe\` names without opening any; read `known_hosts` and `.pub` files; read the Heimdall store **read-only**; with **Q4**, local queries that read no configuration (`<client> -V`, `ssh-keygen -F <host> -f <file>`, `git config --global/--system --get-all core.sshCommand`) | execute configuration, contact an agent or provider, use the network, sign, mutate anything | yes |
| `evaluate` | `ssh -G <alias>` with the user's real configuration, after listing the executing constructs found (file:line) | network, signing | no |
| `agent` | connect to a named agent endpoint and send `SSH_AGENTC_REQUEST_IDENTITIES` only; bounded (256 KiB reply, 1024 identities, 2 s) | sign, add, remove, lock, extensions | no |
| `network` | TCP connect to HostName:Port and read the SSH identification line (RFC 4253 §4.2); 5 s | key exchange; aliases routed through ProxyJump or ProxyCommand (reported undetermined) | no |
| `host_verification` | `ssh -o BatchMode=yes -o PreferredAuthentications=none -o IdentityAgent=none -o IdentityFile=none -o ControlMaster=no -o ControlPath=none <alias>`, classified from the exit code (F11) and bounded stderr markers | signing | no; needs `evaluate` as well when the alias's configuration executes anything (F4) |
| `authentication` | `ssh -T -o BatchMode=yes -o ControlMaster=no -o ControlPath=none <alias> exit 0`; signs once through the configured agent | under `--non-interactive`, run for an identity whose interaction is not `none` (Q2) | no; same `evaluate` rule |

Every child that a probe starts runs with a timeout and its own process group (Unix) or a
job object with kill-on-close (Windows). Both are owned by the probe, so a hanging `Match
exec` is killed with its descendants. Probe children are Heimdall's own diagnostic work,
unlike the user's `run` children in D7.

The doctor report and its finding codes are contract types (§10, `contract::doctor`).
Statically, doctor exits 0 when it completes, whatever its findings. The findings carry
severity and a `next` action. Paths are shown with `~` for the home directory, and
`--redact` removes hostnames and user names (spec §13.6).

## 7. D6 — Existing-access adapters and provider interaction states

**Mechanisms.** `native_agent` and `onepassword` implement `CredentialAdapter`. They are
external signers (spec §7.2) and, per ADR-0004 E-3, **filtered-convenience upstreams**:
results and setup never claim isolation or destination enforcement through them (F12, spec
§8.4). Heimdall never signs with them, never adds, removes or locks keys, and never exports
anything (R-CR-01).

* **`prepare`** is local only. It runs passive checks, and its only effect is materializing
  the binding's integration: environment values and executable choices (§8). It returns:
  * `credential_ref` = mechanism + endpoint + fingerprint;
  * `enforcement`: `destination_scope` = `client_routing` for managed aliases, otherwise
    `unenforced_intent`; `new_authentication_expiry` = `none`; `workload_isolation` =
    `shared_os_user`; `existing_connections` = `unknown`;
  * `refresh_dependency` = `provider_interaction` (1Password) or `none` (native agent);
  * the new `credential_availability` and `provider` fields (§10).
* **`revoke`** removes the binding's integration and reports `remote_pending` empty and
  `latest_possible_credential_expiry` absent. The key stays usable outside Heimdall, and
  the `enforcement` fields already say so (spec §6.7, R-AU-08).
* **`reconcile`** observes the local materialization, so there is no unknown outcome.

**Detection is passive:**

* Unix: `SSH_AUTH_SOCK` and its stat (socket type, owner UID); the documented 1Password
  socket path and the presence of its `agent.toml` (G03-S12 lists the agent/config page;
  the exact path strings must be added to the pinned excerpts before T03 relies on them).
* Windows: names under `\\.\pipe\` without opening them. Which provider serves
  `openssh-ssh-agent` is ambiguous passively (F18). It is reported as `unknown`, with an
  `[I]` hint from the `ssh-agent` service state and the 1Password process; the record keeps
  the label `[I]`.

**Interaction profile per identity.** It is recorded at adoption and drives every result:

| Identity | `interaction` | Basis |
|---|---|---|
| 1Password | `provider_approval`, plus `provider_unlock` while locked | F17 |
| native agent | `none` (declared), unless the key type is `sk-*`, which gives `hardware_presence` | [S01] key types; confirm-constrained keys cannot be detected passively, which is disclosed |
| any key whose `.pub` is a FIDO type | `hardware_presence` | public key type |

**Provider states** (`ProviderStatus`, §10) carry:

* `availability`: `available` | `locked` | `unavailable` | `unknown`;
* `interaction`: `none` | `provider_approval` | `provider_unlock` | `hardware_presence` |
  `passphrase` | `unknown`;
* the probe level that observed it, `observed_at`, and a basis: `observed` | `documented`
  | `inferred` | `declared`.

Passive checks can establish `unavailable` (no endpoint) and `unknown`. `locked` needs the
explicit `agent` level: a native ssh-agent locked with `ssh-add -x` is expected to list no
identities (`[I]`; settled by `integration_adapters::a11_locked_native_agent_lists_nothing`
against a disposable `ssh-agent`). 1Password's listing behaviour while locked is `[U]`, and
its live test is blocked (m02-plan §7).

**Results and codes:**

| Situation | Result | Next action |
|---|---|---|
| endpoint absent | `SERVICE_UNAVAILABLE`, `resource.kind = "provider"` | |
| caller minimum `unattended` (§10) not met: 1Password stops on lock (F17); native agent lock continuity is `unknown`, and unknown never satisfies a minimum (ADR-0006 §14.4 (d)) | `CAPABILITY_UNAVAILABLE` (exit 4) | |
| a probe observed `locked` | `PROVIDER_LOCKED` (exit 3) | `interact` with `provider_interaction` |
| a human step the provider owns is needed now under `--non-interactive` | `INTERACTION_REQUIRED` (exit 3) | `interact` with `provider_interaction`, never a `decision_ref` (spec §5.5) |
| none of the above | `ACCESS_READY`, with `credential_availability` = `interaction_required` (1Password) or `current_only` (native agent), and no claim of unattended use | |

Provider dialogs are reported as the provider's, not as Heimdall prompts: `decision_ref`
belongs only to Heimdall's own decision records (spec §5.5).

**Identity selection.** Every managed alias gets `IdentityAgent <provider endpoint>`,
`IdentityFile <materialized .pub>` and `IdentitiesOnly yes` (F8, F9). The agent is asked to
sign only with the adopted key: there is no fallback to other agent keys (A11 "no
unapproved fallback"), and too-many-keys failures are avoided (A35).

## 8. D7 — Process contract: `run`, `connect`, TUI handoff

**Unix `run` replaces itself with the child (`exec`).** The sequence:

1. `ensure` and `bind`;
2. resolve the program;
3. write the side-channel record `launching`;
4. `execve` through `std::os::unix::process::CommandExt::exec`.

The Heimdall process becomes the child, so these are exactly the platform's: exit status
and death by signal, job control (stop and continue by the shell), terminal ownership,
stdio, working directory and signals. This removes the launcher stop-mirroring failures
that both G02 prototypes showed (ADR-0002 §6, §6.1, "M01 must design exec-equivalent job
control"). Nothing Heimdall prints reaches stdout. Pre-launch diagnostics go to stderr
(spec §10.4).

Disclosed residuals:

* Rust std resets SIGPIPE to default in the child, so a SIGPIPE ignored by the caller is
  not preserved (ADR-0002 §5). Test `run_m02::sigpipe_disposition_is_documented` pins
  this.
* A death of Heimdall between writing `launching` and `execve` is indistinguishable from
  the child dying by the same signal.

**Windows `run` spawns the child and waits.** Windows has no `exec`. The child inherits
the console and the stdio handles directly: Heimdall relays no bytes, so the streams are
byte-clean by construction. While waiting, Heimdall installs a console control handler
that consumes CTRL_C and CTRL_BREAK (tokio's `windows::ctrl_c`/`ctrl_break`). The child,
sharing the console, receives the event itself, and Heimdall then exits with the child's
exact 32-bit exit code. **No job object:** kill-on-close would kill grandchildren the tool
left running on purpose after a normal exit, which `exec` on Unix would not do. If the
launcher is terminated, the child keeps running; this is disclosed.

**Program resolution** is done by Heimdall, never by a shell, and is never resolved
implicitly from the current directory:

* Unix: `PATH` without empty entries or `.`. An `argv[0]` containing `/` is used as given.
* Windows: an explicit path, else `PATH` × `PATHEXT` restricted to `.exe`, `.com`, `.cmd`
  and `.bat`. These are the Q-B batch rules (ADR-0004 §1): `.cmd`/`.bat` targets run; std
  escapes their arguments; an argument std refuses to escape, or a script path containing
  any of `% ! ^ & | < > " ( ) , ; =` or a control character, is refused. This closes the
  §9.7 path gap that ADR-0002 §3.1 observed.

**Exit codes:**

* a pre-launch failure in Heimdall uses the ADR-0006 §6 table;
* a program that cannot be launched (not found, refused, current directory) exits **127**,
  and one found but not executable exits **126**, both with the new code `LAUNCH_FAILED`
  (§10; Q-B fixes 127);
* after launch, the status is the child's;
* the side channel tells these apart when a code collides (spec §10.4).

**Side channel.** `--meta-fd <n>` (Unix) or `--meta-file <path>` (all platforms; created
exclusively, owner-only) receives NDJSON `RunRecord`s (§10):

* `prelaunch_failed`;
* `launching` (resolved executable, operation and binding IDs, PID);
* `exited`, on Windows only.

On Unix the descriptor is close-on-exec. EOF with `launching` as the last record therefore
means the child was launched. If `execve` returns, Heimdall writes `prelaunch_failed`, and
that later record supersedes `launching`. Nothing goes to stdout.

**Argument privacy.** `argv` never crosses IPC and is never journaled. Spec §13.6 forbids
collecting full commands by default, and arguments can carry secrets (A33). The `bind`
request names the resolved executable and the holder process instead (§10, Q8).

**Holder process.** `run` binds with holder = its own PID and OS start time; on Unix that
PID becomes the child. The supervisor releases the binding reference once that exact
process (PID and start time, so a reused PID never counts) has exited (Q5). The PID is
lifecycle metadata, never authorization (spec §4.2, §13.2).

**`connect <alias>`** is `run` without a profile binding for an ordinary alias: the
projection already supplies the configuration (spec §10.3). It resolves the verified
client, checks that the alias is a known destination (managed or observed), and then runs
`exec` or spawn-and-wait with `ssh <alias>`.

**The verified client:**

* Unix: `ssh` from `PATH`.
* Windows: the in-box `%WINDIR%\System32\OpenSSH\ssh.exe` (ADR-0004 E6), unless
  `config.toml` `[clients]` names another. The PATH-first MSI client is recorded as a
  candidate, not chosen.

Its path, version and SHA-256 are reported (R-SS-03).

**Git under `run`.**

* `GIT_SSH_COMMAND` is set only on Windows, and only when the effective Git SSH command
  resolves to Git's bundled MSYS `ssh`, which cannot reach a named pipe (F16). It is set to
  the verified client.
* If the user set `GIT_SSH_COMMAND` or `core.sshCommand`, nothing is set and the result
  reports the override.
* `SSH_AUTH_SOCK` is set to the identity's endpoint, but an effective IdentityAgent in the
  configuration wins (F8). Heimdall reports this as a `consumer_override` with provenance
  (spec §10.3 "Do not set SSH_AUTH_SOCK and assume that every consumer uses it").

**TUI handoff** follows the `system(3)` model, for both connect and run from the TUI:

1. restore cooked mode and leave the alternate screen;
2. keep the child in the TUI's own process group;
3. while waiting, keep SIGINT and SIGQUIT handlers registered (tokio signal), so the TUI
   survives Ctrl-C and the child receives it;
4. leave SIGTSTP at its default, so the shell stops and continues the TUI and its child as
   one job;
5. wait, then re-enter.

On Windows the console control handler is used, as for `run`. In this model there is no
separate process group and no stop mirroring, so the ADR-0002 §6.1 hang cases do not
arise. The crossterm hang-up watchdog and the rule against `Terminal::clear()` cursor
queries stay (overview §10).

## 9. D8 — Test environments: OpenSSH ignores `$HOME`

OpenSSH reads the user configuration and expands `~` from the account's home directory
(F19), so a test cannot redirect `~/.ssh/config` by setting `HOME`. AGENTS.md forbids
editing the owner's `~/.ssh` and using the owner's agents or keys. Therefore:

1. **Product tests** set the user-configuration path through the env-gated test
   configuration (the M01 `testcfg` pattern; never compiled into release builds). Every
   `ssh` they run uses `-F <scratch user config>`. That also drops the system file (F6),
   which the evaluator covers separately. Agents are disposable `ssh-agent -a <scratch>`
   instances or the testkit fake agent, with `SSH_AUTH_SOCK` pointing at them.
2. **"Ordinary `ssh` without `-F`"** (A01, plan "A participant can connect without a
   mandatory work wrapper") is demonstrated only where the account home itself is
   disposable: the WSL distribution ADR-0004 §3 authorizes (`wsl --import`, then
   `--unregister` of that distribution only), and Docker containers on the build host
   (supplementary Linux arm64). The native macOS and Windows rows need a disposable OS
   account, which is an owner input (m02-plan §7).

## 10. Contract additions requested (ADR-0006 revision 3 deltas)

The exact field lists and types are in m02-plan §5. In summary:

* **Requests:** `Request::Setup(SetupRequest { Preview | Apply | Rollback | Repair })` and
  `Request::Catalog(CatalogRequest { … })` (capability `setup/1`).
* **Bind change:** `BindForm::Launch` carries `executable` and `holder` instead of
  `argv` (Q8).
* **Ensure and capabilities:** `RequiredCapabilities.unattended`;
  `EnsureData.{credential_availability, provider}`;
  `ConsumerIntegration.{executables, overrides}`.
* **Next actions:** `NextAction.provider_interaction`.
* **Codes:** `LAUNCH_FAILED`.
* **Inspection:** the `InspectSubject` variants `identities` and `projections`.
* **Other types:** `ids::IdentityId` (`idn`); `contract::{doctor, provider, run_record}`.
* **Resource kinds:** `projection`, `identity`, `provider`, `executable`.
* **Domain decision kind:** `ApplyProjection` (if Q1 is accepted).

Nothing removes or re-types an existing field except `BindForm::Launch`. The contract is
not frozen (ADR-0006 §1), so that change is a revision rather than a major bump, and no
external reader exists yet.

## 11. Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Generated sections inside the user file | Larger owned surface spread among user lines; every user edit near them becomes a conflict; rollback by line ranges is fragile (spec §10.1) |
| Include at the end, preceded by `Match all` | The user's earlier `Host *` values (IdentityAgent, IdentitiesOnly, IdentityFile) would override managed aliases (F1, F8), and managed behaviour would depend on unrelated user content; it would fail the A35 SSH_AUTH_SOCK-override fixture |
| `ssh -F <generated file>` wrapper or a `ssh` shim on PATH | Drops the user and system configuration (F6) or hijacks executable resolution; it would make a launcher mandatory (R-UX-01, R-SS-03) |
| System-wide `ssh_config.d` | Needs elevation (R-DI-02) and affects other users |
| `ssh -G` in default doctor | Executes `Match exec` (F5); spec §10.2 |
| Restoring the pre-adoption snapshot on rollback | Overwrites later user edits (spec §10.1) |
| Unix `run` as spawn-and-wait with stop mirroring | Both G02 prototypes hung or orphaned children on third-party stops (ADR-0002 §6.1) |
| Windows job object with kill-on-close for `run` | Kills grandchildren left running on purpose after a normal exit; not exec-equivalent |
| Heimdall relaying the agent for existing access in M02 | Adds a same-user filter with no real scope (E-3, F12); M03/M04 bring Heimdall endpoints where they enforce something |

## 12. Questions for the orchestrator (authority semantics; recommended answers)

1. **Q1. Projection apply as an owner decision.** Does applying a projection change need a
   server-issued decision record, completed only by an attended `Decide`, as widening
   policy actions do? A change here is one that adds or changes a managed alias's
   HostName, Port, User, agent or identity, or that edits the user's SSH or Git
   configuration. **Recommended: yes.** Add `DecisionKind::ApplyProjection { plan_digest,
   summary }`, bounded to 64 KiB of exact diff text for the client confirmation contract
   (ADR-0006 §3.1). Unattended sessions get `INTERACTION_REQUIRED` + `decision_ref`;
   attended sessions get `APPROVAL_REQUIRED`. No decision is needed for rollback, removal,
   or a byte-identical re-render. *Why:* a projection redirects ordinary tools (spec §9.1),
   and an injected agent must not rewrite the owner's SSH configuration (spec §14.2, A29).
2. **Q2. Non-interactive launch and provider dialogs.** Under `--non-interactive`, may
   `run` or `connect` launch a child whose authentication can raise a provider prompt (a
   1Password approval or unlock, or a security-key touch)? **Recommended: no by default.**
   Refuse before launch with `INTERACTION_REQUIRED` (exit 3) and `next.provider_interaction`
   whenever the identity's recorded interaction is not `none`. The caller may pass
   `--allow-provider-interaction` to accept that the provider, not Heimdall, may prompt.
   Native-agent identities declared `none` are not refused. *Why:* A11 ("without a popup"),
   R-AP-06, R-CR-08; interactive use stays first-class.
3. **Q3. Grants for existing access.** Do `ensure` and `run --profile` against
   existing-access mechanisms follow the same policy and decision rules as managed
   credentials? **Recommended: yes, uniformly.** Without a covering standing policy, the
   first `ensure` of a work binding needs an attended decision. M02 adds no
   policy-creation request. `connect` and ordinary aliases need no grant at all. Personal
   standing policies and the first-trust disclosure (spec §5.2) come with M05-T02 under
   G05. *Alternative, if the owner prefers fewer prompts in M02:* add `PolicyAction::Create`
   now, always behind a `WidenPolicy` decision.
4. **Q4. What "passive" admits.** May default doctor run local queries that read no SSH
   configuration and contact no network or provider (`<client> -V`, `ssh-keygen -F … -f
   <file>`, `git config --global/--system --get-all core.sshCommand`) and list Windows pipe
   names without opening them? **Recommended: yes.** They are reported as `local_query`
   observations and can be switched off with `--no-local-exec`. The A21 canary test covers
   them. `ssh -G`, agent contact and the network are never part of the default.
5. **Q5. Release on holder exit.** May the supervisor release a `run` binding reference
   automatically once the exact holder process (PID and start time) has exited?
   **Recommended: yes.** Release narrows (ADR-0006 §13.3: release is not revoke, so no
   tombstone and no cascade), and PID is never authorization.
6. **Q6. What uninstall keeps.** Does `uninstall` keep the state store by default (identity,
   policies, tombstones, decisions, audit), with `--purge-state` only behind an attended
   typed confirmation that lists what will be lost? **Recommended: yes** (spec §13.6
   "Deleting logs must not delete policy cutoffs or other authority state", §15.2, R-DI-04).
7. **Q7. Git projection on Windows.** May setup set `core.sshCommand` in the user's global
   Git configuration as a separately itemized, default-off entry of the same decision? It
   applies only when Git's effective SSH is the bundled MSYS client (F16). Heimdall writes
   it with `git config --global`, which uses Git's own lock file, and restores it on
   rollback only if it is unchanged. **Recommended: yes, opt-in.** Otherwise Heimdall
   reports the finding with the exact command (1Password documents the same setting
   [G03-S12]).
8. **Q8. Removing `argv` from `bind`.** Does the contract revision drop `argv` from
   `BindForm::Launch` before the freeze? **Recommended: yes**, because of argument privacy
   (§8). The integrator applies it with ADR-0006 revision 3.

### 12.1 Orchestrator rulings (2026-11-01, under the owner's delegation, ADR-0004)

These rulings take effect once the independent design review closes and its accepted
findings are applied.

* **Q1–Q8:** each recommended answer is accepted as written. Two notes:
  * **Q1:** rollback, removal and byte-identical re-renders are narrowing actions,
    allowed on any same-user control connection, in line with ADR-0006 §13.1 item 1.
  * **Q3:** the M02 default is uniform decisions. The *alternative*
    (`PolicyAction::Create`) is not taken; personal standing policies arrive with
    M05-T02.
* **P1:** accepted. P2 is answered in item 3 below.
* **New owner-only inputs:**
  * A disposable macOS user account is a new physical owner input. Creating it needs
    admin consent, so rows that need it are `blocked` on it.
  * The Linux plain-`ssh`-without-`-F` rows use the disposable WSL distribution
    (ADR-0004 §3) or a disposable container.
  * The other owner-only inputs stay as listed in m02-plan.md.
* **P2:** the G01 baseline-worksheet rows stay out of M02's exit, because they need the
  owner's real workflows (ADR-0004 §4).

## 13. Consequences

* New crates: `heimdall-sshconf` (pure), `heimdall-localenv` (local I/O, discovery,
  probes, projection files), `heimdall-adapters` (`native_agent`, `onepassword`) and
  `heimdall-launch` (process contract).
* The `unsafe` inventory gains a third module, `crates/localenv/src/sys.rs`, for:
  * `getpwuid_r` (F19) and `killpg` on Unix;
  * on Windows: `ReplaceFileW`, the profile directory, and the probe job objects.
  The integrator updates overview §9.
* The store moves to migration `0005_existing_access` (`SCHEMA_VERSION` 5) and gains
  `Store::open_read_only` for doctor.
* `docs/compatibility/matrix.md` gains rows for native agent and 1Password × {ssh, Git,
  SCP, SFTP} × {macOS, Linux, Windows}, with exact labels; M02 claims nothing unattended.

## 14. Reopen conditions

Reopen this ADR if any of the following happens:

* a target client contradicts F1–F3 or the include-state inference (corpus test);
* Win32-OpenSSH refuses the rendered P or the `ReplaceFileW`-preserved file;
* a supported user layout needs the include somewhere other than the top;
* the owner rules differently on Q1–Q8;
* G05 changes how consumers bind (spec §10.3);
* M03/M04 need P to carry CertificateFile, ProxyJump or Heimdall endpoints (that is a
  revision of §2's directive set).
