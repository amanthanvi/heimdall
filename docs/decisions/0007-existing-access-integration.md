# ADR-0007 — Existing-access integration (M02): managed OpenSSH projection, nonexecuting discovery, existing-access adapters, and the process contract

**Status:** proposed, revised after design review (§12.2) · **Date:** 2026-11-01 ·
**Tasks:** M02-T00-design (revision 1), M02-T00-design-fix (revision 2)
**Gates:** the existing-access portions of G03 and G08 (plan §5 M02).
**Affects:** R-UX-01, R-UX-04, R-CR-01, R-CR-08, R-SS-01, R-SS-02, R-SS-03, R-SS-04,
R-AP-06, R-RT-04, R-RT-05, R-SE-04, R-DI-04, R-DI-06. Exit cases A01, A11, A21, A22, A27
and A35 (spec §17).
**Companion:** `docs/architecture/m02-plan.md` (units, tests, evidence plan). The contract
additions are **ADR-0006 revision 3 deltas**, given in their final form in m02-plan §5 and
summarized in §10. This ADR does not edit ADR-0006; the integrator applies the deltas.
**Revision 2:** applies the independent design review
(`tests/evidence/artifacts/review-m02-design/review.md`, findings M2-D01–M2-D10) under the
orchestrator's rulings in §12.2. Text changed by it is marked **⟨r2⟩**. §15 maps each
finding to the sections that changed. Questions revision 2 could not settle are in §12.3.
**Not decided here:** anything §12.3 lists as a question. Authority semantics fixed by the
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
(ADR-0006 §7); and the `CredentialAdapter` port (`crates/app/src/ports.rs`). ⟨r2⟩ Reusing it
needs changes to existing M01 code (decision dispatch, bind validation, restart dispatch,
prepared-fact propagation, adapter selection). m02-plan unit U0b lists them and assigns
them to the integrator (§12.2 item 8).

OpenSSH and platform facts this design depends on:

| # | Fact | Source |
|---|---|---|
| F1 | "Unless noted otherwise, for each configuration directive, the first specified value will be used"; sources are read in the order command line, user file, system file | [S01] |
| F2 | "Multiple IdentityFile directives will add to the list of identities tried (this behaviour differs from that of other configuration directives)"; CertificateFile likewise accumulates. ⟨r2⟩ "Alternately an argument of none may be used to indicate no identity files should be loaded" | [S01] |
| F3 | "Include directive may appear inside a Match or Host block to perform conditional inclusion"; relative Include paths resolve under `~/.ssh` (user) or `/etc/ssh` (system); globs expand "in lexical order" | [S01] |
| F4 | "The exec keyword executes the specified command under the user's shell"; ProxyCommand, LocalCommand (with PermitLocalCommand) and KnownHostsCommand also execute commands | [S01] |
| F5 | `-G` "Causes ssh to print its configuration after evaluating Host and Match blocks and exit"; so `ssh -G` runs `Match exec` | [S02], [S01], spec §10.2 |
| F6 | `-F`: "If a configuration file is given on the command line, the system-wide configuration file … will be ignored" | [S02] |
| F7 | Tokens "are expanded without quoting or escaping of shell characters"; `%%` is a literal `%`; `${VAR}` expands in CertificateFile, ControlPath, IdentityAgent, IdentityFile, Include, KnownHostsCommand and UserKnownHostsFile, and an unset variable makes that setting ignored | [S01] |
| F8 | IdentityAgent "overrides the SSH_AUTH_SOCK environment variable and can be used to select a specific agent"; `none` disables the agent | [S01] |
| F9 | ⟨r2⟩ A public-key path in IdentityFile selects "the corresponding private key that is loaded in ssh-agent(1) when the private key file is not present locally". IdentitiesOnly restricts ssh to "the configured authentication identity and certificate files (either the default files, or those explicitly configured in the ssh_config files or passed on the ssh(1) command-line), even if ssh-agent(1) … offers more identities". So **configured identities include every entry the user's files add for the host**, not only Heimdall's (M2-D01) | [S01] |
| F10 | ProxyJump "will compete with the ProxyCommand option - whichever is specified first will prevent later instances of the other from taking effect" | [S01] |
| F11 | ssh "exits with the exit status of the remote command or with 255 if an error occurred" | [S02] |
| F12 | An agent socket "is easily abused by root or another instance of the same user" | [S30] |
| F13 | Windows: the in-box client sets `SSH_AUTH_SOCK` to `\\.\pipe\openssh-ssh-agent` when unset; `Match exec` and ProxyCommand run through `system()` | [G03-S02] [S] (G03 Q03, Q19) |
| F14 | Windows: in IdentityAgent, `\\.\pipe\x` reaches nothing; `//./pipe/x` (also quoted, with spaces or non-ASCII) selects exactly that pipe; in SSH_AUTH_SOCK any non-ASCII pipe name fails | [O P-W03], [O P-W02] |
| F15 | Windows: a path containing `%` works only in `%%` form | [O P-W08] |
| F16 | Windows: Git's bundled MSYS ssh cannot use Windows named pipes; `GIT_SSH_COMMAND` > `core.sshCommand` > `GIT_SSH` > `ssh` | [O P-W02/P-W04], [G03-S13] |
| F17 | 1Password asks "for your consent before an SSH client or terminal session can use your key"; when locked it "will prompt you if an SSH client tries to use one of your keys" and "doesn't keep your private keys in memory"; approvals are wiped when it locks (default) | [S06], [S07] |
| F18 | 1Password on Windows takes over `\\.\pipe\openssh-ssh-agent` after the OpenSSH agent service is disabled | [G03-S12] |
| F19 | OpenSSH resolves `~` and the user configuration from the account's home directory, not `$HOME` | [I]; settled by test `integration_doctor::home_resolution_matches_ssh_g` (m02-plan U3) |
| F20 | ⟨r2⟩ The IdentityFile default is "~/.ssh/id_rsa, ~/.ssh/id_ecdsa, ~/.ssh/id_ecdsa_sk, ~/.ssh/id_ed25519, ~/.ssh/id_ed25519_sk and ~/.ssh/id_mldsa44_ed25519" [S01]. That the defaults are **not** added once any IdentityFile is configured is `[I]` | settled by `integration_sshconf_vs_ssh_g::corpus_identity_list_matches_ssh_g` (`ssh -G` prints the identity list) |
| F21 | ⟨r2⟩ ssh-agent's default socket is created "in the $HOME/.ssh/agent directory", and by default it cleans up stale sockets there ("-U Instructs ssh-agent not to clean up stale agent sockets under $HOME/.ssh/agent/") | [S30] |
| F22 | ⟨r2⟩ Git: the precedence of F16; `GIT_SSH_COMMAND` and `core.sshCommand` run through the shell [G03-S13, G03 Q13]. Beyond that, Git's documentation is not pinned, so the following are `[I]`: the scope order (system < global < local < worktree < command) with the last value winning for a single-valued key; `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>` entries being command scope that `git -c` overrides; `[include] path`; the `<file>.lock` write protocol; which file `--global` writes; `git config --show-scope` output | each is settled by the Git test named where §5.6 or §8 relies on it |
| F23 | ⟨r2⟩ An agent key can carry a confirmation constraint (`ssh-add -c`; the agent asks through ssh-askpass before each use). ssh-add(1) is not pinned, so this is `[I]`. The constraint is not visible in an identity listing, so it cannot be detected passively | settled by `run_m02::a11_confirm_constrained_native_key_refused_before_agent_contact` against a disposable `ssh-agent` |
| F24 | ⟨r2⟩ Atomic exchange of two directory entries: Linux `renameat2(RENAME_EXCHANGE)`, macOS `renameatx_np(RENAME_SWAP)`. Windows has no exchange; `ReplaceFileW` with a backup name keeps the displaced file there. None of these is pinned. Support per filesystem, and what `ReplaceFileW` captures as the backup under a concurrent replacement, are `[I]`/`[U]` | `integration_projection::exchange_supported_on_target_fs`, `windows_replace_retains_displaced_identity` |

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
data (spec §7.3) and owned artifacts of the same projection. ⟨r2⟩ When the owner opts into
the Git item (Q7), the projection gains two more owned artifacts on the same pattern: the
managed Git file P_git and a marked include block B_git in the user's global Git
configuration (§5.6).

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
3. ⟨r2⟩ **Accumulating directives merge, and Heimdall then claims no exclusive selection
   (M2-D01).** A user IdentityFile or CertificateFile that applies to a managed alias (a
   `Host *` default, a matching wildcard, or a later literal section) is added after
   Heimdall's entry (F2). `IdentitiesOnly yes` still offers it, because configured
   identities include those in the user's files (F9). P cannot remove such entries:
   accumulation has no override, and P carries only literal `Host` sections. Heimdall
   never edits them (spec §5.2; §12.2 item 1). For each managed alias the evaluator
   computes the effective identity list (IdentityFile and CertificateFile entries in order,
   each with provenance and certainty) and classifies its **identity selection**:
   * `exclusive`: the list is exactly Heimdall's materialized public key, with no
     CertificateFile, and every entry is determined;
   * `not_exclusive`: the list holds any other entry;
   * `undetermined`: an entry depends on a condition the static level cannot decide
     (`Match exec`, canonicalization, an unset `${VAR}`).

   Only an `exclusive` alias is described as offering only the adopted key, and only for
   its configuration: command-line `-i` or `-o IdentityFile=` remain the caller's
   explicit choice (F1). `not_exclusive` and `undetermined` are reported in the preview,
   in doctor (finding `identity_selection_not_exclusive` or
   `identity_selection_undetermined`, with every extra entry's file:line and the remedy:
   narrow the user's entry with a negated pattern such as `Host * !<alias>`, or move it
   into the sections that need it) and in every readiness result
   (`ConsumerIntegration.pairs[].identity_selection`, §10). The revision-1 finding
   `inherited_identities` is replaced by these.
4. **Collisions are refused.** A managed alias must not equal a name that a *literal* user
   pattern matches. Such an apply is refused with `CONFIG_CONFLICT` and next action
   `review_config` (adopt the alias as observed, or rename it). A match by a user wildcard
   is allowed and shown as inherited.

**The include restores the containing file's state** after the included file is read, so
a `Host` section ending P does not capture the user lines below B. This is
`[I]`: the behaviour is consistent with F3, but no pinned excerpt states it. The corpus
test `integration_sshconf_vs_ssh_g::include_state_is_restored_after_included_file` settles
it against each target client (macOS 10.3p1, the Linux devbox client, Windows in-box
9.5p2) with `ssh -G -F <inert corpus>`. Until it passes on a client, that client's
projection rows stay `implemented_unverified`.

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
| ⟨r2⟩ Git `include.path` (B_git) | absolute, `/` separators, Git-config double-quoted (`\` and `"` escaped); refused with a control character or newline | F22 |
| ⟨r2⟩ Git `core.sshCommand` (P_git) | the verified client's absolute path with `/` separators, single-quoted for the POSIX shell Git runs it through, then Git-config double-quoted; a path containing `'`, `"`, a control character or a newline is refused | F16, F22, [G03-S12] |

A value that breaks a rule is refused with `USAGE_ERROR` before anything is written. A
label containing shell metacharacters is either refused or written as inert data; P never
places a label in a directive that is executed (spec §14.3).

⟨r2⟩ **Encodings.** A user file that starts with a UTF-8 BOM or uses CRLF line endings is
edited in automatic mode only on a client where the corpus test
`integration_sshconf_vs_ssh_g::bom_and_crlf_acceptance` showed that the client loads such a
file with B effective. On any other client the apply is in manual mode with reason
`unsupported_encoding`, and the file is not modified (review A22 note). Byte preservation
alone is not counted as acceptance.

## 5. D4 — Adoption, rendering and rollback: journaled, exchange-based, never restored from a snapshot

### 5.1 Preview

**Preview** is read-only (no operation ID; like `inspect`). ⟨r2⟩ It computes a plan for one
intent: `apply` (with or without the Git item), `rollback`, or `repair` of a named
conflict. It loads the user configuration tree, the current P, the Git files when the Git
item is involved, the catalog and the projection record. It then renders the new bytes of
every file the intent changes. For every literal alias name in the tree plus every managed
alias, it evaluates `RelevantBehavior` before and after (§6), together with each managed
alias's identity selection (§3 item 3). The result carries:

* the diff;
* the inherited values;
* the findings;
* for an apply, the **restore column**: for every alias that the plan adds or changes, the
  behaviour that alias would have if its section were removed now;
* `plan_digest` = SHA-256 over the canonical plan.

The plan holds each file's base state (absent, or present with its SHA-256) and target
state, and each item's behaviour digests before, after and on restore (§5.2). Preview runs
in the runtime, which reads the files through `heimdall-localenv`, the same user's process.

⟨r2⟩ Revision 1's `setup preview --evaluate` is **withdrawn** (M2-D06): preview never
executes configuration. An authorized evaluation is the doctor `evaluate` level (§6). The
preview names the undetermined aliases and the exact doctor command.

### 5.2 Consent: decisions by effect (Q1, as qualified by §12.2 item 4)

⟨r2⟩ A projection change is classified by its effect, never by its name. The classification
compares, for each affected **item** (a managed alias, or Git's SSH selection), three
behaviour digests:

* *current*: its behaviour now;
* *after*: its behaviour under the plan;
* *consented*: the two states recorded with the last executed `ApplyProjection` decision
  that covered the item. These are its approved managed state, and the restore state that
  decision showed in its restore column.

A **behaviour digest** is SHA-256 over the canonical `RelevantBehavior` with each value's
provenance reduced to its source role (`managed`, `user`, `system`, `default`), so line
moves and comments do not change it. An undetermined directive enters with its candidate
values and the kinds of their conditions.

**A change needs no new decision when, for every affected item, *after* equals *current*,
or one of its *consented* states.** Any other change creates an `ApplyProjection` decision
(§10). It is completed only by an attended `Decide`. Unattended sessions get
`INTERACTION_REQUIRED` with `decision_ref`; attended sessions get `APPROVAL_REQUIRED`
(ADR-0006 §3.1). Consequences:

* First adoption, and any new or changed managed alias, always need a decision.
* A byte-identical re-render needs none.
* A rollback, an alias removal, or a `Rerender` repair needs none while the configuration
  yields exactly what the owner was shown: the restore state for a removal, the managed
  state for a re-render.
* A rollback that would expose a HostName, agent, identity or proxy that the user's
  configuration gained after that decision needs one. So does a removal whose *after*
  state is undetermined and differs from the consented one.

The comparison is static and executes nothing. Its reasons are listed in the plan
(`consent.reasons`). The decision summary shows the before, after and restore columns, so
consent to an apply covers exactly that later rollback and nothing wider. (Question QR2,
§12.3, asks the orchestrator to confirm this as the precise form of ruling 4.)

### 5.3 The file replacement primitive

⟨r2⟩ Every write of a file the projection owns or edits (P, the user file, key files, P_git,
B_git's file) uses one primitive. It is designed so that **no file that Heimdall did not
create, or did not validate as the plan's base, is ever deleted or overwritten
unrecoverably** (M2-D03):

1. **Validate the directory.** Open it with `O_DIRECTORY|O_NOFOLLOW` (Unix) or as a
   non-reparse handle (Windows). It must be owned by the current user and not writable by
   group or others (Unix), or carry no reparse point (Windows). Every later step is
   relative to this handle (`openat`, `renameat`, `unlinkat`), so a substituted parent path
   is not followed.
2. **Validate the file**, when the plan expects it to exist. Unix: open it
   `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` relative to the directory and `fstat` it. It
   must be a regular file owned by the effective UID, with a link count of 1 and no group
   or other write bit. Then read it (≤ 1 MiB) and compare its SHA-256 with the plan's base.
   Windows: open it with `FILE_FLAG_OPEN_REPARSE_POINT`; it must be a regular file with no
   reparse tag, owned by the current user's SID, with one link. Record the file identity
   **V** (Unix device and inode; Windows volume serial and 128-bit file ID). When the plan
   expects the file to be absent, `lstat` must report `ENOENT`. A digest mismatch is
   `CONFIG_CONFLICT` (`user_config_changed` or `managed_file_edited`). A type, owner, link
   or reparse failure is manual mode (`unmanageable_file`). In both cases nothing is
   written.
3. **Stage.** Create `.<name>.hm-<generation>-<random>` in the same directory with
   `O_CREAT|O_EXCL|O_NOFOLLOW` and the original's permission bits (new files 0600, or an
   owner-only DACL), write the new bytes, and fsync. Record the staged identity **S** in a
   stage receipt before step 5.
4. **Recheck at the boundary.** `fstat` the validated descriptor again, `lstat` the path,
   and re-read the bytes. The entry must still be V, with the same type, owner, link
   count, mode and digest. This narrows the race window; it does not close it.
5. **Exchange: the commit point for this file.**
   * Unix: atomically exchange the staged name and the path (F24). Afterwards the path is S,
     and the staged name holds **D**, whatever was at the path at that instant. A file the
     plan expects absent is renamed with no-replace (Linux `RENAME_NOREPLACE`, macOS
     `RENAME_EXCL`); `EEXIST` is a conflict.
   * Windows: `ReplaceFileW(path, staged, backup = .<name>.hm-displaced-<generation>,
     REPLACEFILE_WRITE_THROUGH)`. It keeps the replaced file's DACL and attributes (`[I]`,
     settled by `windows_replace_preserves_dacl`) and leaves the displaced file D at the
     backup name (`[I]`, settled by `windows_replace_retains_displaced_identity`). A file
     the plan expects absent is moved with `MoveFileExW` without `REPLACE_EXISTING`.
6. **Post-validate.** D must be a regular file with identity V and the base digest, and the
   path must be S.
7. **Settle.**
   * **Valid:** D's name is removed. Unix removes it with `unlinkat` after checking that the
     entry is still V. Windows deletes it through a handle whose file ID was checked
     (`FileDispositionInfoEx`). Receipt `Settled(applied)`.
   * **D is not V, or its digest is not the base.** Another writer replaced or rewrote the
     file between steps 4 and 5. **Restore** by exchanging again (Unix), or with
     `ReplaceFileW(path, D's name, backup = S's name)` (Windows), so that D is back at the
     path. Then verify that what was displaced is S (ours) and delete it. Result
     `CONFIG_CONFLICT` with reason `concurrent_writer`; the other writer's content is the
     active file; no behaviour change for this file.
   * **The restore finds something that is neither D nor S** (a third writer). Nothing
     further is moved or deleted. The entry not at the path is renamed with no-replace to
     `<name>.hm-conflict-<generation>` and kept. Result `CONFIG_CONFLICT`
     (`concurrent_writer`), effect `partial`, with both paths reported.
8. **Manual mode instead of automatic.** Heimdall prints the exact block and changes
   nothing when the file or its directory fails a step-1 or step-2 check
   (`unmanageable_file`: a symlink, a reparse point such as a junction, OneDrive placeholder
   or file symlink, a hard link count above 1, not a regular file, a foreign owner, not
   writable), when the filesystem has no atomic exchange (`atomic_exchange_unsupported`;
   Unix `EINVAL`/`ENOTSUP`/`ENOSYS` from the exchange), or when the encoding is unsupported
   (§4). Doctor afterwards verifies that the block is present and placed correctly.

There is deliberately no link-then-rename fallback. A rename-replace by another writer
between the link and the rename would lose that writer's file (§11).

### 5.4 Apply: commit points and the partial-effect contract

**Apply** is a journaled operation (`OperationKind::SetupApply`, ADR-0006 §14.1), decided per
§5.2. Once approved (or when §5.2 needs no decision), the driver runs:

1. **Recompute the plan.** If `plan_digest` differs from the approved one, refuse with
   `CONFIG_CONFLICT` ("preview is stale") and write nothing. The approved decision is
   consumed; the owner previews again.
2. **Persist the `SetupIntent`** (§5.7), mint the effect token, and write the `Attempted`
   receipt.
3. ⟨r2⟩ **Revalidate every precondition of every file in the plan** (§5.3 step 2) before the
   first commit point: the user file, P, every key file, and the Git files when the Git
   item is in the plan. Any failure: nothing is written.
4. Execute the file steps in plan order. Two shapes (§12.2 item 2):

   **First adoption** (no B in the user file):
   * *Inactive steps:* the key files, then P. Nothing references them yet: P becomes
     effective only through an Include (F3), so ordinary SSH behaviour is unchanged.
   * *Commit point:* the user-file exchange that inserts B. Immediately before it, the
     user file is revalidated, and so is P (it must still be S_P, the file this operation
     staged).
   * *Partial effect:*
     * A failure before the commit point leaves only inactive files. The result is the
       error (usually `CONFIG_CONFLICT`) with effect `none` for behaviour, and P and the
       key files are reported in the state `written_inactive`. The cleanup executor
       removes those files, bound to generation and identity (§5.8).
     * A post-validation restore (§5.3 step 7) also reports effect `none`.
     * The third-writer case reports `partial`.

   **Update** (B present, intact and first, referencing P at generation N):
   * B's bytes depend only on the marker ID and P's path, so **an update never writes the
     user file**.
   * *Inactive steps:* new key files.
   * *Commit point:* P's exchange. Immediately before it, the user file is revalidated (base
     digest, B intact and first) together with P (identity and digest of generation N).
   * *After the commit point*, the user file is checked again. If it changed during the
     step, the approved behaviour may not hold. P is then restored to generation N by
     exchanging back (§5.3 step 7 applied to P), and the result is `CONFIG_CONFLICT`
     (`user_config_changed`) with effect `none`. If P cannot be restored because P itself
     was replaced concurrently, the result is effect `partial` and names the generation
     that is active.
   * Key files that P no longer references are removed by cleanup after the receipt.

   **Git item** (when in the plan): its own steps follow the SSH commit point (§5.6).
5. Record `ConfigProjection` resources at generation N+1 (role, path, identity, digest),
   record the consented states (§5.2), write the `Confirmed` receipt, and settle.

The result is `SetupResult { generation, items: [{ item: ssh|git, outcome: applied |
not_applied | restored | conflict_preserved, files }] }`. The envelope's effect is:

* `applied` when every item applied;
* `none` when no behaviour changed;
* `partial` otherwise.

A failure after a commit point reports `none` only when the restore was verified;
otherwise it reports the applied or partial effect, never "no change" (§12.2 item 2).

**Cancellation** is honoured only before the first commit point. After it, the driver
finishes or restores. `CancellationRecord.may_have_external_effect` is `true` once any file
was written.

### 5.5 Rollback, repair, removal and uninstall

**Rollback** is a plan, previewed and decided per §5.2, that:

1. removes B from the user file through the §5.3 primitive (this is the commit point), but
   only when B's bytes equal the recorded block. If they differ, the result is
   `marker_edited` and Heimdall shows the exact lines to remove;
2. then removes P and the key files through the cleaner (§5.8).

A P whose digest or identity no longer matches is not removed: it is renamed to
`ssh_config.hm-conflict-<generation>` and reported. Lines the user added anywhere else
survive. `remove(insert(x)) == x` holds byte-for-byte when nothing else changed (property
test, m02-plan U2).

**Repair** resolutions (`Rerender`, `RemoveDuplicateMarkers`, `MoveIncludeToTop`,
`ManualMode`) are plans built on the same machinery and decided by the same rule. Each
conflict kind has a targeted resolution and never a blanket restore (spec §10.1 "A stale
backup cannot overwrite a subsequently edited configuration").

**Removing a managed destination** from the catalog changes no file. The projection becomes
stale, and P changes only through `setup apply`, whose plan shows the alias removal and is
decided per §5.2.

**Uninstall** is the rollback of every item (which may need a decision, §5.2), removal of
the key files, a graceful runtime stop (`Request::Shutdown`), and removal of the runtime
endpoints and `instance.json`. It reports what remains: the state store, the backups, and
from M03 any remote enrollment (spec §7.7, R-DI-04). The state store is kept by default
(Q6). ⟨r2⟩ Q6 qualification (§12.2 item 11):

* If any rollback is incomplete (a conflict, a block still present in manual mode, or a
  preserved `*.hm-conflict-*` file), uninstall reports `CONFIG_CONFLICT` with effect
  `partial`. It keeps the state store, the recovery records, the backups and every
  conflict file, and lists them.
* `--purge-state` refuses (`CONFIG_CONFLICT`, exit 6) while any projection resource is not
  confirmed absent. It never reports an unresolved cleanup as success.

**Snapshots.** Before the first edit, the original user file is copied to
`<state_dir>/backups/ssh_config.<UTC timestamp>.orig` (0600; owner-only ACL on Windows),
and the same applies to the global Git file before its first edit. Heimdall never restores
a snapshot automatically. Snapshots exist for manual recovery, `setup status` lists them,
and only `uninstall --purge-state` deletes them.

### 5.6 GitConfigChange (Q7, specified by §12.2 item 10)

⟨r2⟩ The Git item is opt-in (`--include-git`), default off, and a separately itemized entry
of the same `ApplyProjection` decision. It changes Git's SSH selection only where Git would
otherwise use its bundled MSYS client, which cannot reach a named-pipe agent (F16).

**Observation at preview** uses local queries (Q4): bounded at 2 s, with no shell, stdin
null, the Git executable from the client inventory, and the user's environment.

* `git config --system --show-origin --get-all core.sshCommand` and the same with
  `--global`. These are exactly the Q4 local queries plus `--show-origin`. They depend on
  no working directory, so no repository's local scope can leak in. The output format is
  `[I]`, settled by `git_config_query_output_parsed`. Values are held in memory only, to
  classify them and to build the preview diff text. The plan stores, per entry: scope,
  origin display path, the SHA-256 of the value, and a count per scope.
* Environment overrides (`GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_CONFIG_*`) are per-process
  and per-shell, so setup does not judge them. The run-time resolution of §8 handles them,
  and doctor reports, by name only, any that are set in its own environment.
* **The global file.**
  * `GIT_CONFIG_GLOBAL` set: the item is not offered (manual, reason
    `git_global_redirected`).
  * Otherwise: `~/.gitconfig` if it exists; else `$XDG_CONFIG_HOME/git/config` (default
    `~/.config/git/config`) if it exists; else `~/.gitconfig`, to be created.
  * `~` is Git's home (`$HOME`, else `%USERPROFILE%` on Windows).
  * This rule is `[I]`, settled by `git_global_file_resolution_matches_git` in a scratch
    home.
* **Git's default SSH.** It is the bundled MSYS client when the Git installation contains
  its own `ssh.exe` and no override applies. This is observed passively, as G03 P-W04 did.

**Applicability: absent versus multiple values.** The item is applicable only when **the
system and global scopes have zero `core.sshCommand` values** and Git's default is the
bundled MSYS client. One or more values in either scope make the item `not_applicable`,
with reason `git_ssh_command_present` and the observed entries (scope, origin, count). Heimdall never replaces, reorders or removes a user value. So the
**previous values of an applied change are always the empty list**; multiplicity only ever
blocks the item.

**What it writes:**

* **P_git** = `<config_dir>/gitconfig`, owned by Heimdall:
  `[core]` / `sshCommand = <rendered value>` (§4).
* **B_git**, a marked block at the top of the global file: before the first section
  header, after leading comment and blank lines and a BOM:

  ```gitconfig
  # >>> heimdall managed include (id hm-<16 hex>); remove with `heimdall setup rollback`
  [include]
  	path = "<absolute path of P_git>"
  # <<< heimdall managed include (id hm-<16 hex>)
  ```

  At the top, Heimdall's value is the earliest global entry and therefore the
  lowest-priority one. Any value the user later sets in this file, in a repository, or
  with `git -c` wins, because the last value wins (F22 `[I]`; settled by
  `git_user_set_after_include_wins`).

**Conditional update under Git's own lock.** B_git is written with the §5.3 primitive inside
Git's lock protocol (F22 `[I]`):

1. Heimdall creates `<global file>.lock` with exclusive create and uses it as the staged
   file. `EEXIST` gives `CONFIG_CONFLICT` with reason `git_config_locked`, and nothing is
   written. A lock that Heimdall did not create is never removed.
2. Under the lock it revalidates the global file against the plan's base.
3. It checks that the new bytes parse: `git config --file <staged> --no-includes --list`
   (a local query).
4. It exchanges. The displaced file now sits at the lock name, which keeps Git writers out
   until post-validation finishes. Then the lock name is removed.

During that interval, Git commands that write configuration fail with Git's own lock error,
and nothing is lost. Editors that ignore the lock are covered by §5.3 step 7 and §5.9.

**Effective selection.** The plan carries `effective_before` and `effective_after`
(`GitSshSelection`, §10), computed from the system and global scopes. A repository's own
value, or an environment override, still wins at run time (§8).

**Receipts and recovery.**

* P_git and B_git are file steps of the same `SetupIntent` (§5.7), placed after the SSH
  commit point, with resources `ConfigProjection` in the roles `git_managed` and
  `git_include`.
* **Crash with the lock name occupied.** Recovery examines the lock name by identity:
  * our staged S (not yet exchanged) is removed, and the step did not apply;
  * the displaced D (exchanged but not yet validated) is post-validated or restored as in
    §5.3 step 7.

  Doctor reports `git_config_lock_held`, with the path, for as long as that state lasts.

**Rollback** removes B_git under the lock, only when its bytes equal the recorded block (else
`marker_edited`), and then P_git through the cleaner. A value the user added later survives
byte-for-byte. Because that value already wins, removing B_git then changes no effective
selection, and §5.2 needs no decision.

**Partial application.** The SSH and Git items have separate commit points. If the Git item
fails after the SSH item committed, SSH stays applied and the result is `partial` with the
Git item `not_applied` or `restored` (QR6, §12.3).

### 5.7 Durable intent, receipts and crash recovery

⟨r2⟩ Before any write, the driver persists **`SetupIntent`** in `RecoveryIntent.local`
(m02-plan §5 item 17):

```text
SetupIntent {
  plan_digest,
  intent: apply | rollback | repair(kind),
  generation: N+1,
  approval,
  consent: ConsentRecord,
  files: Vec<FileStep>,
}
FileStep {
  role: user_ssh | managed_ssh | key(fp) | git_include | git_managed,
  path,
  base: Absent | Present { sha256 },
  target: Absent | Present { sha256 },
  commit: bool,
  staged_name,
  displaced_name,
}
```

Stage receipts are written per file step, as `EffectReceipt::Attempted` and `Confirmed`
with adapter identity `config_projection/<environment>` (ADR-0006 §14.1). In order:

1. `staged(role, S)`;
2. `validated(role, V)`, just before the exchange;
3. `exchanged(role)`;
4. `settled(role, outcome)`.

These record, for an already-active P, which generation is active and which file holds the
displaced bytes (§12.2 item 2).

`reconcile(intent, receipts)` re-observes each step **by identity, never by content alone**:

* The path holds S: the step was exchanged. If the displaced name still holds D,
  post-validate or restore it (§5.3 steps 6–7); if it is gone, validation had finished.
* The path holds V, or the base content with no `staged` receipt: the step was not
  exchanged. A staged S that is present is removed, since it is ours. Then:
  * if no commit point has been passed, the driver resumes forward under the same plan
    only when every precondition still holds; otherwise it settles `failed` with
    `CONFIG_CONFLICT` and effect `none`;
  * if a commit point has been passed, it finishes forward or restores that file.
* The path holds neither: another writer was there. Preserve every entry, settle `failed`
  with `CONFIG_CONFLICT` and effect `partial`, and report.

Every file state is therefore observed locally, and a local projection never stays in
`outcome_unknown`. The outcome is applied, not applied, restored, or a reported conflict
with preserved files. On restart the operation is driven from its kind (m02-plan U0b); the
driver calls `reconcile`, never a second `apply`.

### 5.8 Cleanup ownership

⟨r2⟩ Every deletion of P, P_git or a key file goes through the supervisor's single cleanup
executor (R-RT-04) and `ProjectionCleaner` (m02-plan U4). It deletes only when:

* the resource's generation is the one being cleaned (the M01 guard), **and**
* the entry at the locator has the recorded identity **and** digest.

The locator is `ProjectionLocator { role, path, identity, sha256 }`, canonical JSON and
nonsecret. The same bytes in a new identity, such as a newer generation or the user's copy,
are left alone and reported `Ok` with nothing of that generation removed (the M01
`ResourceCleaner` contract).

Deletion itself is bound to identity:

* Windows deletes through a handle opened with `FILE_FLAG_OPEN_REPARSE_POINT` whose file ID
  was checked.
* Unix renames the entry with no-replace to a unique name in the same directory, checks the
  moved entry's identity, and then unlinks it. It moves the entry back (no-replace) if it
  was not ours, or keeps it as `*.hm-conflict-<generation>` when the original name is
  occupied again.

A cleanup for generation N therefore never deletes the content of generation N+1, whatever
the bytes.

### 5.9 Unsupported concurrency (stated; not counted toward A22)

⟨r2⟩ The following cases are outside what M02 supports. They are documented in `setup
status` help and in the compatibility matrix, and A22 evidence does not cover them
(§12.2 item 3):

1. **A writer that opened the file before the commit point and writes through that
   descriptor after post-validation.** Its bytes land in the displaced file, which is then
   removed, or in an already unlinked inode. Heimdall cannot detect this. Editors that
   reopen by path when saving are not affected: their save replaces or rewrites the active
   file, and doctor then reports the missing or edited block.
2. **On Windows, a replacement between `ReplaceFileW`'s own open and its internal rename.**
   What is captured as the backup in that window is `[U]`, settled by
   `windows_replace_retains_displaced_identity`.
3. **Filesystems without atomic exchange.** Heimdall does not attempt automatic mode there:
   it uses manual mode (§5.3 step 8), which is supported behaviour, not a gap. Whether each
   target filesystem supports exchange (APFS, ext4 on the devbox and in WSL, the container
   overlay filesystem) is `[I]`/`[U]`, settled by `exchange_supported_on_target_fs`.

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

**The probe ladder.** ⟨r2⟩ The levels are those spec §10.2 lists. Each level states what
Heimdall does, what Heimdall itself never does, and what the user's configuration can add
when it runs (M2-D06). The report names every level performed and every level declined,
with the reason. Explicit levels need `--active-probe <level>[,…]` (or the TUI
equivalent).

**`--allow-config-commands`.** A level that would run configuration commands also needs
`--allow-config-commands` whenever the static pass finds an executing construct reachable
for the alias (Match exec, ProxyCommand, KnownHostsCommand, LocalCommand with
PermitLocalCommand; F4).

* The flag's help text is the sentence **"runs your configuration's commands with whatever
  effects they have"**, followed by the file:line list.
* The TUI shows the same text and requires a typed `yes`.
* Without the flag the level is declined with reason `config_commands_not_authorized`, and
  nothing runs.

| Level | Heimdall does | Heimdall itself never | What configuration commands can add | Default |
|---|---|---|---|---|
| `static` | parse and evaluate the configuration; stat agent sockets; list `\\.\pipe\` names without opening any; read `known_hosts` and `.pub` files; read the Heimdall store **read-only**; with **Q4**, local queries that read no SSH configuration (`<client> -V`, `ssh-keygen -F <host> -f <file>`, the `git config` queries of §5.6) | execute configuration, contact an agent or provider, use the network, sign, mutate anything | nothing: no configuration command runs | yes |
| `evaluate` | `ssh -G <alias>` with the user's real configuration (F5) | contact an agent, use the network, sign | **anything**: network, agent contact and signing, file changes, long-lived processes (Match exec) | no |
| `agent` | connect to a named agent endpoint and send `SSH_AGENTC_REQUEST_IDENTITIES` only; bounded (256 KiB reply, 1024 identities, 2 s) | sign, add, remove, lock, extensions | — (no configuration runs) | no |
| `network` | TCP connect to HostName:Port and read the SSH identification line (RFC 4253 §4.2); 5 s | key exchange; aliases routed through ProxyJump or ProxyCommand are reported undetermined, not probed | — | no |
| `host_verification` | `ssh -o BatchMode=yes -o PreferredAuthentications=none -o IdentityAgent=none -o IdentityFile=none -o ControlMaster=no -o ControlPath=none <alias>`, classified from the exit code (F11) and bounded stderr markers | ask ssh to sign: with no agent, no identity file and no authentication method, ssh has nothing to sign with | anything, through Match exec, ProxyCommand and KnownHostsCommand | no |
| `authentication` | `ssh -T -o BatchMode=yes -o ControlMaster=no -o ControlPath=none <alias> exit 0` | under `--non-interactive`, run for an identity whose interaction is not `none` (Q2, §7) | anything, as above; plus provider prompts in interactive mode | no |

⟨r2⟩ **Signature counts.** The authentication level offers the identities the configuration
selects. How many signatures it causes depends on the identity list (§3 item 3), the server
and the negotiated algorithms, and it can fail before signing. Heimdall claims no count.
Tests assert a count only for fixtures that fix it
(`a21_authentication_level_single_identity_fixture_signs_exactly_once`).

⟨r2⟩ **Containment.** Every child that a probe starts runs with a timeout.

* Unix: the child runs in its own process group, killed with `killpg` at the timeout. A
  descendant that leaves the group (`setsid`, `setpgid`, a daemonizing double fork) is
  **not contained** and can outlive the probe.
* Windows: a job object with kill-on-close and without breakaway. A process that a
  configuration command starts through another service (Task Scheduler, COM) is outside
  the job (`[I]`).

Each `ProbeRecord` states what applied (§10):

* `containment`: `process_group` or `job_object`;
* `executed_config_commands`: the file:line of each construct that ran;
* `effects_excluded`: only the effects Heimdall enforced did not happen. Whenever
  configuration commands ran, it excludes nothing they could do.

Heimdall never reports an exclusion it cannot enforce. Probe children are Heimdall's own
diagnostic work, unlike the user's `run` children in D7.

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
  * the new `credential_availability` and `provider` fields (§10);
  * ⟨r2⟩ `integration.pairs`: one entry per destination/account pair of the grant, with
    identity, endpoint, managed alias, interaction profile and the static
    `identity_selection` (§3 item 3), computed at prepare time by a passive evaluation of
    the user's current configuration.
* **`revoke`** removes the binding's integration and reports `remote_pending` empty and
  `latest_possible_credential_expiry` absent. The key stays usable outside Heimdall, and
  the `enforcement` fields already say so (spec §6.7, R-AU-08).
* **`reconcile`** observes the local materialization, so there is no unknown outcome.
* ⟨r2⟩ **One mechanism per grant.** M01 records one adapter per grant
  (`ResolvedIntent.adapter`). An `ensure` whose pairs name identities of different
  mechanisms is refused with `CAPABILITY_UNAVAILABLE` and reason `mixed_mechanisms`; the
  next action is to split the profile. Pairs may use different identities of one
  mechanism. Adapter selection follows the catalog's mechanism (m02-plan U0b).

**Detection is passive:**

* Unix: `SSH_AUTH_SOCK` and its stat (socket type, owner UID); the documented 1Password
  socket path and the presence of its `agent.toml` (G03-S12 lists the agent/config page;
  the exact path strings must be added to the pinned excerpts before T03 relies on them).
* Windows: names under `\\.\pipe\` without opening them. Which provider serves
  `openssh-ssh-agent` is ambiguous passively (F18). It is reported as `unknown`, with an
  `[I]` hint from the `ssh-agent` service state and the 1Password process; the record keeps
  the label `[I]`.

**Interaction profile per identity** ⟨r2⟩ (M2-D05; §12.2 item 5). It is recorded at adoption,
re-derived when the identity's public key or endpoint changes, and drives every result:

| Identity | Default `interaction` | Basis |
|---|---|---|
| 1Password | `provider_approval`, plus `provider_unlock` while locked | `documented` (F17) |
| native agent, key type not FIDO | **`unknown`** | `inferred`: a confirmation constraint cannot be observed passively (F23) |
| any key whose public key is a FIDO type (`sk-*`) | `hardware_presence` | `documented` (key types [S01]) |
| native agent after an owner declaration | `none` | `declared`, with `declared_at`, the fingerprint and the endpoint it covers |

**Declaring "no interaction"** (QR1, §12.3). `heimdall identity declare-interaction <id>
none` sends `CatalogRequest::DeclareInteraction`.

* The runtime creates a server-issued `DecisionKind::DeclareInteraction` record, completed
  only by an attended `Decide`; the client shows the decision text and requires a typed
  `yes` (ADR-0006 §3.1). The decision text is: "Heimdall will treat this key as needing no
  confirmation and will launch non-interactive work with it. If the key in fact asks for
  confirmation, the agent's dialog can still appear."
* Approval records `InteractionDeclaration { interaction: none, fingerprint, endpoint,
  declared_at, expires_at, decision }`.
* The declaration **lapses**, and the identity is `unknown` again, when:
  * the identity's endpoint locator differs from the recorded one;
  * an explicit `agent` probe does not list the fingerprint at that endpoint;
  * it reaches `expires_at` (default 30 days; QR1);
  * the owner withdraws it (`WithdrawDeclaration`, narrowing, no decision).
* Every result shows `basis: declared` and `declared_at`, never `observed`.

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
| a human step the provider owns may be needed under `--non-interactive`: ⟨r2⟩ any pair's interaction is not `none`, including `unknown` and a lapsed declaration (Q2 as qualified) | `INTERACTION_REQUIRED` (exit 3), reason `provider_interaction` or `interaction_unknown` | `interact` with `provider_interaction`, never a `decision_ref` (spec §5.5) |
| none of the above | `ACCESS_READY`, with `credential_availability` = `interaction_required` (1Password, or an `unknown` native key) or `current_only` (a native key declared `none`), and no claim of unattended use | |

Provider dialogs are reported as the provider's, not as Heimdall prompts: `decision_ref`
belongs only to Heimdall's own decision records (spec §5.5). ⟨r2⟩ With several pairs, the
non-interactive refusal applies when **any** pair needs or may need interaction, because
`run` cannot know which destination the child will use (QR5).

**Identity selection** ⟨r2⟩ (M2-D01).

* Every managed alias gets `IdentityAgent <provider endpoint>`, `IdentityFile <materialized
  .pub>` and `IdentitiesOnly yes` (F8, F9). This stops the agent from offering keys that
  the configuration does not list, and avoids too-many-keys failures (A35) for `exclusive`
  aliases.
* It does **not** stop ssh from trying identities that the user's configuration adds for
  the alias (F2, F9). Those aliases are `not_exclusive` (§3 item 3), and Heimdall never
  says that only the adopted key is used for them.
* Revision 1's "there is no fallback to other agent keys" is withdrawn. It holds only for
  `exclusive` aliases, and only for the configuration (§12.2 item 1). Whether a
  non-interactive request should refuse a `not_exclusive` alias is QR4.

## 8. D7 — Process contract: `run`, `connect`, TUI handoff

**Unix `run` replaces itself with the child (`exec`).** The sequence:

1. `ensure` and `bind`;
2. resolve the program;
3. write the side-channel record `launching` (an attempt);
4. `execve` through `std::os::unix::process::CommandExt::exec`.

The Heimdall process becomes the child, so these are exactly the platform's: exit status
and death by signal, job control (stop and continue by the shell), terminal ownership,
stdio, working directory and signals. This removes the launcher stop-mirroring failures
that both G02 prototypes showed (ADR-0002 §6, §6.1, "M01 must design exec-equivalent job
control"). Nothing Heimdall prints reaches stdout. Pre-launch diagnostics go to stderr
(spec §10.4).

Disclosed residuals:

* Rust std resets SIGPIPE to default in the child, so a SIGPIPE ignored by the caller is
  not preserved (ADR-0002 §5). ⟨r2⟩ The test
  `run_m02::a27_sigpipe_ignored_by_caller_is_reset_limitation_recorded` records this
  limitation. It is not evidence of signal-disposition fidelity.
* ⟨r2⟩ On Unix, Heimdall has no positive observation of a successful `execve`. Heimdall
  dying after writing `launching`, a successful exec, and an exec failure whose
  `prelaunch_failed` write also failed all look the same to a reader. They are classified
  `indeterminate` (below), never as "launched".

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
* ⟨r2⟩ A resolved path that is not valid Unicode is refused (`LAUNCH_FAILED`, reason
  `refused_path`), because the binding names the executable as text (§10).

**Exit codes:**

* a pre-launch failure in Heimdall uses the ADR-0006 §6 table;
* a program that cannot be launched (not found, refused, current directory) exits **127**,
  and one found but not executable exits **126**, both with the new code `LAUNCH_FAILED`
  (§10; Q-B fixes 127);
* after launch, the status is the child's;
* the side channel tells these apart when it can (spec §10.4); the exit status alone never
  does.

**Side channel** ⟨r2⟩ (M2-D07; §12.2 item 7). Two protocols carry NDJSON `RunRecord`s (§10).
Neither ever carries `argv`.

* **Records.**
  * `launching` is an **attempt**: resolved executable, operation and binding IDs,
    Heimdall's PID, and Git consumer overrides (below);
  * `prelaunch_failed`;
  * on Windows only, `spawned` (written after `CreateProcessW` returned, with the child's
    PID) and `exited`.
* **Invariant: no `launching` record means not launched.** Heimdall execs or spawns only
  after `launching` was written in full (fd: the whole line written; file: written and
  fsync'd). If that write fails, Heimdall aborts: exit 127, `LAUNCH_FAILED` with reason
  `meta_unavailable` on stderr, and no child.
* **`--meta-fd <n>`** (Unix only). The descriptor must be open (`fcntl(F_GETFD)`) and be a
  pipe, socket or regular file; otherwise it is a `USAGE_ERROR` before `ensure`. Heimdall
  sets `FD_CLOEXEC` on it, so an exec closes it. EOF after `launching` is **not** proof of
  exec (residual above). If `execve` returns, Heimdall writes `prelaunch_failed`. A failure
  of that write (for example `EPIPE` because the reader has closed; Rust ignores SIGPIPE,
  so Heimdall does not die of it) leaves `launching` last.
* **`--meta-file <path>`** (all platforms). The file is created exclusively (`O_CREAT |
  O_EXCL | O_NOFOLLOW`, 0600, or an owner-only DACL); an existing path is a `USAGE_ERROR`
  before `ensure`. Each record is one write followed by fsync. On Unix the descriptor is
  closed by the exec (close-on-exec). The file is read after the process exits; a reader
  cannot use EOF as a signal.
* **Reader classification** (normative; `contract::run_record::classify`):

  | Records, in order | Classification |
  |---|---|
  | none | `not_launched` |
  | … `prelaunch_failed` | `not_launched`, with code and reason |
  | `launching` and nothing after (Unix) | `indeterminate`: launched, or Heimdall stopped before or during exec |
  | `launching` and nothing after (Windows) | `indeterminate`: the spawn may have succeeded before Heimdall stopped |
  | `launching`, `spawned` (Windows) | `launched` |
  | `launching`, `spawned`, `exited` (Windows) | `launched`, with the exit code |

  A positive Unix launch observation would need an observer process outside the exec
  model; it is rejected (§11).

**Argument privacy** ⟨r2⟩ (Q8 as qualified, §12.2 item 11). `argv` never crosses IPC and is
never journaled. Spec §13.6 forbids collecting full commands by default, and arguments can
carry secrets (A33). The `bind` request names the resolved executable and the holder
process instead (§10, Q8). Argument text also never appears in:

* error messages: a refusal names an argument by index only (`ArgumentUnescapable {
  index }`);
* batch refusals;
* idempotency replay records;
* events and logs;
* side-channel records.

**Holder process** ⟨r2⟩ (Q5 as qualified).

* **Unix:** `run` binds with holder = its own PID and OS start time, and that PID becomes
  the child.
* **Windows:** the holder is the launcher, which waits for the child. Forced termination of
  the launcher releases the binding while the child may keep running; this is disclosed and
  tested.
* The supervisor releases the binding reference only once that exact process (PID and
  start time, so a reused PID never counts) is observed **exited**. `Unknown` liveness
  never counts as an exit.
* The PID is lifecycle metadata, never authorization (spec §4.2, §13.2).

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

**Git under `run`** ⟨r2⟩ (M2-D10; §12.2 item 10).

* **Resolution.** Before launch, when a `git` executable is resolvable, the CLI resolves
  Git's effective SSH selection **in the child's working directory, with the child's
  environment**: `git -C <cwd> config --show-scope --get core.sshCommand`. It is a local
  query (2 s, no shell, stdin null), and the order is F22's: `GIT_SSH_COMMAND`, then
  `core.sshCommand` at its winning scope, then `GIT_SSH`, then Git's default.
* **Privacy.** The value is used in memory only, to classify the selection as
  `verified_client`, `bundled_msys`, `other` or `undetermined`. It is never recorded or
  sent over IPC. The child's `argv` is never inspected.
* **Unix:** nothing is set for Git; the selection is reported.
* **Windows:** only when the selection is Git's bundled MSYS default (no environment
  override, no value at any scope in that directory, `GIT_SSH` unset), Heimdall adds
  `core.sshCommand=<verified client>` through Git's environment configuration
  (`GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, `GIT_CONFIG_VALUE_<n>`, appended after any
  entries the caller set; a malformed caller `GIT_CONFIG_COUNT` means nothing is added).
  A `git -c core.sshCommand=…` in the child's own arguments, and a caller's
  `GIT_SSH_COMMAND`, therefore still win (F22 `[I]`; settled by
  `git_run_injection_yields_to_dash_c_and_env`). If that test fails on a target Git, the
  injection falls back to `GIT_SSH_COMMAND`, and the result discloses that a per-command
  `-c` is then overridden.
* **Reporting.** Whenever another selection is in force, nothing is set and the result
  reports `ConsumerOverride { consumer: git, setting: "core.sshCommand" | "GIT_SSH_COMMAND"
  | "GIT_SSH", source: git_scope(<scope>) | environment }` in the `launching` record and on
  stderr.
* **Disclosed:** the resolution covers the child's starting directory. Git commands the
  child runs in other repositories may select differently. Because the injected value is
  command scope, it also overrides a `core.sshCommand` that such a repository sets locally.
  The Q7 global include (§5.6) has neither limit and is the recommended Windows setup.
* `SSH_AUTH_SOCK` is set to the identity's endpoint only when every pair of the binding uses
  the same endpoint (otherwise it is left unchanged and the result says so). An effective
  IdentityAgent in the configuration wins (F8). Heimdall reports this as a
  `consumer_override` with provenance (spec §10.3 "Do not set SSH_AUTH_SOCK and assume that
  every consumer uses it").

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

## 9. D8 — Test environments: OpenSSH ignores `$HOME`; fixture isolation is not configuration

OpenSSH reads the user configuration and expands `~` from the account's home directory
(F19), so a test cannot redirect `~/.ssh/config` by setting `HOME`. AGENTS.md forbids
editing the owner's `~/.ssh` and using the owner's agents or keys. Therefore:

1. **Product tests** set the user-configuration path through the env-gated test
   configuration (the M01 `testcfg` pattern; never compiled into release builds). ⟨r2⟩
   (M2-D09; §12.2 item 9.) Every client a test runs gets **only isolation** on its command
   line:
   * `-F <scratch user config>`, which also drops the system file (F6; the evaluator covers
     the system file separately);
   * `-o UserKnownHostsFile=<scratch>/known_hosts` and `-o
     GlobalKnownHostsFile=<scratch>/empty`;
   * `-o BatchMode=yes` where the test is non-interactive.

   For Git, the same is set through `GIT_SSH_COMMAND` in the test harness only. **Never**
   `IdentityAgent`, `IdentityFile`, `IdentitiesOnly`, `HostName`, `User` or `Port`:
   command-line values win (F1), so they would bypass the configuration under test.
2. ⟨r2⟩ **Two counting agents.** `SSH_AUTH_SOCK` points at a **decoy** counting agent, B,
   distinct from the provider agent, A, that the projection names. Projection, A01 and A35
   tests assert A's contacts and **zero contacts on B**. A mutation test breaks the
   rendered IdentityAgent and requires the same oracle to fail.
3. ⟨r2⟩ **Default-identity guard.** Before a client runs, the fixture evaluates the alias
   under test statically. It refuses to run (`FixtureUnsafe`) unless the alias's identity
   list is non-empty and every entry is a scratch path. Otherwise ssh's default identity
   files (F20), which come from the account home (F19), would be the owner's real keys.
4. ⟨r2⟩ **Disposable agents.** Each one is `ssh-agent -D -a <scratch>/agent.sock`, started
   with `HOME=<scratch home>` so that its default socket directory and its stale-socket
   cleanup (F21) stay in scratch. It is stopped by exact PID. A counting proxy socket in
   front of a real agent supplies contact counts.
5. **"Ordinary `ssh` without `-F`"** (A01, plan "A participant can connect without a
   mandatory work wrapper") is demonstrated only where the account home itself is
   disposable: the WSL distribution ADR-0004 §3 authorizes (`wsl --import`, then
   `--unregister` of that distribution only), and Docker containers on the build host
   (supplementary Linux arm64). The native macOS and Windows rows need a disposable OS
   account, which is an owner input (m02-plan §7).

## 10. Contract additions (ADR-0006 revision 3 deltas)

The final field lists and types are in m02-plan §5; that list is normative for the
integrator. In summary:

* **Requests.**
  * `Request::Setup(SetupRequest { Preview { intent } | Apply | Rollback | Repair })`: every
    effectful action carries `plan_digest`. ⟨r2⟩ Preview takes an intent (apply, rollback or
    repair) and has no `evaluate` flag.
  * `Request::Catalog(CatalogRequest { … })`. ⟨r2⟩ It gains `DeclareInteraction` and
    `WithdrawDeclaration`.
  * Both are gated by capability `setup/1`.
* **Bind change:** `BindForm::Launch(LaunchBinding { executable, holder })` replaces
  `argv` (Q8); `holder` is excluded from the request hash.
* **Ensure and capabilities.**
  * `RequiredCapabilities.unattended`;
  * `EnsureData.{credential_availability, provider}`;
  * `ConsumerIntegration.{executables, overrides, pairs}` ⟨r2⟩, where `pairs` carries
    per-pair identity, endpoint, alias, interaction and `identity_selection`.
* **Next actions:** `NextAction.provider_interaction`.
* **Codes:** `LAUNCH_FAILED`. ⟨r2⟩ New `ErrorData.reason` values include
  `concurrent_writer`, `git_config_locked`, `mixed_mechanisms`, `meta_unavailable`,
  `interaction_unknown` and `config_commands_not_authorized`.
* **Inspection:** the `InspectSubject` variants `identities` and `projections`.
* **Other types.**
  * `ids::IdentityId` (`idn`);
  * `contract::{doctor, provider, run_record}`. ⟨r2⟩ `ProbeRecord` gains `authorization`,
    `executed_config_commands`, `effects_excluded` and `containment`. `RunRecord` gains
    `spawned` and the reader classification `classify`. New types `GitConfigChange`,
    `GitSshSelection` and `IdentitySelection`.
* **Resource kinds:** `projection`, `identity`, `provider`, `executable`.
* **Domain.**
  * `DecisionKind::ApplyProjection { operation, plan_digest, summary }`. ⟨r2⟩ It names the
    waiting operation, and its summary includes the restore column.
  * ⟨r2⟩ `DecisionKind::DeclareInteraction` (QR1).
  * ⟨r2⟩ `OperationKind::{SetupApply, SetupRollback, SetupRepair, Catalog}`;
    `RecoveryIntent.local`; `OwnerRef::Projection`.

Nothing removes or re-types an existing field except `BindForm::Launch` and the
`OperationKind` and `DecisionKind` additions, which are exhaustively matched in M01 code
and change with it (m02-plan U0b). The contract is not frozen (ADR-0006 §1), so these are a
revision rather than a major bump, and no external reader exists yet.

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
| ⟨r2⟩ Stripping or rewriting the user's IdentityFile entries to make selection exclusive | Edits unrelated user configuration (spec §5.2; §12.2 item 1) |
| ⟨r2⟩ A digest check followed by plain `rename` | Not a compare-and-swap. A write between the check and the rename is silently lost (M2-D03) |
| ⟨r2⟩ Link-then-rename where atomic exchange is missing | A rename-replace by another writer between the link and the rename loses that writer's file. Manual mode is used instead (§5.3 step 8) |
| ⟨r2⟩ A forked observer process to prove a successful Unix exec | Adds a process outside the exec model (job control, signals, exit status) for a fact that a caller rarely needs. `indeterminate` is reported instead (§8) |
| ⟨r2⟩ Writing `core.sshCommand` with `git config --global` (revision 1 Q7 text) | A set replaces an existing single value. Between Heimdall's check and the write, a value the user added would be lost, and the CLI cannot compare against the preview (M2-D10). The include block under Git's own lock (§5.6) compares and preserves |
| ⟨r2⟩ Run-time Git injection through `GIT_SSH_COMMAND` (revision 1) | It overrides a per-command `git -c core.sshCommand` that Heimdall cannot see without parsing the child's arguments. `GIT_CONFIG_COUNT` yields to it (§8). It remains the fallback if the F22 test refutes that |
| ⟨r2⟩ Keeping `setup preview --evaluate` | It executed configuration inside a nominally read-only preview; the doctor `evaluate` level with `--allow-config-commands` covers authorized evaluation (§6) |

## 12. Questions for the orchestrator (authority semantics; recommended answers)

These are kept as asked in revision 1. §12.1 and §12.2 hold the rulings; §12.3 holds the
questions that revision 2 raises.

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

### 12.2 Rulings on the independent design review (orchestrator, 2026-11-01)

Source: `tests/evidence/artifacts/review-m02-design/review.md` (verdict "proceed after
fixes"; 1 blocker, 9 majors). Every proposed fix is accepted, and §12.1 is qualified
accordingly. The design-fix round applies these rulings to this ADR and to m02-plan.md
before wave 0.

1. **M2-D01 (blocker): no claim of single-key selection when the client can fall back.**
   * The user's configuration is preserved and never edited to strip their
     `IdentityFile` entries.
   * The evaluator computes the effective identity and certificate list for each
     managed alias. If it holds entries beyond the adopted one, readiness reports
     `identity_selection: not_exclusive`, as a doctor finding with the exact remedy, and
     Heimdall never claims that only the adopted key is used.
   * D6's "no fallback" wording is withdrawn wherever it is not guaranteed.
   * Tests: a rejected adopted key with an inherited accepted second key, in
     agent-backed and file-backed variants.
2. **M2-D02: commit points.**
   * First adoption and update get separate commit points and partial-effect contracts.
   * Every precondition is revalidated before activation.
   * A durable intent records enough to reconcile an already-active P.
   * A failure after activation reports the applied or partial effect.
   * Tests: an edit after P is replaced, and a crash there.
3. **M2-D03: the replacement strategy.**
   * The displaced file is kept until validation after the replacement passes.
   * At the write boundary, file identity, type, owner and permissions are rechecked,
     including symlink and reparse-point substitution.
   * Cleanup is bound to generation plus recorded filesystem identity, never to content
     alone.
   * Tests: race injection after the final comparison, and the same bytes in a new file
     identity.
   * Whatever concurrency gap remains is stated as an unsupported case, not counted as
     meeting A22.
4. **M2-D04: rollback and removal by effect.** Rollback and removal are classified by
   their before/after effective behavior. A decision is required when the removal moves
   routing or authentication to another usable configuration, unless that exact rollback
   was part of earlier recorded consent. Test: removal exposes an inherited HostName and
   agent. This qualifies §12.1's Q1 note.
5. **M2-D05: unknown interaction by default.**
   * Native-agent identities default to `interaction: unknown`, which refuses
     non-interactive launch.
   * "No interaction" is an attended owner declaration, recorded with its source and
     time and shown as declared, not observed.
   * Test: a disposable confirm-constrained key in `ssh-agent`, refused before any
     provider contact.
6. **M2-D06: probe levels state their real effects.**
   * `evaluate` on executable configuration is named "runs your configuration's commands
     with whatever effects they have", and needs explicit authorization saying so.
   * Exclusions that cannot be enforced are not claimed. Signature-count assertions are
     specific to each fixture.
   * Tests: hooks that attempt network access, agent contact, mutation and process-group
     escape, each accurately classified.
7. **M2-D07: launch metadata.**
   * `launching` records an attempt. Without a stronger observation the outcome is
     `indeterminate`.
   * The fd and file protocols are specified separately, with their failure cases.
   * Tests: termination just before exec, and an exec failure followed by a failed
     metadata write.
8. **M2-D08: M01 integration work is owned.** U0 or the integrator owns the changes to
   existing M01 code:
   * `decide` dispatch for `ApplyProjection`;
   * bind validation after `argv` is dropped;
   * `OperationKind` setup and catalog variants;
   * durable setup intents and receipts, and recovery dispatch;
   * propagating integration and provider facts through `ensure`, `bind`, replay and
     restart.

   End-to-end tests run through the real dispatcher and store.
9. **M2-D09: fixtures.**
   * Fixture isolation stays separate from the configuration under test: only scratch
     `-F` and trust isolation on the command line.
   * Two counting agents, asserting which one was contacted.
   * A mutation of the rendered `IdentityAgent` must fail the tests.
10. **M2-D10: the Git projection gets a full contract.**
    * `GitConfigChange` is fully specified: scope and origin, previous values, absent
      versus multiple values, conditional update, receipts and recovery.
    * Git's effective selection is resolved at run time in the child's working
      directory, honouring environment and configuration overrides, and never recording
      arguments.
    * Tests: concurrent edits, local overrides, quoting, crash boundaries, and rollback
      after a later user change.
11. **Qualifications on Q1–Q8:**
    * **Q5:** `Unknown` liveness never counts as an exit. On Windows the holder is the
      launcher, which is documented and tested.
    * **Q6:** uninstall keeps conflict and recovery artifacts when rollback is
      incomplete, and a purge never reports an unresolved cleanup as success.
    * **Q8:** removing arguments covers errors, batch refusals, replay and side-channel
      records.

### 12.3 ⟨r2⟩ Questions raised by the design fix (recommended answers)

Units build against the recommended answers. The integrator changes the affected unit if a
ruling differs.

* **QR1. The "no interaction" declaration** (§7; §12.2 item 5). Is the attended declaration
  a server-issued `DecisionKind::DeclareInteraction` record, completed only by an attended
  `Decide` and shown through the client confirmation contract? And does it lapse on an
  endpoint change, on a failed listing of the fingerprint, on owner withdrawal, and after
  a bounded validity? **Recommended: yes.** Validity defaults to 30 days, can be configured
  shorter, and is never longer than 90 days. Withdrawal narrows and needs no decision.
  *Why:* the declaration widens what non-interactive work may launch, and ADR-0006 §3.1
  routes widening through decision records, never request content (A29). The bound limits
  how long a statement nobody re-checks can stand.
* **QR2. The consent rule** (§5.2; §12.2 item 4). Is "no new decision when every affected
  item's after-state equals its current state, its consented managed state, or the
  consented restore state shown in the last decision" the intended reading of "that exact
  rollback was part of earlier recorded consent"? And may the apply decision's restore
  column serve as that consent? **Recommended: yes.** The owner sees the restore column
  when approving the apply, and any drift since then (an inherited HostName or agent added
  later) breaks equality and requires a new decision.
* **QR3. The Git mechanism** (§5.6). Q7 was ruled with "writes it with `git config
  --global`". Revision 2 instead writes a marked include block under Git's own lock
  protocol, plus a Heimdall-owned file, and applies only when no `core.sshCommand` exists
  in any scope. Is this accepted under the Q7 ruling? **Recommended: yes.** The authority
  the owner grants is unchanged: a separately itemized, default-off entry of the same
  decision, for the same setting. It closes the lost-update race that M2-D10 found, and it
  never overwrites or restores a user value.
* **QR4. Non-exclusive selection under non-interactive work** (§3 item 3, §7). Should a
  non-interactive `ensure` or `run` refuse when a pair's identity selection is
  `not_exclusive` or `undetermined`? **Recommended: no, report only, in M02.** The extra
  identities are the owner's own configuration and apply to ordinary ssh anyway. The
  readiness result and doctor state it, Heimdall claims nothing stronger, and A11's "no
  unapproved fallback" evidence is the `exclusive` fixture. A
  `RequiredCapabilities.exclusive_identity` minimum can be added later if a caller needs
  it.
* **QR5. Multi-pair non-interactive launch** (§7). Should non-interactive `run` refuse when
  **any** pair of the binding needs or may need interaction, even if the child might only
  use another pair? **Recommended: yes.** Heimdall does not inspect the child's arguments,
  so it cannot know which destination the child will use; refusing is the only rule that
  guarantees "without a popup".
* **QR6. Partial application across items** (§5.6). When the Git item fails after the SSH
  item committed, may the SSH item stay applied, reported `partial`, instead of being
  rolled back? **Recommended: yes.** Each item is itemized and approved separately in the
  same decision. An automatic rollback would itself be a behaviour change that §5.2 might
  require consent for.

### 12.4 Orchestrator rulings on §12.3 and m02-plan §6 (2026-11-01)

* **QR1–QR6:** each recommended answer is accepted as written.
* **P3, P4, P6:** accepted.
* **P5, the atomic swap mechanism:** the implementer chooses either a reviewed crate or FFI
  in `crates/localenv/src/sys.rs`. A new crate must be pinned and audited per plan §7.4,
  and recorded in `docs/architecture/dependencies.md` with its justification. FFI must be
  added to the overview §9 unsafe inventory. On a filesystem without atomic swap, manual
  mode is used and there is no unsafe fallback (§5.3).
* **B10:** Windows Developer Mode, or one elevation, for the Windows file-symlink row of
  A22. It is a physical owner input, and that row is `blocked` on it.
* **Next step:** this revision gets a second independent design review before wave 0
  (U0 + U0b).

## 13. Consequences

* New crates: `heimdall-sshconf` (pure), `heimdall-localenv` (local I/O, discovery,
  probes, projection files), `heimdall-adapters` (`native_agent`, `onepassword`) and
  `heimdall-launch` (process contract).
* The `unsafe` inventory gains a third module, `crates/localenv/src/sys.rs`, for:
  * `getpwuid_r` (F19) and `killpg` on Unix;
  * ⟨r2⟩ the atomic exchange and no-replace renames (`renameat2` on Linux,
    `renameatx_np` on macOS), unless U0 adopts a reviewed safe wrapper that provides them
    (recorded in `dependencies.md`);
  * on Windows: `ReplaceFileW` with a backup name, handle-based identity checks and
    deletion (`GetFileInformationByHandleEx`, `SetFileInformationByHandle` with
    `FileDispositionInfoEx`), the profile directory, and the probe job objects.

  The integrator updates overview §9.
* The store moves to migration `0005_existing_access` (`SCHEMA_VERSION` 5) and gains
  `Store::open_read_only` for doctor. ⟨r2⟩ It gains tables for interaction declarations,
  per-grant prepared facts and projection consent.
* ⟨r2⟩ Existing M01 code changes in the places m02-plan U0b lists. The integrator applies
  them after the concurrent M01 work on `operations.rs` and `revocation.rs` has landed.
* `docs/compatibility/matrix.md` gains rows for native agent and 1Password × {ssh, Git,
  SCP, SFTP} × {macOS, Linux, Windows}, with exact labels; M02 claims nothing unattended.
  ⟨r2⟩ It also records identity selection exclusivity as a per-configuration fact, the
  §5.9 unsupported cases, and the Git run-time limits of §8.

## 14. Reopen conditions

Reopen this ADR if any of the following happens:

* a target client contradicts F1–F3, F20 or the include-state inference (corpus test);
* Win32-OpenSSH refuses the rendered P or the `ReplaceFileW`-preserved file;
* a supported user layout needs the include somewhere other than the top;
* the owner rules differently on Q1–Q8 or QR1–QR6;
* G05 changes how consumers bind (spec §10.3);
* M03/M04 need P to carry CertificateFile, ProxyJump or Heimdall endpoints (that is a
  revision of §2's directive set);
* ⟨r2⟩ a target filesystem in the declared layout lacks atomic exchange, or
  `ReplaceFileW` is shown not to retain the displaced file;
* ⟨r2⟩ a target Git contradicts F22 (lock protocol, include precedence, `GIT_CONFIG_COUNT`
  yielding to `-c`, or the global-file rule).

## 15. ⟨r2⟩ Change log (revision 2, task M02-T00-design-fix)

| Finding | Ruling (§12.2) | Sections changed here | m02-plan.md |
|---|---|---|---|
| M2-D01 (blocker) inherited identities defeat single-key selection | item 1 | F2, F9, F20 (§1); §3 item 3 (identity selection classes, finding replaces `inherited_identities`); §7 "Identity selection" (no-fallback wording withdrawn), `integration.pairs`; §9 item 3; §10; §11 row; QR4 | U2 `identity_selection`; U3 finding; U6 pairs; U9 A35 tests; §3 A11/A35 rows; §5 items 8, 9, 11 |
| M2-D02 P-before-B on an existing installation | item 2 | §5.4 (first adoption vs update commit points, revalidation, partial-effect contract, cancellation); §5.7 (intent records the active generation and displaced file) | U4 tests `a22_update_*`, `a22_first_adoption_*`; U5 restart tests |
| M2-D03 digest checks are not CAS; cleanup by content | item 3 | §5.3 (replacement primitive: identity and owner recheck, exchange, displaced file kept, restore); §5.8 (generation + identity cleanup, identity-bound deletion); §5.9 (unsupported cases); F24; §11 rows; §13 `unsafe` inventory; §14 | U4 interfaces and race and identity tests; §4 platform rows |
| M2-D04 rollback/removal not inherently narrowing | item 4 | §5.2 (consent by effect, restore column); §5.5 (rollback, repair, removal decided by §5.2); QR2 | U2 `consent`; U5 decision tests; U9 test; §5 items 2, 17 |
| M2-D05 native-agent `none` default violates no-popup | item 5 | F23; §7 interaction table (`unknown` default), declaration workflow and lapse, results table; QR1, QR5 | U6, U8, U9 tests; §5 items 3, 9, 17 |
| M2-D06 probe levels promise unenforceable exclusions | item 6 | §6 ladder (effects of configuration commands, `--allow-config-commands`, signature counts, containment, `ProbeRecord`); §5.1 (`--evaluate` withdrawn from preview); §11 row | U3 tests; U7 hook helper; U9 flags; §5 items 2, 11 |
| M2-D07 EOF after `launching` is not exec proof | item 7 | §8 residuals, side channel (attempt semantics, invariant, fd and file protocols, failure cases, reader classification, Windows `spawned`); §11 row | U8 `meta` and tests; §5 item 12 |
| M2-D08 ownership omits M01 integration work | item 8 | §1 context; §7 one mechanism per grant; §10 (domain kinds, exhaustive matches); §13 | new unit **U0b** (exact functions and types); §2 order; §5 items 15, 17, 18 |
| M2-D09 default fixture bypasses projection selection | item 9 | §9 (isolation-only command line, two counting agents, mutation check, default-identity guard, agent `HOME`); F21 | §0 fixture rules; U7 `ScratchHome`, `CountingProxy`; U9 A35 tests |
| M2-D10 Git projection lacks a contract | item 10 | F16, F22; §4 Git rendering rows; §5.6 (GitConfigChange: observation, applicability, include under Git's lock, receipts, recovery, rollback, partial application); §8 "Git under run" (resolution in the child's directory, `GIT_CONFIG_COUNT` injection, privacy, disclosures); §11 rows; QR3, QR6 | U3 `git.rs`; U4 Git steps and tests; U8 Git run tests; §5 items 2, 8, 12 |
| Q5, Q6, Q8 qualifications | item 11 | §8 holder (Unknown never exits; Windows launcher holder); §5.5 uninstall and purge; §8 argument privacy | U8, U9 tests |
| Review A22/A27 notes (encodings, SIGPIPE) | — | §4 encodings paragraph; §8 SIGPIPE residual reworded | U4, U8 tests |
