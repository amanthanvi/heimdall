# ADR-0007 — Existing-access integration (M02): managed OpenSSH projection, nonexecuting discovery, existing-access adapters, and the process contract

**Status:** proposed, revision 4 · **Date:** 2026-11-01 ·
**Tasks:** M02-T00-design (revision 1), M02-T00-design-fix (revision 2),
M02-T00-design-fix-2 (revision 3), M02-T00-design-fix-3 (revision 4)
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
**Revision 3:** applies the second independent review
(`tests/evidence/artifacts/review-m02-design/round2.md`, findings M2-R01–M2-R08) under the
orchestrator's rulings in §12.5. Text changed by it is marked **⟨r3⟩**. §15.1 maps each
finding to the sections that changed. Questions revision 3 could not settle are in §12.6.
**Revision 4:** applies the third independent review
(`tests/evidence/artifacts/review-m02-design/round3.md`, findings M2-S01–M2-S05) under the
orchestrator's rulings in §12.8. Text changed by it is marked **⟨r4⟩**. §15.2 maps each
finding to the sections that changed. Questions revision 4 could not settle are in §12.9.
**Not decided here:** anything §12.3, §12.6 or ⟨r4⟩ §12.9 lists as an open question.
Authority semantics fixed by the spec, ADR-0004, ADR-0005 or ADR-0006 are not changed.

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
| F22 | ⟨r2⟩ Git: the precedence of F16; `GIT_SSH_COMMAND` and `core.sshCommand` run through the shell [G03-S13, G03 Q13]. Beyond that, Git's documentation is not pinned, so the following are `[I]`: the scope order (system < global < local < worktree < command) with the last value winning for a single-valued key; `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>` entries being command scope that `git -c` overrides; `[include] path`; the `<file>.lock` write protocol; which file `--global` writes; `git config --show-scope` output. ⟨r3⟩ Also `[I]`: a query scoped to one file (`--system`, `--global`) follows `include.path` only with `--includes`; `--global` reads both `$XDG_CONFIG_HOME/git/config` and `~/.gitconfig`, the XDG file first; a query run outside any repository does not follow an `includeIf` whose condition needs one (`gitdir:`, `onbranch:`). ⟨r4⟩ Also `[I]`: a `<file>.lock` that appears through a no-replace rename keeps Git writers out exactly as one Git created with an exclusive open (§5.6) | each is settled by the Git test named where §5.6 or §8 relies on it; ⟨r3⟩ the three added facts by `git_queries_use_includes_flag_and_expand_includes`, `git_both_global_files_present_include_goes_to_first_read_file_and_later_user_values_in_either_win` and `git_value_through_conditional_include_is_counted_conditional`; ⟨r4⟩ the lock fact by `git_writer_during_heimdall_lock_fails_cleanly_nothing_lost`, which now claims the lock by rename |
| F23 | ⟨r2⟩ An agent key can carry a confirmation constraint (`ssh-add -c`; the agent asks through ssh-askpass before each use). ssh-add(1) is not pinned, so this is `[I]`. The constraint is not visible in an identity listing, so it cannot be detected passively | ⟨r3⟩ settled by `f23_confirm_constraint_installed_prompts_per_signature_and_is_not_listed`, an authorized disposable signing control: the constrained key prompts once per signature, the same key added without `-c` prompts zero times, and the two listings are equal. The refusal test `run_m02::a11_confirm_constrained_native_key_refused_before_agent_contact` runs on that verified installation (§12.5 item 8) |
| F24 | ⟨r2⟩ Atomic exchange of two directory entries: Linux `renameat2(RENAME_EXCHANGE)`, macOS `renameatx_np(RENAME_SWAP)`. Windows has no exchange; `ReplaceFileW` with a backup name keeps the displaced file there. None of these is pinned. Support per filesystem, and what `ReplaceFileW` captures as the backup under a concurrent replacement, are `[I]`/`[U]` | `integration_projection::exchange_supported_on_target_fs`, ⟨r3⟩ `windows_replace_retains_displaced_identity_without_race` (the race-free case only). What `ReplaceFileW` captures under a replacement **inside** the call stays `[U]` in M02 (§5.9 item 2) |
| F25 | ⟨r4⟩ A Unix (device, inode) pair can be reused once the file's last link is gone. A birth time (Linux `statx` `STATX_BTIME`, macOS `st_birthtimespec`) distinguishes a reused inode where the filesystem records one. Whether each target filesystem records it (APFS, ext4, the container overlay) is `[I]`/`[U]`. Windows' 128-bit file ID is taken as not reused while the volume is mounted (`[I]`) | `integration_projection::file_identity_birth_recorded_on_target_fs`; the Windows claim is not tested in M02 (§5.9 item 5) |

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
   `inherited_identities` is replaced by these. ⟨r3⟩ Each entry also records its
   fingerprint when its `.pub` is readable, and its backing: `agent` (the private key
   file is absent, so ssh uses the agent's key, F9), `file` (a private key file is
   present) or `unknown`. Reporting is not enough on the no-interaction path: there a
   `not_exclusive` or `undetermined` selection is refused unless every alternative entry
   is cleared (§7, M2-R05).
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
preview names the undetermined aliases and the exact doctor command, ⟨r3⟩ which always
includes `--allow-config-commands` (§6, M2-R06).

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
values and the kinds of their conditions. ⟨r3⟩ The digest does **not** bind a condition's
contents: the command of a `Match exec`, the ranges of a `localnetwork`, the DNS answer a
canonicalization would get. Equal digests therefore prove equal behaviour only for a
**determined** state, one in which every directive of the item's `RelevantBehavior` is
`Determined` or `Unset`. Any other state is **undetermined** (§6). Each recorded state
carries this classification (`BehaviorState { digest, determined }`, §10).

**A change needs no new decision when, for every affected item, its *current* and *after*
states are both determined, and *after* equals *current* or one of its *consented*
states.** ⟨r3⟩ A consented state counts only if it was determined when it was recorded.
An **affected item** is one whose rendered section, or Git selection, the plan changes;
the plan does not affect any other item. Any other change creates an `ApplyProjection` decision
(§10). It is completed only by an attended `Decide`. Unattended sessions get
`INTERACTION_REQUIRED` with `decision_ref`; attended sessions get `APPROVAL_REQUIRED`
(ADR-0006 §3.1). Consequences:

* First adoption, and any new or changed managed alias, always need a decision.
* A byte-identical re-render needs none, because it affects no item.
* A rollback, an alias removal, or a `Rerender` repair needs none while every affected
  item's states are determined and the configuration yields exactly what the owner was
  shown: the restore state for a removal, the managed state for a re-render.
* A rollback that would expose a HostName, agent, identity or proxy that the user's
  configuration gained after that decision needs one.
* ⟨r3⟩ **Any change for which an affected item's current or after state is undetermined
  needs a new attended decision, whatever the digests say** (M2-R03; §12.5 item 3).
  Example: the user changes the command of a `Match exec` that chooses between the same
  candidate HostNames. The candidates and the condition kind are unchanged, so the digest
  is unchanged. A later rollback still needs a decision. Prior consent covers determined
  states only.

The comparison is static and executes nothing. Its reasons are listed in the plan
(`consent.reasons`, ⟨r3⟩ including `undetermined_state`). The decision summary shows the
before, after and restore columns, so consent to an apply covers exactly that later
rollback and nothing wider. QR2 (§12.3) was accepted in §12.4. ⟨r3⟩ §12.5 item 3 limits
it: the restore column serves as consent only for a determined restore state.

### 5.3 The file replacement primitive

⟨r2⟩ Every write of a file the projection owns or edits (P, the user file, key files, P_git,
B_git's file) uses one primitive. It is designed so that **no file that Heimdall did not
create, or did not validate as the plan's base, is ever deleted or overwritten
unrecoverably** (M2-D03).

⟨r3⟩ The primitive only exchanges, validates and, when told to, restores. **Settlement is
a separate step that only the transaction calls** (step 8). Settlement means removing
the displaced entry. The transaction calls it after every transaction-level check has
passed and the outcome is durably recorded (§5.4; §12.5 item 1). Until then the displaced
entry stays where the exchange left it, so a restore remains possible (M2-R01). From
step 3 on, each step writes the durable receipt named in §5.7 before the next begins.

⟨r4⟩ **Identity is not enough to discard** (M2-S02; §12.8 item 2). Identity proves which
entry is Heimdall's. It does not prove that nobody wrote into that entry since Heimdall
last read it. Every discard therefore checks both: the entry must have the recorded
identity **and** its expected digest. That is the target digest for a staged entry S and
the base digest for a displaced entry D, both taken from the `SetupIntent`. The expected
digest travels with every restore and settlement call and receipt (steps 7 and 8). Modified
content is never deleted. It stays in the quarantine as a conflict artifact and is
reported. **The writer's bytes are durable** (M2-S05; §12.8 item 5): every byte the
primitive writes comes from the `SetupIntent` (§5.7), never from a preview held in memory.

1. **Validate the directory.** Open it with `O_DIRECTORY|O_NOFOLLOW` (Unix) or as a
   non-reparse handle (Windows). It must be owned by the current user and not writable by
   group or others (Unix), or carry no reparse point (Windows). Every later step is
   relative to this handle (`openat`, `renameat`), so a substituted parent path
   is not followed. ⟨r3⟩ The directory's quarantine (below) is opened, or created when a
   removal first needs it, relative to the same handle.
2. **Validate the file**, when the plan expects it to exist. Unix: open it
   `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` relative to the directory and `fstat` it. It
   must be a regular file owned by the effective UID, with a link count of 1 and no group
   or other write bit. Then read it (≤ 1 MiB) and compare its SHA-256 with the plan's base.
   Windows: open it with `FILE_FLAG_OPEN_REPARSE_POINT`; it must be a regular file with no
   reparse tag, owned by the current user's SID, with one link. Record the file identity
   **V** (Unix device and inode, ⟨r4⟩ plus the birth time where the filesystem records one,
   F25; Windows volume serial and 128-bit file ID). When the plan
   expects the file to be absent, `lstat` must report `ENOENT`. A digest mismatch is
   `CONFIG_CONFLICT` (`user_config_changed` or `managed_file_edited`). A type, owner, link
   or reparse failure is manual mode (`unmanageable_file`). In both cases nothing is
   written.
3. **Stage.** Create `.<name>.hm-<generation>-<random>` in the same directory with
   `O_CREAT|O_EXCL|O_NOFOLLOW` and the original's permission bits (new files 0600, or an
   owner-only DACL), write the new bytes, and fsync. Record the staged identity **S** in a
   stage receipt (`file.staged`) before step 4. ⟨r3⟩ The staged name is fixed in the
   `SetupIntent` before anything is written (§5.7). Its `<random>` part is 128 bits, as
   hex. ⟨r4⟩ The new bytes come from the step's `content` in the `SetupIntent` (§5.7): the
   whole target for a Heimdall-owned file, or the recorded splice applied to the bytes just
   validated in step 2 for the user file and the global Git file. Their SHA-256 must equal
   the step's target digest, or nothing is written. For B_git the staged name is random
   too. Git's lock name is taken afterwards by a no-replace rename of the receipted staged
   file (§5.6). Revision 3 staged B_git directly at the lock name, which left a crash window
   with no receipt naming the entry (M2-S03).
4. **Recheck at the boundary.** `fstat` the validated descriptor again, `lstat` the path,
   and re-read the bytes. The entry must still be V, with the same type, owner, link
   count, mode and digest. This narrows the race window; it does not close it. ⟨r3⟩ Then
   write `file.validated` (V, or `absent`). Because this receipt is durable before every
   exchange, a step without it was never exchanged.
5. **Exchange: the commit point for this file.** ⟨r3⟩ Afterwards write `file.exchanged`.
   * Unix: atomically exchange the staged name and the path (F24). Afterwards the path is S,
     and the staged name holds **D**, whatever was at the path at that instant. A file the
     plan expects absent is renamed with no-replace (Linux `RENAME_NOREPLACE`, macOS
     `RENAME_EXCL`); `EEXIST` is a conflict.
   * Windows: `ReplaceFileW(path, staged, backup = .<name>.hm-displaced-<generation>,
     REPLACEFILE_WRITE_THROUGH)`. It keeps the replaced file's DACL and attributes (`[I]`,
     settled by `windows_replace_preserves_dacl`) and leaves the displaced file D at the
     backup name (`[I]`, settled by ⟨r3⟩ `windows_replace_retains_displaced_identity_without_race`
     for the race-free case; §5.9 item 2). A file
     the plan expects absent is moved with `MoveFileExW` without `REPLACE_EXISTING`.
6. **Post-validate.** D must be a regular file with identity V and the base digest, and the
   path must be S. ⟨r3⟩ The verdict is recorded (`file.post_validated`). On a mismatch it
   also records the identity actually found at the displaced name, because a restore must
   put exactly that entry back.
   * ⟨r3⟩ **Valid:** the primitive returns. **D stays at the displaced name; nothing is
     settled.** The transaction decides whether to commit (then settle D) or to restore.
   * **D is not V, or its digest is not the base.** Another writer replaced or rewrote the
     file between steps 4 and 5. A file-level restore (step 7) follows at once. Result
     `CONFIG_CONFLICT` with reason `concurrent_writer`; the other writer's content is the
     active file; no behaviour change for this file.
7. **Restore** ⟨r3⟩ (file-level after a mismatch, or transaction-level when §5.4 decides to
   restore). ⟨r4⟩ The call carries the expected entry at each name: S with the target
   digest at the path, and at the aside name D (V, or the identity a mismatch recorded).
   **Before anything moves**, the path must still be S **with the target digest**. If it is
   S with other content, someone edited the active file after the exchange. Restoring
   would put the older file in front of that edit, which is what spec §10.1 forbids for a
   stale backup. So the step is held instead (§5.7 outcome **H**, reason
   `active_entry_modified`; QR13). D's content is not required: D goes back to the path
   whatever it holds, and nothing of it is discarded. Write `file.restore_started` with
   its cause (`file_mismatch` or `transaction_check`). Then exchange again (Unix), or call
   `ReplaceFileW(path, displaced name, backup = staged name)` (Windows), so that D is back
   at the path and S is aside. Verify both identities and write `file.restored`. A step
   whose base was absent (a create) is restored by settling its path entry, expected S
   with the target digest, into the quarantine (step 8). ⟨r4⟩ `file.restored` follows
   that settlement.
   * **The restore finds something that is neither D nor S** (a third writer). Nothing
     is moved or deleted. ⟨r4⟩ The step is held (outcome **H**, reason `third_writer`).
     Revision 3 renamed the entry left aside to `<name>.hm-conflict-<generation>` and
     settled the item. That entry could be the foreign one, and Heimdall cannot tell which
     state the item is in, so the owner decides instead (§5.7 "Outcome H").
8. **Settle** ⟨r3⟩ (called only by the transaction). The entry left aside is removed
   through the quarantine: D after a committed forward step, S after a restore, or an
   unexchanged S.
   1. Write `file.settling` with the source name, the expected identity, ⟨r4⟩ the expected
      digest (the target digest for S, the base digest for D) and a fresh quarantine name
      (128 random bits).
   2. Move the source into the quarantine under that name with a no-replace rename
      (Linux `RENAME_NOREPLACE`, macOS `RENAME_EXCL`, Windows `MoveFileExW` without
      `MOVEFILE_REPLACE_EXISTING`).
   3. Check the moved entry's identity ⟨r4⟩ and read its content (at most 1 MiB). If both
      the identity and the digest are the expected ones, write `file.settled`. Then remove
      the entry inside the quarantine, re-checking its identity ⟨r4⟩ and digest
      immediately before. Unix uses `unlinkat` relative to the quarantine handle. Windows
      uses a handle opened with `FILE_FLAG_OPEN_REPARSE_POINT` whose file ID was checked
      (`FileDispositionInfoEx`).
   4. ⟨r4⟩ **The identity matches but the content does not** (or the content cannot be read
      within the bound). Something wrote into the entry after Heimdall last checked it. In
      the review's case (M2-S02), an editor rewrote the active P in place and the
      transaction then restored the old P. The entry stays in the quarantine under its slot
      name as a **conflict artifact**, and `file.settle_conflict{modified}` records it.
      Result: finding `conflict_artifact_present` with reason `modified_after_exchange`
      and the entry's path. Nothing is deleted. When the kept entry was the active file
      before a restore (S), the operation's effect is `partial`, because a newer edit is no
      longer at its path. When it was a displaced D, the item's outcome stands.
   5. If the identity is not the expected one, a foreign entry took the source name after
      step 1. It is moved back with no-replace, or kept as `<name>.hm-conflict-<generation>`
      if the name is occupied again (`file.settle_conflict{foreign}`). Nothing foreign is
      ever deleted.
9. **Manual mode instead of automatic.** Heimdall prints the exact block and changes
   nothing when the file or its directory fails a step-1 or step-2 check
   (`unmanageable_file`: a symlink, a reparse point such as a junction, OneDrive placeholder
   or file symlink, a hard link count above 1, not a regular file, a foreign owner, not
   writable, ⟨r3⟩ or a quarantine that cannot be created or validated), when the
   filesystem has no atomic exchange (`atomic_exchange_unsupported`;
   Unix `EINVAL`/`ENOTSUP`/`ENOSYS` from the exchange), or when the encoding is unsupported
   (§4). Doctor afterwards verifies that the block is present and placed correctly.

**The quarantine and the directory-concurrency assumption** ⟨r3⟩ (M2-R02; §12.5 item 2).
Unix cannot unlink by identity: `unlinkat` removes whatever entry has the name when it
runs. Removing a name in the user's directories therefore depends on one assumption: no
other process renames an entry onto that name between Heimdall's identity check and the
unlink. Here "the user's directories" are `~/.ssh`, `<config_dir>` and its `keys/`, and the
directory of the Git global file. Editors and tools legitimately rename into these
directories at any time, so **the assumption cannot be enforced there. Heimdall never
removes a name in them.** Every removal first moves the entry into the quarantine of its
own directory, which keeps the rename on one filesystem. That covers a displaced D, a
restored-away S, an unexchanged staged S, and every cleanup (§5.8). The ruling's second
option is taken: the unlink is avoided where the assumption cannot be enforced.

* **The quarantine** is `<dir>/.hm-quarantine`. Heimdall creates it with `mkdirat`, mode
  0700 (Windows: an owner-only DACL), lazily on first need. It removes the directory with
  `rmdir` once empty, which cannot remove anything else: `rmdir` fails on a directory that
  has entries. It holds only entries Heimdall moved there.
* **The assumption, stated for the quarantine only:** no process other than Heimdall
  creates, renames or replaces entries inside a quarantine directory.
* **Enforcement:**
  * Heimdall opens the quarantine with `O_DIRECTORY|O_NOFOLLOW` relative to the validated
    parent handle (Windows: no reparse point). On every use it must be owned by the
    current user, have mode exactly 0700 (an owner-only DACL), and not be a mount point.
    Anything else is manual mode.
  * Entries are created only by no-replace renames, under 128-bit random names or, for
    the cleaner, a name derived from the locator (§5.8).
  * The identity is re-checked immediately before each removal. Removals inside the
    quarantine happen only for an identity recorded in a `file.settling` receipt or a
    cleanup locator, ⟨r4⟩ and only while the entry still has the digest recorded with it.
    An entry that fails the digest check stays in the quarantine as a conflict artifact
    (step 8.4), and `setup status` lists it.

  To break the assumption, a process must deliberately write into Heimdall's private
  directory under a name it cannot predict. Such a process can already rewrite the user's
  files directly, and the threat model makes no claim of hostile same-user isolation
  (spec §2.2 P03, §14.1). This residual is §5.9 item 4.
* **Windows** already deletes through a checked handle, which is bound to the file's
  identity by construction. It uses the quarantine anyway, so that both platforms share
  one recovery table (§5.7).

There is deliberately no link-then-rename fallback. A rename-replace by another writer
between the link and the rename would lose that writer's file (§11).

### 5.4 Apply: commit points and the partial-effect contract

**Apply** is a journaled operation (`OperationKind::SetupApply`, ADR-0006 §14.1), decided per
§5.2. Once approved (or when §5.2 needs no decision), the driver runs:

1. **Recompute the plan.** If `plan_digest` differs from the approved one, refuse with
   `CONFIG_CONFLICT` ("preview is stale") and write nothing. The approved decision is
   consumed; the owner previews again.
2. **Persist the `SetupIntent`** (§5.7), mint the effect token, and write the `Attempted`
   receipt. ⟨r3⟩ A setup request while another setup operation of the environment is open
   or unresolved is refused before this step (`CONFIG_CONFLICT`, reason
   `setup_in_progress`, §5.7). ⟨r4⟩ The `SetupIntent`, carrying every target's content, is
   written **at admission**, in the store transaction that checks for other setup
   operations and inserts the operation (§5.7 "One setup operation at a time"). That is
   before any decision record exists, so `decide` can add `approval` to it (m02-plan U0b
   row 1). This step mints the token and writes `Attempted`. Step 1's recomputed plan must
   reproduce the intent's `plan_digest`, which binds every target digest and so every
   byte the writer will stage.
3. ⟨r2⟩ **Revalidate every precondition of every file in the plan** (§5.3 step 2) before the
   first commit point: the user file, P, every key file, and the Git files when the Git
   item is in the plan. Any failure: nothing is written.
4. Execute the file steps in plan order. Two shapes (§12.2 item 2). ⟨r3⟩ In both, the
   commit step's displaced entry is kept until the item's **transaction check** has passed
   and `item.committed` is durable. That record is written in one store transaction with
   the item's resources at N+1, the projection record and the consented states. Only then
   is anything settled (§5.3 step 8; M2-R01, §12.5 item 1).

   **First adoption** (no B in the user file):
   * *Inactive steps:* the key files, then P. Nothing references them yet: P becomes
     effective only through an Include (F3), so ordinary SSH behaviour is unchanged.
   * *Commit point:* the user-file exchange that inserts B (a no-replace create when the
     user file is absent). Immediately before it, the user file is revalidated, and so is
     P (it must still be S_P, the file this operation staged).
   * ⟨r3⟩ *Transaction check, after the commit step's post-validation:* P is still S_P with
     the target digest, and every key file still has its staged identity. If this passes,
     write `item.committed`, then settle the displaced user file. If it fails, write
     `item.rolling_back`, restore the user file (§5.3 step 7; the displaced file is still
     there), settle the staged one, and hand P and the key files to the cleaner. The
     result is `CONFIG_CONFLICT` (`managed_file_edited`) with effect `none`. ⟨r4⟩ If the
     restore cannot proceed (the user file was edited or replaced after the exchange, or the
     displaced file is gone), nothing is moved and the operation is held (§5.7 outcome H).
   * *Partial effect:*
     * A failure before the commit point leaves only inactive files. The result is the
       error (usually `CONFIG_CONFLICT`) with effect `none` for behaviour, and P and the
       key files are reported in the state `written_inactive`. The cleanup executor
       removes those files, bound to generation and identity (§5.8).
     * A post-validation restore (§5.3 step 7) also reports effect `none`, ⟨r4⟩ unless its
       settlement kept a modified S (§5.3 step 8.4). That is `partial`.
     * ⟨r4⟩ The third-writer case is held: `OUTCOME_UNKNOWN`, effect `unknown` (§5.7).
       Revision 3 reported `partial`.

   **Update** (B present, intact and first, referencing P at generation N):
   * B's bytes depend only on the marker ID and P's path, so **an update never writes the
     user file**.
   * *Inactive steps:* new key files.
   * *Commit point:* P's exchange. Immediately before it, the user file is revalidated (base
     digest, B intact and first) together with P (identity and digest of generation N).
   * ⟨r3⟩ *Transaction check, after P's exchange and post-validation.* Old P (D) is still
     at the displaced name. The check re-reads the user file: identity, base digest, B
     intact and first.
     * **Pass:** write `item.committed` (resources at N+1, projection record, consented
       states, one store transaction). Only then is old P settled.
     * **Fail:** the user file changed during the step, so the approved behaviour may not
       hold. Write `item.rolling_back`. P is restored to generation N by the restore
       exchange (§5.3 step 7); this works because old P was not settled. Then settle the
       staged new P. The result is `CONFIG_CONFLICT` (`user_config_changed`) with effect
       `none`.
     * ⟨r4⟩ If the restore meets a third writer (P itself was replaced concurrently), or P
       was edited in place after the exchange, nothing is moved and the operation is held
       (§5.7 rows F5a and F5d). Revision 3 reported `partial` here.
     * A crash between post-validation and `item.committed` is row T1 of §5.7. The check
       runs again at recovery and its result decides. A crash after `item.committed` only
       finishes forward (row T2).
     * An edit of the user file **after** `item.committed` is a later user edit, not part
       of this operation. Old P is settled, and doctor reports the edit.
   * Key files that P no longer references are removed by cleanup after `item.finished`.

   **Git item** (when in the plan): its own steps follow the SSH commit point (§5.6), with
   its own transaction check (P_git still S) and its own `item.committed`.
5. ⟨r3⟩ For each item, settle every displaced entry after its `item.committed`, then
   write `item.finished` with the item's outcome. The operation settles once every item is
   finished.

The result is `SetupResult { generation, items: [{ item: ssh|git, outcome: applied |
not_applied | restored | conflict_preserved ⟨r4⟩ | held, files }] }`. The envelope's effect
is:

* `applied` when every item applied;
* `none` when no behaviour changed;
* ⟨r4⟩ `unknown` when any item is held (§5.7 outcome H; the code is `OUTCOME_UNKNOWN`);
* `partial` otherwise.

A failure after a commit point reports `none` only when the restore was verified;
otherwise it reports the applied or partial effect, never "no change" (§12.2 item 2).
⟨r4⟩ `conflict_preserved` is now written only when the owner closes a held operation with
`keep` (§5.7).

**Cancellation** is honoured only before the first commit point. After it, the driver
finishes or restores. `CancellationRecord.may_have_external_effect` is `true` once any file
was written. ⟨r3⟩ A cancelled operation settles its staged files through the quarantine
and hands its inactive files to the cleaner (`item.finished{not_applied}`).

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
backup cannot overwrite a subsequently edited configuration"). ⟨r4⟩ A held operation
(§5.7 outcome H) has its own two resolutions, `RetryHeld` and `KeepHeld`, which name the
operation (§5.7 "Repair path").

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
  conflict file, and lists them. ⟨r3⟩ The same holds for a quarantine directory that
  still has entries. ⟨r4⟩ Entries stay there only when they could not be discarded safely:
  a Heimdall entry whose content changed after Heimdall moved it (§5.3 step 8.4).
  Revision 3 said only foreign entries stay, which the content check made untrue. Empty
  quarantine directories are removed with `rmdir`.
* ⟨r4⟩ Uninstall is a setup operation, so a held operation blocks it (`setup_in_progress`,
  §5.7). The refusal names the held operation and its two repair commands.
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

* `git config --system --includes --show-origin --get-all core.sshCommand` and the same
  with `--global`. These are exactly the Q4 local queries plus `--show-origin` and ⟨r3⟩
  `--includes`. The flag is explicit because a query scoped to one file does not follow
  `include.path` by default. The control in `git_queries_use_includes_flag_and_expand_includes`
  runs the same fixture without the flag and must miss the value. `--global` reads both
  global files when both exist (F22 `[I]`). The queries depend on
  no working directory, so no repository's local scope can leak in. The output format is
  `[I]`, settled by `git_config_query_output_parsed`. Values are held in memory only, to
  classify them and to build the preview diff text. The plan stores, per entry: scope,
  origin display path, the SHA-256 of the value, a count per scope, and ⟨r3⟩ whether the
  entry was reached through a conditional include.
* ⟨r3⟩ **Static scan of the include graph** (M2-R08; §12.5 item 8). A conditional include
  (`[includeIf "<condition>"] path = …`) whose condition needs a repository is not followed
  by a query run outside one, yet it applies in every repository its condition matches.
  Heimdall therefore also reads the system file, both global files, and every file they
  include, conditionally or not, with the pure Git-text scanner `sshconf::gitedit::scan`.
  The reads are bounded: 1 MiB per file, 64 files, include depth 10, regular files only,
  opened non-blocking. The scanner counts every `core.sshCommand` key it finds and marks
  one reached through an `includeIf` as `conditional`. It never evaluates a condition and
  never runs Git for it. Relative include paths resolve against the including file's
  directory, and `~/` against Git's home. An include it cannot read or resolve (a
  permission error, a bound exceeded, a path it cannot expand) makes the item
  `not_applicable` with reason `git_config_unreadable`.
* Environment overrides (`GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_CONFIG_*`) are per-process
  and per-shell, so setup does not judge them. The run-time resolution of §8 handles them,
  and doctor reports, by name only, any that are set in its own environment.
* **The global file.**
  * `GIT_CONFIG_GLOBAL` set: the item is not offered (manual, reason
    `git_global_redirected`).
  * ⟨r3⟩ Otherwise B_git goes at the top of the **first global file Git reads, among
    those that exist**: `$XDG_CONFIG_HOME/git/config` (default `~/.config/git/config`)
    when it exists, else `~/.gitconfig`. When neither exists, `~/.gitconfig` is created.
    Revision 2 chose the file `git config --global` writes. With both files present that
    is `~/.gitconfig`, which Git reads after the XDG file, so a value the user later put
    in the XDG file would have lost to Heimdall's include. Placing B_git first in read
    order means a later user value in either file wins.
  * `~` is Git's home (`$HOME`, else `%USERPROFILE%` on Windows).
  * This rule is `[I]`, settled in a scratch home by `git_global_file_resolution_follows_read_order`
    and by `git_both_global_files_present_include_goes_to_first_read_file_and_later_user_values_in_either_win`.
    If a target Git reads the two files in the other order, the rule follows the
    observed order.
  * ⟨r3⟩ **Residual, disclosed.** Suppose B_git is in `~/.gitconfig` because no XDG file
    existed, and the user later creates the XDG file with a `core.sshCommand`. Git reads
    that value first, so Heimdall's include wins over it. Doctor reports
    `git_user_value_shadowed` with both origins and the remedy: move the value to
    `~/.gitconfig`, or roll back the Git item. The matrix lists the case.
* **Git's default SSH.** It is the bundled MSYS client when the Git installation contains
  its own `ssh.exe` and no override applies. This is observed passively, as G03 P-W04 did.

**Applicability: absent versus multiple values.** The item is applicable only when **the
system and global scopes have zero `core.sshCommand` values** ⟨r3⟩ counting every file
they include, conditionally or not. The include graph must also have been read in full,
and Git's default must be the bundled MSYS client. One or more values in either scope,
including one reached only through an include, make the item `not_applicable`,
with reason `git_ssh_command_present` and the observed entries (scope, origin, count,
`conditional`). ⟨r3⟩ Repository-local, worktree and command scopes are not part of
applicability (QR3 wording corrected, §12.5 item 9). Values there win at run time anyway
(§8). Heimdall never replaces, reorders or removes a user value. So the
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
Git's lock protocol (F22 `[I]`). ⟨r4⟩ (M2-S03; §12.8 item 3.) The lock name `<global
file>.lock` is deterministic, so any Git writer can create it. Its content therefore proves
nothing: a lock holding exactly the bytes Heimdall planned can still be another writer's.
Heimdall takes the lock only through an entry that a receipt already names:

1. ⟨r4⟩ **Stage under a random name, then claim.** Heimdall stages the new bytes at the
   step's random staged name (§5.3 step 3) and writes `file.staged` with S's identity.
   **That receipt is the ownership record.** It is durable before the lock name exists,
   and its token is S's file identity, which no content can imitate (F25: device, inode
   and birth time on Unix, the 128-bit file ID on Windows). Heimdall then claims the lock
   by renaming the staged file onto `<global file>.lock` with no-replace (Linux
   `RENAME_NOREPLACE`, macOS `RENAME_EXCL`, Windows `MoveFileExW` without
   `MOVEFILE_REPLACE_EXISTING`). The lock name appears atomically, and only if it was
   absent, which is what Git's exclusive create guarantees (F22 `[I]`). `EEXIST` gives
   `CONFIG_CONFLICT` with reason `git_config_locked`. Nothing is written to the global
   file, and S is settled from its staged name. Revision 3 created the lock name directly
   with exclusive create. A crash before `file.staged` then left an entry at the lock name
   that no receipt named, and recovery row F0x could delete another writer's lock after
   checking only its content (M2-S03).
2. Under the lock it revalidates the global file against the plan's base.
3. It checks that the new bytes parse: `git config --file <lock name> --no-includes --list`
   (a local query).
4. It exchanges. The displaced file now sits at the lock name, which keeps Git writers out
   until post-validation ⟨r3⟩ and settlement finish.
5. ⟨r3⟩ The Git item's transaction check follows: P_git still has its staged identity and
   target digest. Then comes `item.committed` for the item. Only after that does
   settlement (§5.3 step 8) move the displaced file from the lock name into the
   quarantine, which also releases Git's lock (M2-R01).

⟨r4⟩ **Who owns the lock name.** An entry at the lock name is Heimdall's only when its
identity is one a receipt recorded **before** that entry could be at the lock name:

* S, recorded by `file.staged` before the claim;
* D, recorded as V by `file.validated` before the exchange put it there.

Anything else is foreign, whatever its content, and is never moved or removed. That includes
an entry with equal bytes and another identity, and any entry when no receipt for the step
exists. **At recovery**, on a Unix filesystem that records no birth time (F25), a (device,
inode) pair at the lock name does not prove ownership. While Heimdall was down, the user may
have removed its lock (Git's error message suggests it), and Git may have created a new one
on the freed inode. There recovery observes every entry at the lock name as X (QR15). Within
one run this does not arise: the live path holds the lock from claim to settlement, and the
lock's identity is checked at each step. Heimdall never deletes a lock. Releasing it means
moving Heimdall's own entry into the quarantine (§5.3 step 8).

During that interval, Git commands that write configuration fail with Git's own lock error,
and nothing is lost. Editors that ignore the lock are covered by §5.3 step 7 and §5.9.

**Effective selection.** The plan carries `effective_before` and `effective_after`
(`GitSshSelection`, §10), computed from the system and global scopes. A repository's own
value, or an environment override, still wins at run time (§8).

**Receipts and recovery.**

* P_git and B_git are file steps of the same `SetupIntent` (§5.7), placed after the SSH
  commit point, with resources `ConfigProjection` in the roles `git_managed` and
  `git_include`.
* **Crash with the lock name occupied.** ⟨r3⟩ Recovery follows the §5.7 table. ⟨r4⟩ The
  B_git step has a random staged name and uses the lock name as its displaced name. Before
  `file.validated`, rows G1–G4 decide from where S is found. From `file.validated` on, the
  F rows apply, with the lock name as the aside name. An entry at the lock name that the
  ownership rule above does not make Heimdall's is never moved or removed, whatever its
  content. The Git item is then `not_applied` with `git_config_locked`, or held, as the
  rows say.

  Doctor reports `git_config_lock_held`, with the path, for as long as that state lasts.
  ⟨r4⟩ The finding also says whether a receipt makes the lock Heimdall's. When none does,
  the remedy is Git's own: remove the lock once no Git process is running. Heimdall never
  does that itself.

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
  approval: Option<ProjectionApproval { decision, plan_digest }>,   ⟨r3⟩
  consent: ConsentRecord,
  files: Vec<FileStep>,
}
FileStep {
  role: user_ssh | managed_ssh | key(fp) | git_include | git_managed,
  path,
  base: Absent | Present { sha256 },
  target: Absent | Present { sha256 },
  content: StepContent,                                              ⟨r4⟩
  commit: bool,
  staged_name,
  displaced_name,
}
StepContent =                                                        ⟨r4⟩
  | Whole { bytes }                   // P, P_git, a key file: the whole target
  | Splice { offset, remove_len,      // the user file, the global Git file:
             removed_sha256, insert } //   B or B_git inserted, or removed
  | Absent                            // target absent: the cleaner removes it
```

⟨r3⟩ `approval` is the projection-specific approval, distinct from the declaration
approval (§10; §12.5 item 7). The staged and displaced names are fixed in the intent
before anything is written. On Unix the displaced name is the staged name, because the
exchange leaves D there. On Windows it is `.<name>.hm-displaced-<generation>`. ⟨r4⟩ For
B_git the staged name is random and the displaced name is the lock name on both
platforms (§5.6).

⟨r4⟩ **Target content is durable** (M2-S05; §12.8 item 5). The intent carries every byte
the writer will write. `ProjectionWriter::apply` and `reconcile` read the bytes from the
intent alone. Neither consults a preview, a `ProjectionSpec` or any state held in memory,
so a fresh writer in a fresh process can execute or recover any intent. Revision 3's
intent held only digests, from which a fresh writer could not rebuild a new alias section
or a public key.

* **What is stored.** Only nonsecret bytes that Heimdall itself renders:
  * the rendered SSH configuration sections, that is P;
  * public-key files;
  * the managed Git file P_git;
  * the include blocks B and B_git, as the `insert` of a splice.

  The splice for the user file and the global Git file stores Heimdall's block and its
  offset, never the user's lines. Removing a block stores the range and the SHA-256 of
  the removed bytes, which must equal the recorded block. No private material is ever
  involved. `StepContent` is built only from the renderer's output and the public-key
  serializer (a `Rendered` type that nothing else constructs). The canary scan covers
  stored intents (spec §7.3).
* **Bound to the digests.** `Whole.bytes` hashes to `target.sha256`. A splice applies
  only to base bytes whose SHA-256 is `base.sha256`, as read in §5.3 step 2, and its
  result hashes to `target.sha256`. Anything else is refused before the first write, and
  the operation is left unresolved (`ReconcileError::IntentInvalid`). Because
  `plan_digest` binds every target digest, an approval also covers the bytes.
* **Bounded.** A whole target is at most 256 KiB (P), 16 KiB (a key file) or 4 KiB
  (P_git). A splice inserts at most 4 KiB. One intent holds at most 256 key files and
  1 MiB of content in total. A plan beyond any bound is refused at preview with
  `CAPABILITY_UNAVAILABLE`, reason `projection_too_large`, and nothing is admitted.
* **Encoding.** Bytes are base64 (RFC 4648 §4, padded) on the wire, so a BOM and CRLF
  line endings survive exactly.

**Receipts** ⟨r3⟩ (§12.5 items 2 and 7). Each receipt is an M01 `StageReceipt` that
carries the typed payload `local` (m02-plan §5 item 17a). It is appended in its own store
transaction before the next step begins:

| Receipt | Written | Records |
|---|---|---|
| `file.staged` | after S was created and fsync'd; ⟨r4⟩ for B_git, before the lock name is claimed, which makes it the lock's ownership record (§5.6) | S's identity |
| `file.validated` | after the boundary recheck, **before** the exchange | V, or `absent` |
| `file.exchanged` | after the exchange, or the no-replace create, returned | — |
| `file.post_validated` | after post-validation | `valid`; or `mismatch` with the identity observed at the displaced name |
| `file.restore_started` | before a restore exchange, ⟨r4⟩ after the check that the path still holds S with the target digest | cause: `file_mismatch` or `transaction_check` |
| `file.restored` | after the restore exchange, both identities verified; ⟨r4⟩ for a create, after the path entry's settlement | — |
| ⟨r4⟩ `file.held` | when the step reaches outcome H; again only when a later observation differs, and at most 16 times per step | the reason, and what each observed name held (∅, S, S′, V, V′, D, X or ?), by identity, never content. Replaces revision 3's `file.restore_conflict` |
| `file.settling` | before the move into the quarantine | source (`displaced`, `staged` or `path`) ⟨r4⟩ and its name, expected identity, ⟨r4⟩ expected digest, quarantine name |
| `file.settled` | after the moved entry's identity ⟨r4⟩ and digest were verified, before its removal | `quarantined` or `nothing_displaced` |
| `file.settle_conflict` | when the source was missing or foreign, ⟨r4⟩ or the moved entry's content had changed | what was found (`missing`, `foreign` or ⟨r4⟩ `modified`) and where it was kept |
| `item.committed` | in **one** store transaction with the item's `ConfigProjection` resources at N+1, the projection record and the consented states | item, generation |
| `item.rolling_back` | before a transaction-level restore | item, reason (a `ConflictKind`) |
| `item.finished` | after the item's last settlement | `applied`, `not_applied`, `restored` or `conflict_preserved` |

Each receipt's M01 `effect` field is fixed by its phase. `item.committed` and
`item.finished{applied}` carry `Confirmed` with adapter `config_projection/<environment>`.
Every other phase carries `Attempted` with the operation's effect token. M01 readers
therefore count a written file as a possible effect (`may_have_external_effect`). The
setup driver reads only `local`.

**Recovery is a total function** ⟨r3⟩ (M2-R02; §12.5 item 2) ⟨r4⟩ (M2-S01; §12.8 item 1).
`reconcile(intent, receipts)` evaluates, for each file step,
`decide(shape, last receipt, item state, observation) -> action` over its whole domain:

* the step's **shape**: replace (base present, target present), create (base absent), the
  B_git claim (before `file.validated`), or removal (target absent; the cleaner's);
* its **last durable receipt**, or none;
* its **item state**: open, `item.committed`, `item.rolling_back` or `item.finished`;
* the **observation**, by identity ⟨r4⟩ and content, of three entries:
  * the *path*;
  * the *aside* name, which holds the step's other entry. Before the exchange and after
    a restore this is the staged name; after the exchange it is the displaced name. On
    Unix the two names are the same. On Windows recovery looks at both names, and both
    holding an entry is observed as X;
  * the quarantine *slot* named by `file.settling`.

S, V and D are the recorded identities. ⟨r4⟩ Each observed name gets exactly one symbol:

| Symbol | Observed |
|---|---|
| ∅ | no entry (`ENOENT` relative to the validated directory handle) |
| S | a regular file owned by the user, link count 1, with S's identity and the target digest |
| S′ | S's identity with other content, or content that cannot be read within 1 MiB |
| V, V′ | the validated identity V with, or without, the base digest. After a forward exchange, D is V |
| D | after `post_validated{mismatch}`: the identity that receipt recorded, whatever its content |
| Q, Q′ | in the slot: the identity `file.settling` recorded with, or without, its expected digest |
| X | anything else: another identity, a link count above 1, another owner, or not a regular file |
| ? | the observation failed: permission, I/O, or a directory or quarantine that no longer validates (§5.3 step 1) |

⟨r4⟩ `decide` has four kinds of action:

* **Forward** continues the approved plan: stage, validate, exchange, post-validate,
  commit, and settle after the commit. It ends in `applied`.
* **Restore** undoes the exchanged steps and then settles what they left aside. It ends
  in `restored`.
* **Abort** applies only when the item's commit step was never exchanged. It settles
  Heimdall's own staged entries and hands the inactive files to the cleaner. It ends in
  `not_applied`.
* **H** is the preserving conflict outcome. It covers every combination that the rows
  below do not give one of the first three actions: the rows marked H, every `?` (reason
  `unobservable`, before any row is tried), and anything no row lists.

Each action checks an entry's identity before moving it, and a discard also needs the
expected digest (§5.3). The live path writes the same receipts and, after any failure,
continues through the same `decide`.

**Outcome H** ⟨r4⟩ (§12.8 item 1):

* **Nothing is moved and nothing is deleted.** H writes `file.held { reason, observed }`,
  but only when the observation differs from the step's last `held` receipt.
* **The operation stays unresolved.** It moves to M01's unresolved state,
  `outcome_unknown` (QR14):
  * code `OUTCOME_UNKNOWN`, reason `projection_held`, effect `unknown`;
  * next action `reconcile`, naming the operation;
  * item outcome `held`.
* **Every restart re-observes** the step from the receipt before `held`. If a row now
  gives a forward, restore or abort action, recovery continues with it. Otherwise
  nothing changes.
* **Serialization still holds.** While the operation is held, no other setup request is
  admitted, not even uninstall. Its own repair is the only exception ("One setup operation
  at a time", below).
* **Reasons:**
  * `active_entry_replaced`: after an exchange and before the outcome is recorded, the
    path is not S;
  * `active_entry_modified`: the path holds S′ when a restore is due (QR13);
  * `displaced_missing`, `displaced_replaced`: D is gone, or another entry is at its name;
  * `third_writer`;
  * `ambiguous_exchange`: the receipts and the entries cannot show whether the exchange
    happened;
  * `unobservable`;
  * `unmatched`: no row lists the combination.

**Repair path for a held operation** ⟨r4⟩. `setup status` and the doctor finding
`projection_held` list each held step:

* its role and path, and the reason;
* what each observed name holds: Heimdall's S, D or V, or a foreign entry, and whether the
  content matches.

The finding names the two resolutions:

* **`setup repair --operation <id> retry`** (`RepairResolution::RetryHeld`). The owner first
  brings the files into a state a row recognizes, for example by moving an edited file
  back. Retry then re-observes and continues by the table, as a restart does. It runs
  only the held operation's own recovery, under that operation's approval.
* **`setup repair --operation <id> keep`** (`RepairResolution::KeepHeld`):
  * Heimdall moves and deletes nothing;
  * it finishes each open item: `applied` if the item has `item.committed`,
    `conflict_preserved` otherwise;
  * the operation settles `failed`, with `CONFIG_CONFLICT` and effect `partial`;
  * every entry Heimdall left in place is listed under `remaining` (`conflict_file`,
    `quarantine`);
  * nothing is handed to the cleaner, because the files of an uncommitted item may still
    be referenced;
  * the projection record keeps its last committed generation, so the next preview starts
    from the files as they are.

Both resolutions are previewed, and their plan digest binds the observed entries, so a
change between preview and repair makes the repair stale. `keep` changes no file, and
`retry` adds nothing the held operation was not approved for. Neither needs a new decision
under §5.2 (QR12).

*Replace step* (base present, target present). Within each receipt's block the rows are
tried in order. A `*` matches any symbol except `?`.

| Row | Last receipt (item state) | Path | Aside | Action |
|---|---|---|---|---|
| F0 | none | * | ∅ | Not staged. T0 |
| F0x | none | * | a regular file owned by the user, link count 1 | A crash between the exclusive create and `file.staged`. ⟨r4⟩ The evidence is the name, which is 128 random bits fixed in the intent, not the content. Write `file.staged` with its identity, then F1. Settlement checks the content, so a partly written file is kept and reported (§5.3 step 8.4). **Never used for the Git lock name** (G0) |
| F0z ⟨r4⟩ | none | * | X | A foreign entry at Heimdall's staged name: left in place and reported (`conflict_artifact_present`). Abort |
| F1 | `staged` | * | S, S′ | Not exchanged, because `file.validated` precedes every exchange. T0: resume continues with this S if it is unchanged (S); abort settles it |
| F1a | `staged` | * | ∅, X | S vanished, or something replaced it at its name. Abort, `concurrent_writer`, effect `none`. An X is left in place and reported |
| F2a | `validated` | V, V′ | S, S′ | Not exchanged. T0: resume revalidates the path, which refuses a V′, and continues with S if it is unchanged; abort settles S |
| F2b | `validated` | S, S′ | V | Exchanged, receipt lost. Write `file.exchanged`, then F3 |
| F2c | `validated` | S, S′ | V′, X | Exchanged, and D is not the validated base. Write `file.exchanged` and `file.post_validated{mismatch, observed}`. File-level restore (F5) |
| F2d | `validated` | S, S′ | ∅ | Exchanged, and D has vanished, so nothing can be restored. ⟨r4⟩ **H** (`displaced_missing`). Revision 3 settled the item as `conflict_preserved` |
| F2e | `validated` | X | S, S′ | Not exchanged; another writer changed the path. Settle S. Abort with `CONFIG_CONFLICT` (`user_config_changed` or `managed_file_edited`), effect `none` |
| F2g | `validated` | V, V′ | ∅ | Not exchanged, and S vanished. Abort, `concurrent_writer`, effect `none` |
| F2j ⟨r4⟩ | `validated` | ∅ | S, S′ | Not exchanged; the file was removed. Settle S. Abort with `CONFIG_CONFLICT`, effect `none` |
| F2k ⟨r4⟩ | `validated` | V, V′ | X | Not exchanged: the validated file is still at the path, and an exchange would have moved it aside. Something replaced S at its name. The X is left in place and reported. Abort |
| F2h ⟨r4⟩ | `validated` | X, ∅ | V | Exchanged, then the active S was replaced or removed: **H** (`active_entry_replaced`) |
| F2f | `validated` | any other | | **H** (`ambiguous_exchange`) |
| F3 | `exchanged` | S, S′ | V | Post-validate: write `file.post_validated{valid}`, then F4 |
| F3a ⟨r4⟩ | `exchanged` | S, S′ | V′, X | Write `file.post_validated{mismatch, observed}`. File-level restore (F5) |
| F3b ⟨r4⟩ | `exchanged` | S, S′ | ∅ | D vanished before post-validation: **H** (`displaced_missing`) |
| F3c ⟨r4⟩ | `exchanged` | any other | | The exchange is certain, but the path is not S: **H** (`active_entry_replaced`) |
| F4 | `post_validated{valid}` (open) | S, S′ | V | The item decides (T1): commit, then settle V (F4d); or restore (F5), which needs the path to be S |
| F4a ⟨r4⟩ | `post_validated{valid}` (open) | S, S′ | ∅ | D vanished after a valid post-validation. No restore is possible and no outcome is recorded: **H** (`displaced_missing`). Revision 3's T1 promised a restore here |
| F4c ⟨r4⟩ | `post_validated{valid}` (open) | S, S′ | V′, X | Another entry is at D's name, or D was written into: **H** (`displaced_replaced`) |
| F4b | `post_validated{valid}` (open) | any other | | ⟨r4⟩ **H** (`active_entry_replaced`). Revision 3 preserved the entries and settled the item |
| F4d | `post_validated{valid}` (`item.committed`) | * | V, V′ | Settle V. The content check keeps a V′ (§5.3 step 8.4). A path other than S is a later user edit; it is reported |
| F4e ⟨r4⟩ | `post_validated{valid}` (`item.committed`) | * | ∅, X | Nothing of Heimdall's is left to settle. Write `file.settle_conflict{missing}` or `{foreign}`; an X is left in place. The outcome stands (`applied`, finding `displaced_missing` or `conflict_artifact_present`) |
| F5 | restore due ⟨r4⟩: `restore_started`, `post_validated{mismatch}`, or `post_validated{valid}` with `item.rolling_back` | S | D | Write `file.restore_started`, unless it is the last receipt. Do the restore exchange, verify both identities, and write `file.restored` |
| F5a ⟨r4⟩ | restore due | S′ | D | The active file was edited after the exchange: **H** (`active_entry_modified`; QR13). Nothing is restored over the edit |
| F5b | `restore_started` | D | S, S′ | Restore exchange done, receipt lost: write `file.restored`. **An interrupted restore is recognized as such and never read as "not exchanged"**, because `file.validated` is on record |
| F5c ⟨r4⟩ | `restore_started` | X | S, S′ | The restore exchange is done (S is aside), and then the path was replaced. Write `file.restored` and report `concurrent_writer`. The X stays active |
| F5d ⟨r4⟩ | restore due | any other | | **H** (`third_writer`). Revision 3 renamed the entry left aside to `*.hm-conflict-*` and settled the item (its F5c and F7) |
| F6 | `restored` | * | S, S′ | Settle S. The content check keeps an S′ (§5.3 step 8.4) |
| F6a ⟨r4⟩ | `restored` | * | ∅, X | Nothing to settle. Write `file.settle_conflict{missing}` or `{foreign}`; an X is left in place. The outcome stands (`restored`) |

D in F5 is V or V′ after a forward exchange, or the identity `post_validated{mismatch}`
recorded.

*Settlement*, for every shape. The source is the name `file.settling` recorded. ⟨r4⟩ Every
combination of source {Q, Q′, ∅, X} and slot {∅, Q, Q′, X} has a row:

| Row | Last receipt | Source | Slot | Action |
|---|---|---|---|---|
| F8d | `settling` | * | X | A foreign entry was moved in. Move it back with no-replace, or keep it as `<name>.hm-conflict-<gen>`. `file.settle_conflict{foreign}`; nothing deleted |
| F8b | `settling` | * | Q | Moved, receipt lost: write `file.settled`, then remove, re-checking first |
| F8f ⟨r4⟩ | `settling` | * | Q′ | Moved, and its content had changed: it stays in the quarantine. `file.settle_conflict{modified}`; finding `conflict_artifact_present` |
| F8a | `settling` | Q, Q′ | ∅ | Move not done: move, then check (§5.3 step 8). ⟨r4⟩ When the source is the path (a create restore) and holds Q′: **H** (`active_entry_modified`), not a move |
| F8e | `settling` | X | ∅ | A foreign entry is at the source. It is not moved. `file.settle_conflict{foreign}`; nothing deleted |
| F8c | `settling` | ∅ | ∅ | **Never inferred as settled.** The entry vanished without a Heimdall receipt. `file.settle_conflict{missing}`; the item's outcome stands; finding `displaced_missing` |
| F9 | `settled` | * | Q | Remove it, re-checking the identity ⟨r4⟩ and digest first |
| F9a ⟨r4⟩ | `settled` | * | Q′ | Written into after the check: kept. `file.settle_conflict{modified}` |
| F9b | `settled` | * | ∅ | Done. Removal happens only after `file.settled`, so the absence matches a receipt |
| F9c | `settled` | * | X | Keep it. Reported (`conflict_artifact_present`) |
| F9d ⟨r4⟩ | `settle_conflict` | * | * | Final for the step. Nothing further is moved |
| H0 ⟨r4⟩ | `held` | * | * | Re-observe, and decide from the receipt before `held` |

For a create restore (`file.settling{source: path}`), the block's end is followed by
`file.restored`.

*Create step* (base absent). Nothing is displaced, so the aside name is the staged name.
Rows F0–F1a and the settlement block apply unchanged, and:

| Row | Last receipt (item state) | Path | Aside | Action |
|---|---|---|---|---|
| C1 | `validated{absent}` | ∅ | S, S′ | Not created. T0: resume continues with S if it is unchanged; abort settles it |
| C2 | `validated{absent}` | S, S′ | ∅ | Created, receipt lost. Write `file.exchanged`, then C6 |
| C3 | `validated{absent}` | X | S, S′ | Another writer created the file first. Settle S. Abort, `concurrent_writer`, effect `none` |
| C4 | `validated{absent}` | ∅ | ∅ | S vanished before the create. Not created; nothing is inferred. Abort, `concurrent_writer`, effect `none` |
| C4b ⟨r4⟩ | `validated{absent}` | ∅ | X | S is gone and nothing is at the path, so nothing of the step is active. The X is left in place and reported. Abort |
| C4h ⟨r4⟩ | `validated{absent}` | any other | | **H** (`ambiguous_exchange`). For example, X with an empty aside name is what both "created, then replaced" and "S lost, then someone else created the file" leave |
| C6 ⟨r4⟩ | `exchanged` | S, S′ | * | Post-validate: the path is S. Write `file.post_validated{valid}`, then C5. An entry at the staged name is left in place and reported |
| C6a ⟨r4⟩ | `exchanged` | any other | | **H** (`active_entry_replaced`). **This is the catch-all for a foreign active entry after a create** (§12.8 item 1). An editor that saves by rename leaves exactly this, and its file may hold B, so Heimdall cannot treat the item as not applied |
| C5 | `post_validated{valid}` (open) | S, S′ | * | The item decides (T1): commit, then write `file.settled{nothing_displaced}`; or restore (C7) |
| C5a ⟨r4⟩ | `post_validated{valid}` (open) | any other | | **H** (`active_entry_replaced`), as C6a |
| C5b | `post_validated{valid}` (`item.committed`) | * | * | Nothing is displaced: write `file.settled{nothing_displaced}`. A path other than S is a later user edit; it is reported |
| C7 ⟨r4⟩ | restore due: `restore_started`, or `post_validated{valid}` with `item.rolling_back` | S | * | Write `file.restore_started`, unless it is the last receipt. Settle the path entry through the quarantine (`file.settling{source: path}`, then the settlement block, then `file.restored`) |
| C7a ⟨r4⟩ | restore due | S′ | * | The created file was edited after the create. Removing it would hide the edit: **H** (`active_entry_modified`; QR13) |
| C7b ⟨r4⟩ | restore due | any other | | **H** (`active_entry_replaced`) |
| C8 ⟨r4⟩ | `restored` | * | * | Done. The path's later state is only reported |

*The B_git claim* ⟨r4⟩ (§5.6), before `file.validated`. These rows replace F0–F1a for the
B_git step. "The lock" is `<global file>.lock`; S is the identity `file.staged` recorded:

| Row | Last receipt | Observed | Action |
|---|---|---|---|
| G0 | none | an entry at the lock name | No receipt names it, so it is foreign: never moved, whatever its content; reported `git_config_locked`. F0, F0x or F0z apply to the staged name |
| G1 | `staged` | S or S′ at the staged name | Not claimed. T0: resume claims the lock with this S if it is unchanged; abort settles S from the staged name. An entry at the lock name is foreign: left in place, reported |
| G2 | `staged` | S or S′ at the lock name, and on Unix S's identity has a birth time (F25) | Claimed but not validated. T0: resume continues under the lock with this S if it is unchanged; abort settles S from the lock name, which releases Heimdall's own lock |
| G3 | `staged` | S at neither name, or at the lock name without a birth time | Abort, with `git_config_locked` or `concurrent_writer`. Every entry at either name is left in place and reported |

From `file.validated` on, the B_git step uses the replace rows, with the lock name as its
aside name. On a Unix filesystem without birth time, recovery observes the lock name as X,
so those rows abort (F1a, F2k) or hold (§5.6).

*Removal* (target absent), performed by the cleaner (§5.8). The cleaner writes no stage
receipts. Its slot name is derived from the locator, so a retry finds what an earlier
attempt moved. L is the locator's identity with its digest; L′ is that identity with other
content. ⟨r4⟩ Every combination of path {L, L′, ∅, X} and slot {∅, L, L′, X} has a row,
and `?` is R6:

| Row | Path | Slot | Recovery action | Conflict outcome |
|---|---|---|---|---|
| R1 | L | ∅ | Move to the slot, check the identity ⟨r4⟩ and digest, remove | — |
| R1a ⟨r4⟩ | L′ | ∅ | Left alone: the file was edited in place | M01 `Ok` with nothing removed; finding `projection_edited` |
| R2 | ∅, X | L | Crash after the move: re-check, remove | — |
| R2a ⟨r4⟩ | ∅, X | L′ | Kept in the quarantine | finding `conflict_artifact_present` (`modified_after_exchange`) |
| R3 | ∅ | ∅ | The resource is absent. The cleaner reports it absent and claims nothing about who removed it | — |
| R4 | X (same bytes or not) | ∅ | Left alone | M01 `Ok` with nothing removed; finding `projection_edited` or `conflict_artifact_present` |
| R5 | ∅, X | X | Moved back with no-replace, or kept as `*.hm-conflict-<gen>` | Reported |
| R6 ⟨r4⟩ | L, L′ | X | Nothing is moved. The resource is not confirmed absent, and the executor retries on its normal back-off | finding `conflict_artifact_present` |

*Item level* (each of `ssh` and `git`):

| Row | State | Recovery action |
|---|---|---|
| T0 | The commit step was never exchanged (its row says so) | Nothing of the item is active. Resume forward under the same plan, ⟨r4⟩ with the bytes from the intent, only when every precondition still holds (§5.4 step 3). ⟨r4⟩ Resuming continues each step from its current phase. A step with no receipt is staged. A step at `staged` or `validated` keeps its S, which must still be unchanged: its path is revalidated (§5.3 step 2), and it continues at step 4. An S that is modified or gone cannot be continued, so the item aborts. A staged name is therefore never reused, and no entry appears at it without a receipt naming it. Otherwise abort: settle the staged files, hand the inactive files to the cleaner, and write `item.finished{not_applied}`. The result is `CONFIG_CONFLICT` with effect `none` |
| T1 | The commit step is at `post_validated{valid}`, with no `item.committed` and no `item.rolling_back`, ⟨r4⟩ and every exchanged step of the item observes path S or S′ and, for a replace step, aside V | The crash fell between post-validation and the outcome record (M2-R01). **Re-run the item's transaction check now** (§5.4). If it passes, write `item.committed`, then settle. If it fails, write `item.rolling_back` and restore (F5, C7). ⟨r4⟩ The restore proceeds only where F5 or C7 allows it; otherwise the step is H. Revision 3 called the restore "always possible", which a vanished D refutes (M2-S01) |
| T1h ⟨r4⟩ | As T1, but an exchanged step observes anything else | **H**. The transaction check is not run |
| T2 | `item.committed` | Finish forward: the item's remaining steps, then every settlement (F4d, F4e, C5b). Never restore. Write `item.finished{applied}` |
| T3 | `item.rolling_back`, ⟨r4⟩ or the commit step's file-level restore (`restore_started{file_mismatch}`) | Finish the restore of every exchanged step (F5–F6, C7), settle S, hand the inactive files to the cleaner, and write `item.finished{restored}`. ⟨r4⟩ A step that reaches H holds the item. Revision 3's `item.finished{conflict_preserved}` here is withdrawn |
| T4 | `item.finished` for every item | Settle the operation with the recorded outcomes |
| TH ⟨r4⟩ | A step of the item is at H, or the item's receipts contradict each other (for example both `item.committed` and `item.rolling_back`) | **H** for the item, and so for the operation |

Wherever an entry is not provably Heimdall's, the conflict outcome preserves it. A missing
or foreign entry ends in a preserved state and is reported, never deleted, and
settlement is never inferred from an absence that no receipt accounts for (§12.5 item 2).
⟨r4⟩ Revision 3 also said that a local projection never stays in `outcome_unknown`, because
every file state is observed locally. That is withdrawn: a held operation stays there until
the owner repairs it (QR14). The outcome is applied, not applied, restored, held, or, after
`keep`, a reported conflict with preserved files. On restart the operation is driven from
its kind (m02-plan U0b); the driver calls `reconcile`, never a second `apply`. A receipt
this build cannot decode, such as an unknown phase, leaves the operation unresolved and
reported; nothing is inferred from it.

**The table is checked without its row list** ⟨r4⟩ (§12.8 item 1; m02-plan U4). `decide`
is a pure function. `recovery_decide_is_total_over_the_generated_domain` enumerates its
whole domain from the symbol alphabet and the receipt and item-state enums, never from
the rows:

* every shape, every last receipt (none and `held` included) and every item state;
* observations that no row names, and ones that need a hard link, a non-regular file or an
  unreadable directory to construct.

A filesystem-backed run, `recovery_generated_observations_preserve_every_entry`, builds
each generated combination in a scratch directory and runs `reconcile`. It then repeats
the run with a crash injected after each write that `reconcile` makes. Both tests check
only properties that every correct table has:

1. **Totality:** exactly one action, and no panic or error other than H.
2. **No loss:** every entry present before is present after, with its identity and bytes,
   at a name the result reports. The only exception is a Heimdall entry whose bytes match
   its expected digest and whose removal follows a durable `file.settled`: S, or D after
   `item.committed`.
3. **Foreign entries are never deleted.** They move only back to the name they came from,
   or to a `*.hm-conflict-*` name, both with no-replace.
4. **The path changes only through the plan:** a forward exchange or create under T0 or
   T1, or a restore exchange between S and D.
5. **H moves and deletes nothing**, and leaves the operation `outcome_unknown`.
6. **Outcomes match receipts:** `applied` only with `item.committed`; `restored` only
   with `file.restored` for every exchanged step; `not_applied` only when the commit step
   was never exchanged.
7. **Idempotence:** a second `reconcile` moves nothing more and writes nothing for an
   unchanged H.

m02-plan U4 test `recovery_table_rows_each_have_a_test_vector` keeps the other direction:
every row above has a vector, ⟨r4⟩ and the vector's action is the row's.

**One setup operation at a time** ⟨r3⟩. The table assumes that no other Heimdall
operation writes these files concurrently. Setup operations of one environment are
therefore serialized. A setup request while another setup operation is open or
unresolved is refused with `CONFIG_CONFLICT`, reason `setup_in_progress`. It is
retryable once the other operation settles.

⟨r4⟩ **Admission is atomic** (§12.8 item 6). The check for other setup operations and the
insertion of the new one happen in **one store transaction**, `Txn::insert_setup_operation`
(m02-plan §5 item 18). That transaction writes the operation row, its idempotency record
and its `RecoveryIntent` with the `SetupIntent`. It is the M01 admission transaction,
which runs as SQLite `BEGIN IMMEDIATE`, so two admissions can never both see an empty set.
Inside it:

1. Idempotency is classified first. A replay of the same request ID returns its own
   operation, and a conflicting reuse is `REQUEST_CONFLICT`. A retry is therefore never
   refused because of itself.
2. Then the transaction reads the environment's open or unresolved setup operations:
   queued, running, awaiting approval, or `outcome_unknown`.
3. If there are any, the request is refused and nothing is written. The refusal names
   each blocking operation with its next action: observe it, decide it, cancel it before
   its commit point, or, if it is held, repair it.
4. The one exception is the repair of a held operation O, `RetryHeld` or `KeepHeld` naming
   O. It is admitted when the set is exactly {O} and O is held.

A crash during the transaction leaves either the whole admission or none of it. A
restart therefore never finds a blocker with no operation behind it, nor an operation
admitted past a blocker.

### 5.8 Cleanup ownership

⟨r2⟩ Every deletion of P, P_git or a key file goes through the supervisor's single cleanup
executor (R-RT-04) and `ProjectionCleaner` (m02-plan U4). It deletes only when:

* the resource's generation is the one being cleaned (the M01 guard), **and**
* the entry at the locator has the recorded identity **and** digest.

The locator is `ProjectionLocator { role, path, identity, sha256 }`, canonical JSON and
nonsecret. The same bytes in a new identity, such as a newer generation or the user's copy,
are left alone and reported `Ok` with nothing of that generation removed (the M01
`ResourceCleaner` contract).

Deletion itself is bound to identity ⟨r3⟩ through the quarantine (§5.3):

* The cleaner moves the entry, with no-replace, into the quarantine of its own directory.
  The slot name is derived from the locator: `<role>-<generation>-<first 16 hex of the
  SHA-256 of the canonical locator>`.
* It checks the moved entry's identity ⟨r4⟩ and digest and removes it there: Unix with
  `unlinkat` after a re-check, Windows through a handle opened with
  `FILE_FLAG_OPEN_REPARSE_POINT` whose file ID was checked. ⟨r4⟩ An entry whose identity
  matches but whose content changed after the move stays in the quarantine as a conflict
  artifact (row R2a), as in §5.3 step 8.4.
* A foreign entry is moved back with no-replace, or kept as `*.hm-conflict-<generation>`
  when the original name is occupied again.
* Because the slot name is deterministic, a retry after a crash finds the moved entry
  (§5.7 rows R1–R5, ⟨r4⟩ R1a, R2a and R6).
* The cleaner claims that the resource is absent, never that it removed it.

Revision 2 renamed the entry to a unique name in the same directory and unlinked it
there. That still unlinked a name in a directory other writers use (M2-R02).

A cleanup for generation N therefore never deletes the content of generation N+1, whatever
the bytes.

### 5.9 Unsupported concurrency (stated; not counted toward A22)

⟨r2⟩ The following cases are outside what M02 supports. They are documented in `setup
status` help and in the compatibility matrix, and A22 evidence does not cover them
(§12.2 item 3):

1. **A writer that opened the file before the commit point and writes through that
   descriptor after post-validation.** Its bytes land in the displaced file, which is
   ⟨r3⟩ later moved into the quarantine and removed, or in an already unlinked inode.
   ⟨r4⟩ Settlement now reads the content before removing it (§5.3 step 8). A write that
   lands before that check is detected, and the entry is kept as a conflict artifact.
   Only a write between the final check and `unlinkat`, or into the inode after its
   removal, is lost, and Heimdall cannot detect that. Editors that
   reopen by path when saving are not affected: their save replaces or rewrites the active
   file, and doctor then reports the missing or edited block. ⟨r4⟩ A save that rewrites
   the active file while a restore is due holds the operation instead of being restored
   over (§5.3 step 7).
2. **On Windows, a replacement between `ReplaceFileW`'s own open and its internal rename.**
   What is captured as the backup in that window is `[U]`. ⟨r3⟩ It stays `[U]` in M02
   (§12.5 item 8). `windows_replace_retains_displaced_identity_without_race` shows only
   the race-free case, in which the backup's file ID equals V. No M02 test injects a
   replacement inside `ReplaceFileW`, so no evidence claims this window.
3. **Filesystems without atomic exchange.** Heimdall does not attempt automatic mode there:
   it uses manual mode (§5.3 step 9), which is supported behaviour, not a gap. Whether each
   target filesystem supports exchange (APFS, ext4 on the devbox and in WSL, the container
   overlay filesystem) is `[I]`/`[U]`, settled by `exchange_supported_on_target_fs`.
4. ⟨r3⟩ **A same-user process that writes into a Heimdall quarantine directory**
   between Heimdall's identity check and its removal of an entry there (§5.3). It would
   have to target Heimdall's private, mode-0700 directory under an unpredictable name.
   The threat model makes no claim of hostile same-user isolation (spec §2.2 P03, §14.1).
5. ⟨r4⟩ **Identity reuse** (F25). Suppose another process removes Heimdall's entry and a
   new file then gets the same (device, inode) at a name Heimdall observes. On a Unix
   filesystem that records no birth time, identity alone cannot tell the two apart.
   Two rules bound the effect:
   * every discard also needs the expected digest, so a recycled identity is discarded
     only when its bytes are exactly Heimdall's expected bytes;
   * the Git lock is the one name other programs create. At recovery it is never treated
     as Heimdall's without a birth time (§5.6).

   Windows file IDs are taken as not reused (`[I]`). M02 does not test that.

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

**`--allow-config-commands`.** ⟨r3⟩ (M2-R06; §12.5 item 6.) Some levels run ssh against
the user's real, mutable configuration tree: `evaluate`, `host_verification` and
`authentication`. Each of them needs `--allow-config-commands`, **whether or not the static
pass found an executing construct**. The static pass runs before ssh opens the files, and
the files can change in between: an editor, a sync tool or a hook can insert a
`Match exec` after the pass. Revision 2 gated only on what the static pass found, which
is withdrawn. The static pass now only informs: it lists the executing constructs it
found for the alias (Match exec, ProxyCommand, KnownHostsCommand, LocalCommand with
PermitLocalCommand; F4). The list may be empty.

* The flag's help text is the sentence **"runs your configuration's commands with whatever
  effects they have"**, followed by the file:line list ⟨r3⟩ as the static pass found it,
  or "none found now; the configuration can change before ssh reads it".
* The TUI shows the same text and requires a typed `yes`.
* Without the flag the level is declined with reason `config_commands_not_authorized`, and
  nothing runs.
* ⟨r3⟩ **Fail closed on a tree Heimdall cannot fully read.** The level is declined with
  reason `config_not_fully_readable`, **even with the flag**, when the static pass for the
  alias meets any of these: an unreadable include, a bound exceeded, or an Include path it
  cannot expand (`IncludeUnreadable`, `BoundExceeded`, or `TokenUnavailable` in an
  Include). The authorization would not name what runs (QR11 asks the orchestrator to
  confirm this reading).
* ⟨r3⟩ **After the run** ⟨r4⟩ (M2-S04; §12.8 item 4). Heimdall takes a second snapshot of
  the alias's configuration tree. It does not just re-read the files the static pass
  read. It re-walks the include expansion: every `Include` is expanded again (globs, `~`,
  tokens, `${VAR}`), and every file reached is read under the same bounds.
  * `ProbeRecord.config_tree_changed` is the **comparison of the two observed
    snapshots**. When it is `true`, `config_tree_differences` lists each file added (for
    example a new member of an `Include` glob), removed, modified or unreadable.
  * `false` means only that the two snapshots are equal. It does **not** show that ssh
    read the tree of the static pass: a file changed for ssh's read and restored before
    the second snapshot leaves both snapshots equal.
  * `executed_config_commands` therefore lists the constructs **the static pass found
    before execution**. It is never presented as complete, whatever
    `config_tree_changed` says. Every rendering labels it "configuration commands found
    before the run; the run may have executed others". Revision 3's claim that the list is
    complete when nothing changed is withdrawn.
  * `effects_excluded` excludes nothing configuration commands could do, as before.
* ⟨r3⟩ A **snapshot mode** is deferred. It would run ssh against a validated, immutable
  copy of the tree, but it needs proven path equivalence first: relative includes, `~`,
  tokens such as `%d`, and `Match final` would all have to resolve as in the real tree.
  It is not in M02 (§11; m02-plan §8).

| Level | Heimdall does | Heimdall itself never | What configuration commands can add | Default |
|---|---|---|---|---|
| `static` | parse and evaluate the configuration; stat agent sockets; list `\\.\pipe\` names without opening any; read `known_hosts` and `.pub` files; read the Heimdall store **read-only**; with **Q4**, local queries that read no SSH configuration (`<client> -V`, `ssh-keygen -F <host> -f <file>`, the `git config` queries of §5.6) | execute configuration, contact an agent or provider, use the network, sign, mutate anything | nothing: no configuration command runs | yes |
| `evaluate` | `ssh -G <alias>` with the user's real configuration (F5); ⟨r3⟩ always needs `--allow-config-commands` | contact an agent, use the network, sign | **anything**: network, agent contact and signing, file changes, long-lived processes (Match exec) | no |
| `agent` | connect to a named agent endpoint and send `SSH_AGENTC_REQUEST_IDENTITIES` only; bounded (256 KiB reply, 1024 identities, 2 s) | sign, add, remove, lock, extensions | — (no configuration runs) | no |
| `network` | TCP connect to HostName:Port and read the SSH identification line (RFC 4253 §4.2); 5 s | key exchange; aliases routed through ProxyJump or ProxyCommand are reported undetermined, not probed | — | no |
| `host_verification` | `ssh -o BatchMode=yes -o PreferredAuthentications=none -o IdentityAgent=none -o IdentityFile=none -o ControlMaster=no -o ControlPath=none <alias>`, classified from the exit code (F11) and bounded stderr markers; ⟨r3⟩ always needs `--allow-config-commands` | ask ssh to sign: with no agent, no identity file and no authentication method, ssh has nothing to sign with | anything, through Match exec, ProxyCommand and KnownHostsCommand | no |
| `authentication` | `ssh -T -o BatchMode=yes -o ControlMaster=no -o ControlPath=none <alias> exit 0`; ⟨r3⟩ always needs `--allow-config-commands` | under `--non-interactive`, run for an identity whose interaction is not `none`, ⟨r3⟩ or for a pair with an uncleared fallback identity (Q2, §7) | anything, as above; plus provider prompts in interactive mode | no |

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
* `executed_config_commands`: the file:line of each construct ⟨r3⟩ the static pass found
  before the run. ⟨r4⟩ It is never complete: the run may have executed others;
* ⟨r3⟩ `config_tree_changed`: ⟨r4⟩ whether the snapshot taken after the level, by
  re-walking the include expansion, differs from the static pass's snapshot. It is absent
  for levels that run no configuration. `false` is not proof that the tree was unchanged
  while ssh read it;
* ⟨r4⟩ `config_tree_differences`: each file added, removed, modified or unreadable
  between the two snapshots (at most 256 entries, the file bound);
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
    the user's current configuration. ⟨r3⟩ The runtime stores only the historical part
    of this (`PreparedFacts`, below). It recomputes the interaction and eligibility part
    in every result.
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
| native agent after an owner declaration | `none` | `declared`, with `declared_at`, the fingerprint and the endpoint it covers; ⟨r3⟩ only while the declaration is live, at the same endpoint and unexpired, checked fresh for every result and before every non-interactive launch (below) |

**Declaring "no interaction"** (QR1, §12.3). `heimdall identity declare-interaction <id>
none` sends `CatalogRequest::DeclareInteraction`.

* The runtime creates a server-issued `DecisionKind::DeclareInteraction` record, completed
  only by an attended `Decide`; the client shows the decision text and requires a typed
  `yes` (ADR-0006 §3.1). The decision text is: "Heimdall will treat this key as needing no
  confirmation and will launch non-interactive work with it. If the key in fact asks for
  confirmation, the agent's dialog can still appear."
* Approval records `InteractionDeclaration { ⟨r3⟩ revision, state: live, interaction: none,
  fingerprint, endpoint, declared_at, expires_at, decision }`.
  * ⟨r3⟩ The store keeps one row per identity. Its `revision` grows with every
    declaration, withdrawal and recorded lapse, each a compare-and-swap on the expected
    revision. The row is never deleted, so a revision is never reused.
  * ⟨r3⟩ **Declaration-specific approval** (§10; §12.5 item 7). `Decide approve` copies the
    decision record's fields into `DeclarationApproval { decision, identity, fingerprint,
    endpoint, interaction, valid_until }` in the waiting catalog intent. The catalog
    driver builds the declaration from that approval alone, never from request content.
    If the identity's fingerprint or endpoint changed after the decision was created, it
    writes nothing and answers `DECISION_STALE`. `ApplyProjection`'s plan digest plays no
    part in this.
* The declaration **lapses**, and the identity is `unknown` again, when:
  * the identity's endpoint locator differs from the recorded one;
  * an explicit `agent` probe does not list the fingerprint at that endpoint. ⟨r3⟩ The CLI
    that ran the listing (`doctor --active-probe agent`, `identity adopt --from-agent`)
    records the lapse with `WithdrawDeclaration { revision, reason: listing_missing }`
    when the runtime is running. Doctor never starts the runtime: otherwise it reports
    `interaction_declaration_lapsed` with `recorded: false` and the exact command
    (QR9);
  * it reaches `expires_at` (default 30 days; QR1). ⟨r3⟩ Expiry is evaluated at every
    read, so nothing has to be written for it to take effect;
  * the owner withdraws it (`WithdrawDeclaration`, narrowing, no decision).
* Every result shows `basis: declared` and `declared_at`, never `observed`.

**Launch eligibility is checked fresh** ⟨r3⟩ (M2-R04; §12.5 item 4).

* **Prepared facts are history.** What `prepare` observed is stored per grant as
  `PreparedFacts`: endpoint, alias, identity selection and provider status, each with its
  time. Attached bindings, `bind`, replay and restart reuse these. They hold **no
  interaction, availability or eligibility field** (m02-plan §5 item 17), so a stored
  fact can never re-establish `interaction: none`.
* **Eligibility is computed in the transaction that builds each result.** This covers
  every `ensure` result (attached and coalesced included), every `bind` result, and
  `inspect identities`. Each pair's `interaction`, `interaction_basis`, `declaration`,
  `noninteractive` and `credential_availability` are derived from the identity's live
  declaration row. A declaration counts only if:
  * it exists in state `live`;
  * its endpoint equals the identity's current endpoint;
  * its `expires_at` is later than the runtime's current time (ADR-0006 time rules).

  The result names the declaration it relied on (`DeclarationRef { revision, endpoint,
  expires_at }`) and when it checked (`eligibility_checked_at`).
* **Before any non-interactive launch**, the CLI reads `inspect identities` again,
  immediately before exec or spawn. This covers `run`, `connect`, and the
  `authentication` probe under `--non-interactive`. Doctor never starts the runtime: it
  reads the store read-only and applies the same pure rule,
  `heimdall_domain::catalog::eligibility`. The CLI launches only if every
  declaration the bind (or connect) result relied on is still live with the **same
  revision and endpoint**, and its `expires_at` is still later than now.
  * A withdrawal, a lapse, a re-declaration (new revision) or an expiry after `bind`
    refuses the launch: `INTERACTION_REQUIRED`, reason `interaction_unknown`, and a
    `prelaunch_failed` record.
  * A replayed `bind` result goes through the same check, so idempotent replay never
    skips it.

**Fallback identities on the no-interaction path** ⟨r3⟩ (M2-R05; §12.5 item 5, which
qualifies QR4). Reporting `not_exclusive` does not prevent a dialog: ssh tries an
inherited key after the adopted key is rejected, and the agent may then prompt for it.
The **no-interaction path** is non-interactive `ensure` readiness, `run`, `connect` and
the `authentication` probe, without `--allow-provider-interaction`. On it, a pair whose
selection is `not_exclusive` or `undetermined` is refused unless **every reachable
alternative identity is cleared** (QR8 asks for this criterion to be confirmed):

* An alternative is **cleared** only when all of these hold:
  * it is agent-backed: an IdentityFile or CertificateFile entry whose private key file is
    absent (F9), used through the alias's effective IdentityAgent;
  * its fingerprint, read from the `.pub`, is a catalog identity at that same endpoint;
  * that identity's fresh eligibility is `interaction: none`.
* These are never cleared:
  * an entry whose private key file is present, since ssh may ask for a passphrase and
    Heimdall never opens private keys to find out;
  * a FIDO `sk-` entry;
  * an `undetermined` entry;
  * an entry whose `.pub` is missing;
  * every alternative of an alias that has no determined `IdentitiesOnly yes`, because the
    agent may then offer keys that cannot be listed passively.
* The refusal is `INTERACTION_REQUIRED` (exit 3) with reason `fallback_identity_interaction`.
  It names each uncleared entry's file:line, and its next action is `interact` with
  `provider_interaction`, never a `decision_ref`. The remedies are:
  * narrow the user's entry (`Host * !<alias>`);
  * adopt and declare the alternative;
  * pass `--allow-provider-interaction`.
* The CLI's pre-launch check re-evaluates the selection statically, so a `Host *`
  IdentityFile added after `ensure` is seen. The check is passive and executes nothing.
* `exclusive` pairs and interactive use are unchanged.

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
| a human step the provider owns may be needed under `--non-interactive`: ⟨r2⟩ any pair's interaction is not `none`, including `unknown` and a lapsed declaration (Q2 as qualified); ⟨r3⟩ judged on fresh eligibility, so a withdrawn, lapsed, expired or re-declared declaration also counts; or any pair has an uncleared fallback identity (§7, M2-R05) | `INTERACTION_REQUIRED` (exit 3), reason `provider_interaction`, `interaction_unknown` or ⟨r3⟩ `fallback_identity_interaction` | `interact` with `provider_interaction`, never a `decision_ref` (spec §5.5) |
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
  `exclusive` aliases, and only for the configuration (§12.2 item 1). ⟨r3⟩ QR4 answered
  "report only" (§12.4). §12.5 item 5 qualifies that answer: on the no-interaction path
  a `not_exclusive` or `undetermined` selection is refused unless every alternative is
  cleared ("Fallback identities on the no-interaction path", above). Elsewhere it is
  reported, as before.

## 8. D7 — Process contract: `run`, `connect`, TUI handoff

**Unix `run` replaces itself with the child (`exec`).** The sequence:

1. `ensure` and `bind`;
2. resolve the program;
3. ⟨r3⟩ under `--non-interactive`, the pre-launch eligibility check (§7): a fresh
   `inspect identities` that must show the same declaration revisions, endpoints and an
   unexpired `expires_at`, plus a fresh static selection whose fallback identities are
   all cleared. A failure writes `prelaunch_failed` and exits 3;
4. write the side-channel record `launching` (an attempt);
5. `execve` through `std::os::unix::process::CommandExt::exec`.

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
    `WithdrawDeclaration`. ⟨r3⟩ `WithdrawDeclaration` also carries an optional expected
    `revision` and a `reason` (`owner` or `listing_missing`).
  * Both are gated by capability `setup/1`.
  * ⟨r3⟩ **Fail-closed landing** (§12.5 item 7). Until the real drivers land in the
    activation change set (m02-plan §2, wave 3), the new requests are refused at every
    layer:
    * `setup/1` is not offered, so a session cannot negotiate it;
    * a Setup or Catalog request on a session is answered `SCHEMA_UNSUPPORTED` by the
      existing session gate (ADR-0006 §2.4, unchanged) and never dispatched;
    * a request that reaches dispatch by any other path gets `CAPABILITY_UNAVAILABLE`
      with reason `driver_unavailable`, and leaves no operation, idempotency record,
      decision or event;
    * an open setup or catalog operation found at restart stays unresolved and untouched;
    * a decision of the new kinds is refused, not consumed.

    Wave-0 acceptance tests cover each layer (m02-plan U0b). QR7 asks the orchestrator to
    confirm the session-layer code.
* **Bind change:** `BindForm::Launch(LaunchBinding { executable, holder })` replaces
  `argv` (Q8); `holder` is excluded from the request hash.
* **Ensure and capabilities.**
  * `RequiredCapabilities.unattended`;
  * `EnsureData.{credential_availability, provider}`;
  * `ConsumerIntegration.{executables, overrides, pairs}` ⟨r2⟩, where `pairs` carries
    per-pair identity, endpoint, alias, interaction and `identity_selection`. ⟨r3⟩ Pairs
    gain `declaration` (`DeclarationRef { revision, endpoint, expires_at }`),
    `noninteractive` and `eligibility_checked_at`, all computed fresh per result (§7).
    Identity entries gain `fingerprint`, `backing` and `cleared`.
* **Next actions:** `NextAction.provider_interaction`.
* **Codes:** `LAUNCH_FAILED`. ⟨r2⟩ New `ErrorData.reason` values include
  `concurrent_writer`, `git_config_locked`, `mixed_mechanisms`, `meta_unavailable`,
  `interaction_unknown` and `config_commands_not_authorized`. ⟨r3⟩ Also
  `driver_unavailable`, `fallback_identity_interaction`, `config_not_fully_readable`,
  `git_config_unreadable` and `setup_in_progress`. ⟨r4⟩ Also `projection_held` (with
  `OUTCOME_UNKNOWN`, §5.7) and `projection_too_large`.
* **Inspection:** the `InspectSubject` variants `identities` and `projections`.
* **Other types.**
  * `ids::IdentityId` (`idn`);
  * `contract::{doctor, provider, run_record}`. ⟨r2⟩ `ProbeRecord` gains `authorization`,
    `executed_config_commands`, `effects_excluded` and `containment`. `RunRecord` gains
    `spawned` and the reader classification `classify`. New types `GitConfigChange`,
    `GitSshSelection` and `IdentitySelection`. ⟨r3⟩ `ProbeRecord` also gains
    `config_tree_changed`. `GitValueObservation` gains `conditional`. New finding codes:
    `git_config_unreadable`, `git_user_value_shadowed` and `displaced_missing`.
    `RemainingArtifact.kind` gains `quarantine`. ⟨r4⟩ `ProbeRecord` gains
    `config_tree_differences`, and the meaning of `config_tree_changed` and
    `executed_config_commands` is narrowed (§6). New finding code `projection_held`.
  * ⟨r4⟩ The port `ProjectionWriter` keeps no state between calls and gains
    `observe_held` (m02-plan §5 item 15).
* **Resource kinds:** `projection`, `identity`, `provider`, `executable`.
* **Domain.**
  * `DecisionKind::ApplyProjection { operation, plan_digest, summary }`. ⟨r2⟩ It names the
    waiting operation, and its summary includes the restore column.
  * ⟨r2⟩ `DecisionKind::DeclareInteraction` (QR1).
  * ⟨r2⟩ `OperationKind::{SetupApply, SetupRollback, SetupRepair, Catalog}`;
    `RecoveryIntent.local`; `OwnerRef::Projection`.
  * ⟨r3⟩ **Approvals, one per decision kind** (§12.5 item 7):
    * `ProjectionApproval { decision, plan_digest }` lives only in `SetupIntent`;
    * `DeclarationApproval { decision, identity, fingerprint, endpoint, interaction,
      valid_until }` lives only in `CatalogIntent`.

    Revision 2's shared `LocalApproval { decision, plan_digest }` is withdrawn, because
    `DeclareInteraction` has no plan digest.
  * ⟨r3⟩ **Typed local receipt payload:** `StageReceipt.local: Option<LocalReceipt>`
    (`file { step, phase }` | `item { item, phase }`, §5.7). Old rows read with `None`;
    nothing is migrated. ⟨r4⟩ `FilePhase` gains `held`, loses `restore_conflict`, and
    records the expected digest and source name in `settling`; `settle_conflict` gains
    `modified`.
  * ⟨r4⟩ **Durable target content:** `FileStep.content: StepContent` (`whole` | `splice` |
    `absent`), bound to the step's digests and size-bounded (§5.7). `FileIdentity` gains an
    optional Unix `birth`.
  * ⟨r4⟩ **Held operations:** `ConflictKind::projection_held`,
    `RepairResolution::{retry_held, keep_held}`, `PreviewIntent::Repair.operation`, item
    and file outcome `held` (§5.7).
  * ⟨r4⟩ **Store:** `Txn::insert_setup_operation` checks for other setup operations and
    admits the new one in one transaction (§5.7).
  * ⟨r3⟩ `BehaviorState { digest, determined }` in the consent record (§5.2).
  * ⟨r3⟩ `InteractionDeclaration` gains `revision`, `state`, `ended_at` and `end_reason`.
    `PreparedFacts` holds history only (§7).

Nothing removes or re-types an existing field except `BindForm::Launch` and the
`OperationKind` and `DecisionKind` additions, which are exhaustively matched in M01 code
and change with it (m02-plan U0b). ⟨r3⟩ `StageReceipt.local` and `RecoveryIntent.local`
are additive: serde default, omitted when absent. The contract is not frozen (ADR-0006 §1), so these are a
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
| ⟨r2⟩ Link-then-rename where atomic exchange is missing | A rename-replace by another writer between the link and the rename loses that writer's file. Manual mode is used instead (§5.3 step 9) |
| ⟨r2⟩ A forked observer process to prove a successful Unix exec | Adds a process outside the exec model (job control, signals, exit status) for a fact that a caller rarely needs. `indeterminate` is reported instead (§8) |
| ⟨r2⟩ Writing `core.sshCommand` with `git config --global` (revision 1 Q7 text) | A set replaces an existing single value. Between Heimdall's check and the write, a value the user added would be lost, and the CLI cannot compare against the preview (M2-D10). The include block under Git's own lock (§5.6) compares and preserves |
| ⟨r2⟩ Run-time Git injection through `GIT_SSH_COMMAND` (revision 1) | It overrides a per-command `git -c core.sshCommand` that Heimdall cannot see without parsing the child's arguments. `GIT_CONFIG_COUNT` yields to it (§8). It remains the fallback if the F22 test refutes that |
| ⟨r2⟩ Keeping `setup preview --evaluate` | It executed configuration inside a nominally read-only preview; the doctor `evaluate` level with `--allow-config-commands` covers authorized evaluation (§6) |
| ⟨r3⟩ Settling the displaced file inside the primitive (revision 2) | An update could then find, after a concurrent edit of the user file, that the old P it must restore was already deleted (M2-R01). Settlement now follows `item.committed` (§5.3 step 8, §5.4) |
| ⟨r3⟩ Unlinking a checked name in the user's directories | Unix has no unlink by identity, so a rename onto the name between the check and `unlinkat` would be deleted. Same-user editors rename into those directories, so the directory-concurrency assumption cannot be enforced there (M2-R02). Removal goes through the quarantine (§5.3) |
| ⟨r3⟩ Inferring "validation finished" or "settled" from an absent displaced file | Another writer could have removed it. Only a matching receipt (`file.settled`) or a cleanup goal state accounts for an absence (§5.7 rows F2d, F8c, R3) |
| ⟨r3⟩ Reusing prior consent for an undetermined state with an equal digest | The digest does not bind condition contents (M2-R03). Binding consent to the exact `Match exec` text was also rejected: it would present consent as authorizing a dynamic program. Undetermined states always need a new decision (§5.2) |
| ⟨r3⟩ Reusing stored prepared facts for interaction or eligibility | A withdrawn, lapsed or expired declaration would be resurrected at bind or restart (M2-R04). Eligibility is recomputed per result and re-checked before launch (§7) |
| ⟨r3⟩ Refusing only the adopted key's interaction on the no-interaction path | An inherited fallback identity can still raise the agent's dialog (M2-R05). Uncleared alternatives are refused (§7) |
| ⟨r3⟩ `--allow-config-commands` only when the static pass finds an executing construct (revision 2) | The tree can change between the static pass and ssh opening it (M2-R06). The authorization is required for every level that runs the real tree (§6) |
| ⟨r3⟩ Snapshot evaluation (ssh against a validated copy of the tree), now | **Deferred, not rejected.** It needs proven path equivalence for relative includes, `~`, tokens and `Match final`, and M02 has no such proof (§12.5 item 6) |
| ⟨r3⟩ Minimal local drivers in wave 0 | The ruling took the fail-closed option (§12.5 item 7): the new requests are refused until their real drivers land, so no partial driver is ever reachable |
| ⟨r3⟩ Placing B_git in the file `git config --global` writes when both global files exist (revision 2) | Git reads the XDG file first, so a later user value there would lose to Heimdall's include (F22 `[I]`). B_git goes in the first-read file (§5.6) |
| ⟨r4⟩ Settling a combination the recovery table does not list as `conflict_preserved` (revision 3 rows F2d, F2f, F5c, F7) | Heimdall could not tell which state the item was in, and the settled operation left the store and the files disagreeing. Such combinations are now held for the owner (§5.7 outcome H; M2-S01) |
| ⟨r4⟩ Discarding a restored-away or displaced entry after checking only its identity | An editor that rewrote the active file in place keeps its identity, so its edit would be deleted (M2-S02). Discards also need the expected digest; modified content stays in the quarantine (§5.3 step 8) |
| ⟨r4⟩ Restoring over an active file that was edited after the exchange, keeping the edit only in the quarantine | The edit would be preserved but no longer active, which is the stale-backup case spec §10.1 forbids. The operation is held instead (§5.3 step 7; QR13) |
| ⟨r4⟩ Creating `<file>.lock` with exclusive create as B_git's staged file (revision 3) | A crash before `file.staged` left an entry at a name any Git writer uses, with no receipt naming it. Recovery could then delete another writer's lock after checking only its content (M2-S03). Heimdall stages under a random name and claims the lock by a no-replace rename (§5.6) |
| ⟨r4⟩ Content equality, or an extended attribute or token written into the lock file, as proof of owning the lock | Content can be equal by coincidence or by design: Git writes the same bytes Heimdall planned. A token in the content would also become Git configuration. The identity recorded before the claim cannot be imitated by content (§5.6) |
| ⟨r4⟩ Inferring a complete command inventory from equal digests of the files read (revision 3) | A new glob member, or a change reverted before the comparison, leaves those digests equal (M2-S04). The comparison re-walks the include expansion and never implies completeness (§6) |
| ⟨r4⟩ Rebuilding target bytes at apply or recovery from the `ProjectionSpec`, or from a preview held in memory | The catalog can change after the approval, and a cache does not survive a restart (M2-S05). The intent carries the bytes (§5.7) |
| ⟨r4⟩ Storing the whole target user file or global Git file in the intent | Those files are the user's, not Heimdall's rendering. A splice of Heimdall's own block, applied to the validated base and checked against the target digest, suffices (§5.7) |
| ⟨r4⟩ Checking for other setup operations in one transaction and admitting in another | Two admissions could both see the empty set (§12.8 item 6). The check and the insert are one store transaction (§5.7) |

## 12. Questions for the orchestrator (authority semantics; recommended answers)

These are kept as asked in revision 1. §12.1 and §12.2 hold the rulings; §12.3 holds the
questions that revision 2 raises. ⟨r3⟩ §12.4 and §12.5 hold the later rulings; §12.6 holds
the questions that revision 3 raises. ⟨r4⟩ §12.7 and §12.8 hold the rulings on those and
on the third review; §12.9 holds the questions that revision 4 raises.

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
  ⟨r3⟩ in the system or global scope, counting the files they include (wording corrected
  by §12.5 item 9; revision 2 said "in any scope"). Is this accepted under the Q7 ruling? **Recommended: yes.** The authority
  the owner grants is unchanged: a separately itemized, default-off entry of the same
  decision, for the same setting. It closes the lost-update race that M2-D10 found, and it
  never overwrites or restores a user value.
* **QR4. Non-exclusive selection under non-interactive work** (§3 item 3, §7). Should a
  non-interactive `ensure` or `run` refuse when a pair's identity selection is
  `not_exclusive` or `undetermined`? **Recommended: no, report only, in M02.** The extra
  identities are the owner's own configuration and apply to ordinary ssh anyway. The
  readiness result and doctor state it, Heimdall claims nothing stronger, and A11's "no
  unapproved fallback" evidence is the `exclusive` fixture. ⟨r3⟩ (Qualified by §12.5
  item 5: on the no-interaction path, refuse unless every alternative is cleared, §7.) A
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

### 12.5 Rulings on design review round 2 (orchestrator, 2026-11-01)

Source: `tests/evidence/artifacts/review-m02-design/round2.md` (verdict: proceed after
fixes; M2-R01–R07 major, R08 medium). Every fix is accepted. Where a finding offered a
choice, the fail-closed option is taken:

1. **R01: settlement waits for the update to finish.** Exchange and post-validation are
   separated from final settlement. The displaced P is kept until every update-level
   check passes and the outcome is durably recorded.
2. **R02: recovery follows a state table.** The table covers forward exchange, restore
   exchange, deletion, creation when the base is absent, and removal when the target is
   absent, with durable restore phases. Settlement is never inferred from absence
   without matching receipts. A missing or foreign entry produces a preserved conflict
   state.
   * The directory-concurrency assumption for the final unlink is written down and
     enforced.
   * If it cannot be enforced, the unlink is avoided: the displaced file is renamed
     into a Heimdall-owned quarantine directory instead.
3. **R03: dynamic states need a new decision.** A behaviour-changing restore whose
   before or after state is **undetermined** always needs a new attended decision.
   Prior consent covers only determined states.
4. **R04: launch eligibility is checked fresh.** Historical prepared facts are separate
   from current eligibility to launch. Before any non-interactive launch, at bind and at
   readiness, the declaration is revalidated: it must exist, and its revision, endpoint
   and expiry must still match.
5. **R05: fallback identities on the no-interaction path.** On the no-interaction path,
   a `not_exclusive` or `undetermined` selection is refused unless every reachable
   alternative identity has sufficient interaction information. Otherwise the caller
   must pass `--allow-provider-interaction`. This qualifies QR4.
6. **R06: running against the real tree always needs authorization.**
   `--allow-config-commands` is required whenever an evaluation or probe runs against
   the mutable real configuration tree. A snapshot mode may be added later, but only
   with proven path equivalence. Unreadable or unresolved includes fail closed.
7. **R07: how wave 0 lands.**
   * New requests fail closed until their real drivers land. `setup/1` is not offered,
     and a direct request gets `CAPABILITY_UNAVAILABLE`. Wave 0 includes acceptance
     tests for this.
   * U0 freezes a typed local receipt payload, with serialization, defaults for old
     rows and migration behaviour.
   * U0 also freezes a declaration-specific approval representation, separate from
     `ApplyProjection`'s plan digest.
   * The kind-mapping test covers journaled kinds only, and documents how `Probe` maps.
8. **R08: tests must discriminate.**
   * For F23, verify that the constrained key was installed, and add an authorized
     disposable signing control.
   * Keep the Windows claim about the internal `ReplaceFileW` window marked `[U]`.
   * The Git fixtures cover both global files present, ordinary and conditional
     includes, multiplicity through includes, and include expansion.
9. **QR3 wording:** applicability is system and global only. The "any scope" wording is
   corrected.

### 12.6 ⟨r3⟩ Questions raised by revision 3 (recommended answers)

Units build against the recommended answers; the integrator changes the affected unit if a
ruling differs. Each question concerns authority or contract semantics that §12.5 does not
fix word for word.

* **QR7. Which code a session sees in wave 0** (§10, §12.5 item 7). The ruling says that
  `setup/1` is not offered and that "a direct request gets `CAPABILITY_UNAVAILABLE`".
  ADR-0006 §2.4 already fixes `SCHEMA_UNSUPPORTED` for a request whose capability the
  session did not negotiate. The M01 session gate answers it before dispatch, and a
  capability the server does not offer can never be negotiated. **Recommended:** leave
  ADR-0006 §2.4 unchanged:
  * a session sees `SCHEMA_UNSUPPORTED` (and a hello that *requires* `setup/1` is
    rejected with it);
  * `CAPABILITY_UNAVAILABLE` with reason `driver_unavailable` is the answer on every path
    that reaches dispatch (`OperationsDispatcher::handle_as`, the `Operations` entry
    points), and later for a runtime configured without a `ProjectionWriter`;
  * M02 CLI commands that have not landed keep M01's "not available in this build"
    envelope.

  *Why:* each layer keeps the code the contract already defines for it, and every layer
  fails closed. *Alternative:* to make sessions see `CAPABILITY_UNAVAILABLE`, `Request::
  required_capability()` would return nothing for the new requests until activation.
  That changes the gate's meaning between waves, so it is not recommended.
* **QR8. When a fallback identity is "cleared"** (§7; §12.5 item 5). The ruling requires
  "sufficient interaction information" for every reachable alternative. **Recommended:**
  an alternative is cleared only when it is agent-backed (its private key file is absent),
  its fingerprint is a catalog identity at the alias's effective IdentityAgent endpoint,
  and that identity's fresh eligibility is `interaction: none`, that is, a live owner
  declaration. File-backed, FIDO, undetermined and `.pub`-less entries are never cleared,
  and neither is any alternative of an alias without a determined `IdentitiesOnly yes`.
  *Why:* only a declaration is an owner statement about interaction (QR1). Anything else
  would widen what non-interactive work may launch without a decision record (ADR-0006
  §3.1, A29).
* **QR9. Recording a lapse after a failed listing** (§7). May any same-user control
  session send `WithdrawDeclaration { revision, reason: listing_missing }` with no
  decision? And when the runtime is not running, may doctor leave the lapse unrecorded
  and only report it? **Recommended: yes to both.** Withdrawal narrows, and narrowing is
  allowed on any same-user control connection (§12.1 Q1 note; ADR-0006 §13.1 item 1). The
  `revision` makes it a compare-and-swap, so a stale listing cannot withdraw a newer
  declaration. Doctor never starts the runtime (§6; spec §10.2), and the pre-launch check
  still applies to every launch.
* **QR10. Quarantine directories in the user's directories** (§5.3). Creating
  `.hm-quarantine` inside `~/.ssh`, `<config_dir>`, `<config_dir>/keys` and the directory
  of the Git global file (`~/.hm-quarantine` for `~/.gitconfig`) adds Heimdall-owned
  directories where the user keeps configuration. Is this within the adoption authority?
  **Recommended: yes.** They are not configuration: OpenSSH and Git never read them.
  They are created lazily, mode 0700, and hold only entries Heimdall displaced. They are
  removed when empty, and `setup status` and uninstall list any that are not (spec §5.2
  "permission to adopt is not permission to rewrite unrelated configuration" is not
  engaged). *Alternative:* one quarantine under `<state_dir>`. Rejected: a rename across
  filesystems fails or copies, and a copy is not identity-preserving.
* **QR11. "Unreadable or unresolved includes fail closed"** (§6; §12.5 item 6).
  **Recommended reading:** a level that runs the real tree is declined with
  `config_not_fully_readable` *even with* `--allow-config-commands` when the static pass
  for the alias could not read or resolve an include. *Why:* the authorization text
  lists what the configuration runs; if part of the tree is unreadable, the owner would
  authorize something nobody could show them. *Alternative:* treat the flag as covering
  unreadable parts too, and say so in the prompt.

### 12.7 Orchestrator rulings on §12.6 and m02-plan P7–P9 (2026-11-01)

The recommended answer to each question is accepted, as follows:

* **QR7: two stages, two codes.** A session that did not negotiate `setup/1` gets
  `SCHEMA_UNSUPPORTED`, as ADR-0006 §2.4 specifies. Every path that reaches dispatch gets
  `CAPABILITY_UNAVAILABLE` with reason `driver_unavailable`. This refines §12.5 item 7.
* **QR8: which fallback identity is cleared.** Only an agent-backed catalog identity at
  the same endpoint, holding a live `none` declaration. File-backed, FIDO and
  undetermined entries, and aliases without `IdentitiesOnly yes`, are never cleared.
* **QR9: recording a lapse.** `WithdrawDeclaration { reason: listing_missing }` is a
  narrowing action, allowed from any same-user session. Doctor reports `recorded: false`
  when the runtime is not running.
* **QR10: quarantine directories.** Accepted inside `~/.ssh`, `~` and the config
  directory. They hold no configuration, have mode 0700, and are removed when empty.
* **QR11: unreadable includes.** An unreadable include declines the level, even with
  `--allow-config-commands`. Nobody can authorize what nobody could show them.
* **P7, P8, P9:** accepted.
  * **P7:** U0b lands in two phases, with the store bodies.
  * **P8:** setup operations are serialized.
  * **P9:** the Git include block goes in the first-read global file.
* **Next step:** revision 3 gets a third independent design review before wave 0.

### 12.8 Rulings on design review round 3 (orchestrator, 2026-11-01)

Source: `tests/evidence/artifacts/review-m02-design/round3.md` (verdict: proceed after
fixes; M2-S01, S02, S03 and S05 major, S04 medium). Every fix is accepted:

1. **S01: recovery is a total function.** Recovery is defined over step shape, last
   receipt phase and observed state.
   * Any combination without an explicit forward or restore action resolves to a
     preserving conflict outcome. Nothing is deleted, the operation stays unresolved,
     and the owner gets a repair path.
   * The table gains explicit rows for:
     * create `file.exchanged` and create `file.restore_started`;
     * replace F3 with `path S, aside ∅`, and F4 with `aside X/∅`;
     * a catch-all for a foreign active entry after a create.
   * Tests generate observations independently of the row list.
2. **S02: identity is not enough.** Before a restored-away or settled entry is
   discarded, its content is checked against the expected digest, carried through the
   restore/settle contract. Modified content is preserved as a conflict artifact in
   quarantine and reported. It is never deleted.
3. **S03: a deterministic lock is presumed foreign.** An unreceipted Git lock at the
   deterministic `<file>.lock` name is treated as unowned. It is preserved and reported as
   a conflict, whatever its content. Automatic recovery of that window needs a separate
   ownership record written before the exclusive create, keyed by a token that the lock
   file's content cannot imitate. Content equality never proves ownership.
4. **S04: honest reporting of config commands.** `config_tree_changed` is a comparison of
   observed snapshots, re-walking include expansion. `executed_config_commands` lists the
   constructs found before execution and is never presented as complete. The evidence
   wording follows.
5. **S05: the writer's content is durable.** The setup intent carries the nonsecret
   rendered bytes of every target, bound to their digests and size-bounded: rendered SSH
   configuration sections, public-key files, and the Git include block. No private
   material is ever involved.
   * `ProjectionWriter::apply` and recovery read the bytes from the intent, with no
     in-memory preview cache.
   * Test: a fresh writer with no prior `preview`, including recovery before a remaining
     file is staged.
6. **`setup_in_progress`:** the empty-set check and the admission of the operation happen
   in one store transaction. Simultaneous-admission and restart tests are required.

### 12.9 ⟨r4⟩ Questions raised by revision 4 (recommended answers)

Units build against the recommended answers; the integrator changes the affected unit if a
ruling differs. Each question concerns authority or contract semantics that §12.8 does not
fix word for word.

* **QR12. Repairing a held operation** (§5.7 "Repair path"). The ruling gives the owner "a
  repair path" but does not say what it may do or who may start it. **Recommended:**
  * two resolutions: `retry`, which re-observes and continues by the table, and `keep`,
    which closes the operation and moves nothing;
  * both are previewed, and their plan digest binds the observed entries;
  * neither needs a decision, and both may be sent on any same-user control session;
  * while an operation is held, its repair is the only setup request admitted.

  *Why:* `keep` changes no file and so no behaviour (§5.2). `retry` runs only the held
  operation's own recovery, which that operation's approval already covers. Narrowing is
  allowed on any same-user control connection (ADR-0006 §13.1 item 1). Without the
  exception, the held operation would block its own repair. *Alternative:* require an
  attended `Decide` for `keep`, because it gives up automatic recovery for good. Not
  recommended: it decides nothing about access, and the files stay exactly as they are.
* **QR13. A restore that would cover a newer edit** (§5.3 step 7; rows F5a, C7a, F8a). The
  ruling preserves modified content "as a conflict artifact in quarantine" before a
  discard. When the active file itself (S at the path) was edited after the exchange, a
  restore would move that edit off the path into the quarantine and put the older file
  back. **Recommended:** check the active entry's content before any restore move. If it
  changed, do not restore; hold the operation (`active_entry_modified`). The
  discard-time check of §12.8 item 2 still covers an edit that races the restore, and
  such an edit is kept in the quarantine. *Why:* spec §10.1 forbids a stale backup
  overwriting a later edit. Keeping the edit only in a hidden quarantine directory would
  satisfy "never deleted" but not "survives" (A22). *Alternative:* restore anyway and keep
  the edit in the quarantine, reported, with effect `partial`. That is what the ruling's
  words alone require.
* **QR14. What "the operation stays unresolved" means on the wire** (§5.7 outcome H).
  **Recommended:** M01's unresolved state, `outcome_unknown`, with code `OUTCOME_UNKNOWN`,
  reason `projection_held`, effect `unknown`, next action `reconcile`, and item outcome
  `held`. It is never purged while unresolved and is re-observed at every restart, as
  M01 does for its other unresolved operations. Revision 3's sentence that a local
  projection never stays in `outcome_unknown` is withdrawn. *Why:* the state exists, means
  exactly this ("the effect may or may not have applied; reconcile before retrying"), and
  keeps the operation from being settled with an outcome nobody established.
  *Alternative:* settle with `CONFIG_CONFLICT`, effect `partial`, and a `held` flag. Not
  recommended: a settled operation would release `setup_in_progress`, and the next setup
  would run on files the table could not classify.
* **QR15. The Git lock's ownership token** (§5.6; rows G0–G3). The ruling asks for an
  ownership record written before the exclusive create, keyed by a token the lock's
  content cannot imitate. A file's identity is not known before the file exists.
  **Recommended:** stage under a random name, write `file.staged` with S's identity
  (the record), then claim the lock with a no-replace rename, which has the same
  all-or-nothing effect as Git's exclusive create (F22 `[I]`). The token is S's identity.
  At recovery on Unix the token counts only with a birth time (F25), because Git may have
  reused a freed inode at the lock name while Heimdall was down. Where the filesystem
  records no birth time, recovery observes every entry at the lock name as foreign. A crash
  of the Git item between the claim and the end of settlement then leaves the lock in
  place: the item aborts or is held, and `git_config_lock_held` reports it for the owner
  to remove. *Why:* this meets the ruling without putting a token in Git's configuration
  text. *Alternatives:* never treat any lock-name entry as Heimdall's at recovery, which
  leaves a lock behind after every such crash; or offer the Git item only in manual mode
  on filesystems without birth time.

### 12.10 Orchestrator rulings on §12.9 and m02-plan P10–P11 (2026-11-01)

* **QR12–QR15:** each recommended answer is accepted.
  * **QR12:** `retry`/`keep` of a held operation is previewed and needs no decision. It may
    come from any same-user session, and it is the only setup request admitted while that
    operation is held.
  * **QR13:** a newer edit to the active file after the exchange holds the operation
    instead of restoring over it. This is stricter than §12.8 item 2 and is preferred,
    because spec §10.1 forbids hiding a newer edit behind an older file.
  * **QR14:** a held operation is `outcome_unknown` (`OUTCOME_UNKNOWN`, effect `unknown`,
    `next: reconcile`). Revision 3's claim that a local projection never stays in
    `outcome_unknown` is withdrawn.
  * **QR15:** the lock token is the identity recorded before the claim. On Unix that
    includes a birth time. Without a birth time, an entry at the lock name is foreign and
    is left for the owner.
* **P10 and P11:** accepted. The full crash-injection domain runs natively; check.sh runs
  a seeded sample of at least 2,048 cells. The content bounds stand as proposed.
* **Next step:** a focused check (design review round 4) covers M2-S01 to S05, the new
  interfaces, and U0b's descriptions of the current M01 code at ADR-0006 r2.17
  (§13.20). Wave 0 follows if it is clean.

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
    `FileDispositionInfoEx`), the profile directory, and the probe job objects;
  * ⟨r3⟩ the quarantine: `mkdirat` with mode 0700 and `unlinkat` relative to a validated
    quarantine handle (Unix). On Windows: `MoveFileExW` without replace into the
    quarantine, and owner-only DACL creation. The safe wrapper exposes removal **only** as
    a method on a validated quarantine handle, so production code cannot unlink a name in
    any other directory. ⟨r4⟩ That method also takes the expected digest and re-reads the
    entry before removing it;
  * ⟨r4⟩ the birth time for `FileIdentity` (Linux `statx` with `STATX_BTIME`, macOS
    `st_birthtimespec`), unless the reviewed wrapper of P5 provides it.

  The integrator updates overview §9.
* The store moves to migration `0005_existing_access` (`SCHEMA_VERSION` 5) and gains
  `Store::open_read_only` for doctor. ⟨r2⟩ It gains tables for interaction declarations,
  per-grant prepared facts and projection consent. ⟨r3⟩ The declarations table keeps one
  row per identity with a monotonic revision. The migration adds tables only:
  `stage_receipts` and `recovery_intents` are not rewritten, and their new `local` fields
  default to absent.
* ⟨r2⟩ Existing M01 code changes in the places m02-plan U0b lists. The integrator applies
  them after the concurrent M01 work on `operations.rs` and `revocation.rs` has landed.
  ⟨r3⟩ U0b lands in two phases (m02-plan §2):
  * wave 0: every change, fail closed for the new requests, plus the store bodies;
  * wave 3: the activation change set, landed with U5's drivers.
* `docs/compatibility/matrix.md` gains rows for native agent and 1Password × {ssh, Git,
  SCP, SFTP} × {macOS, Linux, Windows}, with exact labels; M02 claims nothing unattended.
  ⟨r2⟩ It also records identity selection exclusivity as a per-configuration fact, the
  §5.9 unsupported cases, and the Git run-time limits of §8. ⟨r3⟩ It also records the
  quarantine directories, the `git_user_value_shadowed` residual, the fallback-identity
  refusal, and the Windows `ReplaceFileW` window as `[U]`. ⟨r4⟩ It also records held
  operations and their repair, birth-time support per filesystem (F25), and the limit of
  `config_tree_changed` (§6).

## 14. Reopen conditions

Reopen this ADR if any of the following happens:

* a target client contradicts F1–F3, F20 or the include-state inference (corpus test);
* Win32-OpenSSH refuses the rendered P or the `ReplaceFileW`-preserved file;
* a supported user layout needs the include somewhere other than the top;
* the owner rules differently on Q1–Q8, QR1–QR6 or ⟨r3⟩ QR7–QR11 ⟨r4⟩ or QR12–QR15;
* G05 changes how consumers bind (spec §10.3);
* M03/M04 need P to carry CertificateFile, ProxyJump or Heimdall endpoints (that is a
  revision of §2's directive set);
* ⟨r2⟩ a target filesystem in the declared layout lacks atomic exchange, or
  `ReplaceFileW` is shown not to retain the displaced file;
* ⟨r2⟩ a target Git contradicts F22 (lock protocol, include precedence, `GIT_CONFIG_COUNT`
  yielding to `-c`, or the global-file rule), ⟨r3⟩ or the `--includes`, global read order
  or conditional-include facts;
* ⟨r3⟩ a target filesystem refuses a no-replace rename into the quarantine directory, or
  a supported platform cannot validate the quarantine's owner and mode;
* ⟨r3⟩ a native test shows what `ReplaceFileW` captures under a replacement inside the
  call (§5.9 item 2);
* ⟨r4⟩ a target Git does not treat a `<file>.lock` that appeared by rename as held (F22);
* ⟨r4⟩ a target filesystem in the declared layout records no birth time, or reuses
  identities in a way that a birth time does not distinguish (F25);
* ⟨r4⟩ the generated-observation test finds a combination that the table handles with a
  forward, restore or abort action and that violates one of its properties (§5.7).

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

### 15.1 ⟨r3⟩ Change log (revision 3, task M02-T00-design-fix-2)

Source: `tests/evidence/artifacts/review-m02-design/round2.md`, rulings §12.5.

| Finding | Ruling (§12.5) | Sections changed here | m02-plan.md |
|---|---|---|---|
| M2-R01 settlement deletes the P an update must restore | item 1 | §5.3 preamble and steps 6–8 (the primitive no longer settles; settlement is a separate transaction step); §5.4 (transaction check after post-validation, `item.committed` before any settlement, crash and late-edit cases); §5.6 lock step 5; §11 row | U4 `replace` interface, `ReplaceHook` points, tests `a22_update_user_edit_after_p_post_validation_*`, `a22_update_crash_between_post_validation_and_commit_*`, `a22_update_crash_after_commit_before_settlement_*`; §5 items 15 (`StageSink::commit_item`), 17a, 18 (`commit_projection_item`) |
| M2-R02 recovery misreads interrupted restores; unlink window | item 2 | §5.3 step 7 (durable restore phases), step 8 and "The quarantine and the directory-concurrency assumption" (**option chosen: quarantine; no unlink of a name in the user's directories; assumption stated and enforced for the quarantine only**); §5.7 receipt table and the **recovery state table** (rows F0–F9c, C1–C5, R1–R5, T0–T4), one setup operation at a time; §5.8 cleaner through the quarantine with a deterministic slot; §5.9 items 1 and 4; §11 rows; §13; QR10 | U4 crash-injection and table-vector tests, quarantine enforcement tests; U5 `setup_in_progress`; §5 items 2 (`quarantine` artifact), 14, 17a |
| M2-R03 undetermined digests reuse consent | item 3 | §5.2 (determined vs undetermined states, `BehaviorState`, rule rewritten, QR2 limit); §10; §11 row | U2 `consent` interface and tests; U5 test; §5 items 2 (`undetermined_state`), 17 (`ConsentRecord`), 18 |
| M2-R04 prepared facts outlive a declaration | item 4 | §7 declaration (revision, state, decision-only source), lapse recording, "Launch eligibility is checked fresh"; results table; §8 run step 3; §10; §11 row; QR9 | U0b rows 5–6, 22 (`domain::catalog::eligibility`) and tests; U5 tests; U6 delegation; U8 pre-launch check and tests; §5 items 3, 8, 17, 18 |
| M2-R05 inherited fallback identities can prompt | item 5 | §3 item 3 (fingerprint, backing); §7 "Fallback identities on the no-interaction path", results table, identity selection paragraph; §6 authentication row; QR4 note; §11 row; QR8 | U2 report fields; U0b row 22 (`domain::catalog::fallback_clearance`); U6 delegation; U8 pre-launch check and `a11_inherited_confirm_constrained_fallback_*`; U9 A35 variant; §5 items 8, 9, 14 |
| M2-R06 authorization after the static pass | item 6 | §6 `--allow-config-commands` (always for real-tree levels, fail closed on unreadable includes, `config_tree_changed`, snapshot deferred), ladder rows, `ProbeRecord`; §5.1; §11 rows; QR11 | U3 interface and tests; U9 rules; U10; §5 items 11, 14; §8 |
| M2-R07 wave 0 not implementable | item 7 | §10 (fail-closed landing, approvals per decision kind, typed local receipt payload); §5.7 (`ProjectionApproval`, receipt payload); §7 (declaration-specific approval); §13 (U0b phases); §11 row; QR7 | U0 frozen interfaces and rescoped kind-mapping test; U0b phases, rows 1, 10, 12, 16–21 and wave-0 acceptance tests; §2 order; §5 items 4, 17, 17a, 18 |
| M2-R08 non-discriminating tests | item 8 | F22 (three added `[I]` facts), F23 (signing control), F24; §5.6 (`--includes`, static include scan, conditional entries, unreadable includes, first-read global file and the `git_user_value_shadowed` residual); §5.9 item 2 (stays `[U]`) | U3 Git observation tests; U4 Git placement tests, Windows test renamed; U6/U8 F23 control; U7 askpass `approve`/`deny`; §3 rows |
| QR3 wording | item 9 | §5.6 applicability; §12.3 QR3 text | §5 item 2 |

### 15.2 ⟨r4⟩ Change log (revision 4, task M02-T00-design-fix-3)

Source: `tests/evidence/artifacts/review-m02-design/round3.md`, rulings §12.8.

| Finding | Ruling (§12.8) | Sections changed here | m02-plan.md |
|---|---|---|---|
| M2-S01 recovery table omits reachable states | item 1 | §5.7 rewritten as a total function: observation alphabet (S/S′, V/V′, D, Q/Q′, X, ?), four action kinds, **outcome H** (nothing moved or deleted, `file.held`, operation `outcome_unknown`), the repair path (`retry`, `keep`), rows F0z, F1a, F2h, F2j, F2k, F3a–F3c, F4a–F4e, F5a, F5c, F5d, F6a, F8f, F9a, F9d, H0, C4b, C4h, **C6/C6a (create `exchanged`)**, **C7–C7b (create `restore_started`)**, C8, R1a, R2a, R6, T1h, TH; T1 and T3 corrected; the generated-observation test; §5.3 step 7 (third writer held); §5.4 partial-effect contract; §5.5 repair and uninstall; §10; §11 row; §14; QR12, QR14 | U4 `recovery::decide` and `StepObservation`, generated tests, crash tests for create `exchanged`/`restore_started`, displaced missing/replaced after post-validation, foreign active entry after a create; U5 held repair; U9 `setup repair --operation`; U0 frozen list; §5 items 2, 11, 14, 15, 17, 17a |
| M2-S02 identity-only restore and settlement lose an in-place edit | item 2 | §5.3 preamble, step 7 (pre-restore content check; QR13), step 8 (expected digest, `settle_conflict{modified}`, kept in the quarantine), quarantine enforcement; §5.4; §5.5 quarantine wording; §5.7 receipts and rows F5a, F8f, F9a, C7a, R1a, R2a; §5.8; §5.9 item 1 narrowed; §11 rows; §13; QR13 | U4 `restore`/`settle`/`remove_verified` take `Expected`; tests for an in-place edit after the forward exchange then rollback and restart, a racing edit kept in the quarantine, a write through an open descriptor, cleanup content check; §5 item 17a |
| M2-S03 F0x can claim a foreign Git lock | item 3 | F22 (lock by rename), F25 (birth time); §5.3 steps 2–3; §5.6 lock protocol (stage, `file.staged` as the ownership record, no-replace claim), "Who owns the lock name", receipts and recovery; §5.7 F0x restricted, rows G0–G3; §5.9 item 5; §11 rows; §13; §14; QR15 | U4 `projection::git` claim, `ReplaceHook` claim points, `git_foreign_lock_with_exact_target_bytes_is_never_claimed_or_removed`, `git_lock_claimed_only_after_staged_receipt`, identity birth tests; §5 item 17 (`FileIdentity.birth`) |
| M2-S04 `config_tree_changed` cannot establish completeness | item 4 | §6 "After the run" (snapshot comparison re-walking include expansion, `config_tree_differences`, list never complete) and `ProbeRecord` bullets; §10; §11 row | U3 probe interface and the new-glob-member and change-then-revert controls; U7 hook `revert`; U9 and U10 wording; §3 A21 row; §5 item 11 |
| M2-S05 writer port has no source of target bytes | item 5 | §5.3 preamble and step 3; §5.4 step 2 (intent written at admission); §5.7 `FileStep.content`/`StepContent` (what is stored, digest binding, bounds, encoding); §10; §11 rows | U0 frozen list and wire tests; U4 `projection::content`, stateless `LocalProjection`, fresh-writer and recovery-before-staging tests; §5 items 15, 17 |
| `setup_in_progress` admission | item 6 | §5.7 "Admission is atomic" (`Txn::insert_setup_operation`, order inside the transaction, the held-repair exception); §10; §11 row | U0b row 20 and the new row 23, store tests; U5 simultaneous-admission and restart tests; §5 item 18 |
