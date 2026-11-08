# ADR-0007 — Existing-access integration (M02): managed OpenSSH projection, nonexecuting discovery, existing-access adapters, and the process contract

**Status:** proposed, revision 5 · **Date:** 2026-11-01 ·
**Tasks:** M02-T00-design (revision 1), M02-T00-design-fix (revision 2),
M02-T00-design-fix-2 (revision 3), M02-T00-design-fix-3 (revision 4),
M02-T00-design-fix-4 (revision 5)
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
**Revision 5:** applies the fourth independent review
(`tests/evidence/artifacts/review-m02-design/round4.md`, findings M2-T01–M2-T06 and its
interface reconciliation list) under the orchestrator's rulings in §12.11. Text changed by
it is marked **⟨r5⟩**. §15.3 maps each finding to the sections that changed. Questions
revision 5 could not settle are in §12.12.
**Not decided here:** anything §12.3, §12.6, ⟨r4⟩ §12.9 or ⟨r5⟩ §12.12 lists as an open
question.
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
| F22 | ⟨r2⟩ Git: the precedence of F16; `GIT_SSH_COMMAND` and `core.sshCommand` run through the shell [G03-S13, G03 Q13]. Beyond that, Git's documentation is not pinned, so the following are `[I]`: the scope order (system < global < local < worktree < command) with the last value winning for a single-valued key; `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>` entries being command scope that `git -c` overrides; `[include] path`; the `<file>.lock` write protocol; which file `--global` writes; `git config --show-scope` output. ⟨r3⟩ Also `[I]`: a query scoped to one file (`--system`, `--global`) follows `include.path` only with `--includes`; `--global` reads both `$XDG_CONFIG_HOME/git/config` and `~/.gitconfig`, the XDG file first; a query run outside any repository does not follow an `includeIf` whose condition needs one (`gitdir:`, `onbranch:`). ⟨r4⟩ Also `[I]`: a `<file>.lock` that appears through a no-replace rename keeps Git writers out exactly as one Git created with an exclusive open (§5.6). ⟨r5⟩ Also `[I]`: Git never reads, and never renames, a lock it did not create, so a lock whose content is not configuration (Heimdall's lock holder K, §5.6) keeps writers out in the same way | each is settled by the Git test named where §5.6 or §8 relies on it; ⟨r3⟩ the three added facts by `git_queries_use_includes_flag_and_expand_includes`, `git_both_global_files_present_include_goes_to_first_read_file_and_later_user_values_in_either_win` and `git_value_through_conditional_include_is_counted_conditional`; ⟨r4⟩ the lock fact by `git_writer_during_heimdall_lock_fails_cleanly_nothing_lost`, which now claims the lock by rename ⟨r5⟩ with the lock holder K |
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
   the step's target digest, or nothing is written. ⟨r5⟩ (M2-T02.) The materializer takes
   the whole `FileStep`, so it checks the validated bytes against the step's base digest
   and its output against the step's target digest itself. When the base is absent (a
   first adoption with no user file, or no global Git file), the splice is applied to an
   empty input, which admits only an insert at offset 0 that removes nothing (§5.7
   "Bound to the digests"). ⟨r5⟩ (M2-T01.) B_git is staged like any other step, under
   its own random staged name, and its exchange uses the normal names of step 5. Git's
   lock is held by a separate Heimdall entry, the lock holder K, never by S or D (§5.6).
   Revision 4 claimed the lock with S itself, so the exchange then had no staged name to
   use, and on Windows the lock name would have been both the replacement and the backup.
   Revision 3 staged B_git directly at the lock name, which left a crash window with no
   receipt naming the entry (M2-S03).
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
   * ⟨r5⟩ The B_git step uses these same names: its staged name, and on Windows its own
     displaced name. Git's lock name is never an argument of the exchange; K occupies it
     throughout (§5.6 "Name transitions").
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
   unexchanged S. ⟨r5⟩ The Git lock holder K is settled the same way, from the lock name,
   after every other entry of the Git item (§5.6).
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
Heimdall takes the lock only through an entry that a receipt already names.

⟨r5⟩ (M2-T01; §12.11 item 1.) That entry is the **lock holder K**: a small Heimdall file
whose only job is to occupy the lock name. It is a step of its own in the intent (role
`git_lock`, §5.7), separate from B_git's S and D. Revision 4 claimed the lock with S itself.
The exchange then had no staged name to take S from, and on Windows `ReplaceFileW` would
have had to use the lock name as both its replacement and its backup (M2-T01).

1. ⟨r5⟩ **Stage K, then claim.** Heimdall creates K at the lock step's random staged name
   (128 bits, fixed in the intent) with `O_CREAT|O_EXCL|O_NOFOLLOW` and mode 0600 (Windows:
   an owner-only DACL). It writes the holder bytes from the intent, fsyncs, and writes
   `file.staged` with K's identity. The holder bytes are one line, `heimdall setup lock,
   generation <N>, <32 hex>`, whose hex part is 128 random bits fixed at admission.
   **That receipt is the ownership record.** It is durable before the lock name exists,
   and its token is K's file identity, which no content can imitate (F25: device, inode
   and birth time on Unix, the 128-bit file ID on Windows). Heimdall then claims the lock
   by renaming K onto `<global file>.lock` with no-replace (Linux `RENAME_NOREPLACE`,
   macOS `RENAME_EXCL`, Windows `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`). The
   lock name appears atomically, and only if it was absent, which is what Git's exclusive
   create guarantees (F22 `[I]`). `EEXIST` gives `CONFIG_CONFLICT` with reason
   `git_config_locked`. Nothing is written to the global file, and K is settled from its
   staged name.
   * K's random line is **not** a proof of ownership (§11): ownership is K's identity.
     The line only gives every discard of K (§5.3 step 8) an expected digest that no Git
     writer's lock has, so a discard can never remove another writer's lock, even where
     identities have no birth time. Git never reads or renames a lock it did not create,
     so K's content never becomes Git configuration (F22 `[I]`).
   * Revision 3 created the lock name directly with exclusive create. A crash before
     `file.staged` then left an entry at the lock name that no receipt named, and
     recovery row F0x could delete another writer's lock after checking only its content
     (M2-S03).
2. Under the lock, B_git is staged at its own random staged name (§5.3 step 3,
   `file.staged` with S). The global file is revalidated against the plan's base (§5.3
   steps 2 and 4, `file.validated`), or found absent.
3. It checks that the new bytes parse: `git config --file <B_git's staged name>
   --no-includes --list` (a local query). ⟨r5⟩ Revision 4 ran this on the lock name, which
   then held S.
4. It exchanges with the ordinary names of §5.3 step 5. On Unix the exchange swaps B_git's
   staged name and the path, so D lands at the staged name. On Windows it is
   `ReplaceFileW(path, staged name, backup = .<name>.hm-displaced-<generation>)`. When the
   global file is absent it is a no-replace rename of the staged name onto the path. ⟨r5⟩
   **K stays at the lock name throughout**, which keeps Git writers out until settlement
   ends.
5. ⟨r3⟩ The Git item's transaction check follows: P_git still has its staged identity and
   target digest. Then comes `item.committed` for the item. Only after that does
   settlement (§5.3 step 8) move D into the quarantine (M2-R01). ⟨r5⟩ Then K is settled
   from the lock name into the quarantine, which releases Git's lock. A restore and an
   abort end the same way: S is settled first, then K. K is always the Git item's last
   settled entry, and `item.finished` follows it.

⟨r4⟩ **Who owns the lock name.** ⟨r5⟩ An entry at the lock name is Heimdall's only when it
has K's identity, which the lock step's `file.staged` recorded **before** K could be at the
lock name. B_git's S and D are never at the lock name. Revision 4 also counted S and D there.

Anything else is foreign, whatever its content, and is never moved or removed. That includes
an entry with equal bytes and another identity, and any entry when no receipt for the step
exists. **At recovery**, on a Unix filesystem that records no birth time (F25), a (device,
inode) pair at the lock name does not prove ownership. While Heimdall was down, the user may
have removed its lock (Git's error message suggests it), and Git may have created a new one
on the freed inode. There recovery observes every entry at the lock name as X (QR15). Within
one run this does not arise: the live path holds the lock from claim to release, and K's
identity ⟨r5⟩ and holder digest are checked at each step. Heimdall never deletes a lock.
Releasing it means moving K into the quarantine (§5.3 step 8).

During that interval, Git commands that write configuration fail with Git's own lock error,
and nothing is lost. Editors that ignore the lock are covered by §5.3 step 7 and §5.9.

⟨r5⟩ **Name transitions** (M2-T01; §12.11 item 1). The tables state which name holds which
entry after each transition. N_s is B_git's random staged name, and N_d its Windows displaced
name `.<name>.hm-displaced-<generation>`. N_k is K's random staged name, and "lock" is
`<global file>.lock`. On Unix, D lands at N_s, which is therefore also B_git's displaced name
(§5.7). ∅ is no entry, and V the validated global file. Where Unix and Windows differ, a
cell reads "Unix / Windows", and "—" marks a name that platform does not use. Each receipt
is written after its transition and before the next one.

*Replace* (the global file exists):

| # | Transition | Receipt | path | N_s | N_d (Windows) | lock | N_k |
|---|---|---|---|---|---|---|---|
| 0 | start | — | V | ∅ | ∅ | ∅ | ∅ |
| 1 | create K at N_k, write the holder bytes, fsync | K: `file.staged{K}` | V | ∅ | ∅ | ∅ | K |
| 2 | claim: no-replace rename N_k → lock | — | V | ∅ | ∅ | K | ∅ |
| 3 | stage S at N_s | B_git: `file.staged{S}` | V | S | ∅ | K | ∅ |
| 4 | revalidate and recheck the global file; parse-check N_s | B_git: `file.validated{V}` | V | S | ∅ | K | ∅ |
| 5U | Unix: exchange N_s ↔ path | B_git: `file.exchanged` | S | D | — | K | ∅ |
| 5W | Windows: `ReplaceFileW(path, N_s, backup = N_d)` | B_git: `file.exchanged` | S | ∅ | D | K | ∅ |
| 6 | post-validate | B_git: `file.post_validated` | S | D / ∅ | — / D | K | ∅ |
| 7 | the Git item's check passes | `item.committed` | S | D / ∅ | — / D | K | ∅ |
| 8 | settle D (Unix from N_s, Windows from N_d) | B_git: `file.settling`, `file.settled` | S | ∅ | ∅ | K | ∅ |
| 9 | release: settle K from the lock | K: `file.settling{source: path}`, `file.settled` | S | ∅ | ∅ | ∅ | ∅ |
| 10 | — | `item.finished{applied}` | S | ∅ | ∅ | ∅ | ∅ |

*Restore* (after 6 on a mismatch, or after `item.rolling_back`):

| # | Transition | Receipt | path | N_s | N_d (Windows) | lock |
|---|---|---|---|---|---|---|
| R1 | check that the path is S with the target digest (§5.3 step 7) | B_git: `file.restore_started` | S | D / ∅ | — / D | K |
| R2U | Unix: exchange N_s ↔ path | B_git: `file.restored` | D | S | — | K |
| R2W | Windows: `ReplaceFileW(path, N_d, backup = N_s)` | B_git: `file.restored` | D | S | ∅ | K |
| R3 | settle S from N_s | B_git: `file.settling`, `file.settled` | D | ∅ | ∅ | K |
| R4 | release K | K: `file.settling{source: path}`, `file.settled` | D | ∅ | ∅ | ∅ |
| R5 | — | `item.finished{restored}` | D | ∅ | ∅ | ∅ |

*Abort* (before 5): S is settled from N_s if it was staged. K is then settled from the lock,
or from N_k if it was never claimed. `item.finished{not_applied}` follows.

*Create* (no global file exists; the same on Unix and Windows):

| # | Transition | Receipt | path | N_s | lock | N_k |
|---|---|---|---|---|---|---|
| 1–3 | as for a replace | as for a replace | ∅ | S | K | ∅ |
| 4 | check that the path is absent; parse-check N_s | B_git: `file.validated{absent}` | ∅ | S | K | ∅ |
| 5 | no-replace rename N_s → path (Linux `RENAME_NOREPLACE`, macOS `RENAME_EXCL`, Windows `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`) | B_git: `file.exchanged` | S | ∅ | K | ∅ |
| 6–7 | post-validate; the check passes | `file.post_validated`, `item.committed` | S | ∅ | K | ∅ |
| 8 | nothing is displaced | B_git: `file.settled{nothing_displaced}` | S | ∅ | K | ∅ |
| 9–10 | release K; finish | K: `file.settling`, `file.settled`; `item.finished{applied}` | S | ∅ | ∅ | ∅ |

A create's restore settles the path's S, which must have the target digest, into the
quarantine (`file.restore_started`, `file.settling{source: path}`, `file.settled`,
`file.restored`), and then releases K. **The lock stays occupied after a create's commit
point**, because S leaves N_s, never the lock name. Revision 4 would have released Git's
lock at the create itself.

Since K is the only Heimdall entry ever at the lock name, the B_git step recovers by the
ordinary replace and create rows of §5.7, with its ordinary aside names. Only the lock
step has rows of its own (K0–K4, §5.7).

**Crash vectors.** Each transition above gets two process crashes, one before its receipt
and one after it. Each runs on Unix and on Windows, for a replace and for a create
(m02-plan U4 `git_name_transitions_crash_at_every_point_reconciles`). Each vector states
the rows that apply and the outcome:

| Crash | Rows | Outcome after restart |
|---|---|---|
| after 1, before or after `file.staged{K}` | K0x, then K1 | T0 resumes and claims → `applied`. With a lock created by another writer while Heimdall was down, the claim gets `EEXIST`: abort, `git_config_locked`, K settled from N_k, the other lock untouched |
| after 2, before 3 | K2 | T0 resumes → `applied` |
| after 3 or 4 | B_git F0x/F1/F2a or C1; K2 | T0 resumes (the path is revalidated) → `applied` |
| after 5, before `file.exchanged` | B_git F2b or C2; K2 | the exchange is recognized; continue → `applied` |
| after 6 | B_git F4 or C5; T1 | the check is re-run: `applied`, or a restore → `restored` |
| after 7 | T2; F4d or C5b; K2 | D settled, K released → `applied` |
| inside 8 or 9 | the settlement rows F8–F9d, on B_git or on the lock step | settlement completes; K released → `applied` |
| after R1, or after R2 before `file.restored` | F5 or C7; F5b | restore done or recognized → `restored` |
| inside R3 or R4 | the settlement rows | completes → `restored` |

Each vector also runs on Unix **without a birth time** (a test-only identity source). After
any crash from 2 on, K at the lock is observed as X (K4). It is never moved or removed, and
doctor reports `git_config_lock_held` for the owner. The B_git step finishes what its own
rows allow. Before 5 the item aborts (`not_applied`), because T0 resumes only under a lock
it can prove is Heimdall's. From 5 on it ends `applied` or `restored` as above, with the
lock step ending `settle_conflict{foreign}` and the lock left in place.

**Effective selection.** The plan carries `effective_before` and `effective_after`
(`GitSshSelection`, §10), computed from the system and global scopes. A repository's own
value, or an environment override, still wins at run time (§8).

**Receipts and recovery.**

* P_git and B_git are file steps of the same `SetupIntent` (§5.7), placed after the SSH
  commit point, with resources `ConfigProjection` in the roles `git_managed` and
  `git_include`.
* ⟨r5⟩ The lock holder K is a third file step of the Git item, role `git_lock`, placed
  before B_git (§5.7). It has no resource and never outlives the operation.
* **Crash with the lock name occupied.** ⟨r3⟩ Recovery follows the §5.7 table. ⟨r5⟩ B_git
  recovers by the ordinary replace or create rows, with its own staged name and, on
  Windows, its own displaced name. The lock step recovers by rows K0–K4. An entry at the
  lock name that the ownership rule above does not make Heimdall's is never moved or
  removed, whatever its content. The Git item is then `not_applied` with
  `git_config_locked`, or ends as its B_git rows say, or is held. Revision 4 used the lock
  name as B_git's displaced name (rows G0–G3, withdrawn).

  Doctor reports `git_config_lock_held`, with the path, for as long as that state lasts.
  ⟨r4⟩ The finding also says whether a receipt makes the lock Heimdall's. When none does,
  the remedy is Git's own: remove the lock once no Git process is running. Heimdall never
  does that itself.

**Rollback** removes B_git under the lock, only when its bytes equal the recorded block (else
`marker_edited`), and then P_git through the cleaner. ⟨r5⟩ It holds the lock through K and
follows the replace transitions above, with a splice that removes B_git. A value the user
added later survives byte-for-byte. ⟨§12.39, §12.41⟩ When that value is read after B_git,
it already wins, so removing B_git changes no effective selection and §5.2 needs no decision.
When Heimdall's value is the effective one (the user's value is shadowed, for example in an
XDG file created after the apply), or when the winner cannot be established, the rollback
changes Git's effective value and needs a decision. The rollback removes B_git from the file
its step wrote (`ItemRecord.include_file`, §12.37 item 3).

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
  role: user_ssh | managed_ssh | key(fp) | git_include | git_managed
        | git_lock,                                                  ⟨r5⟩
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
  | LockHolder { bytes }              // ⟨r5⟩ K, the git_lock step (§5.6)
```

⟨r3⟩ `approval` is the projection-specific approval, distinct from the declaration
approval (§10; §12.5 item 7). The staged and displaced names are fixed in the intent
before anything is written. On Unix the displaced name is the staged name, because the
exchange leaves D there. On Windows it is `.<name>.hm-displaced-<generation>`. ⟨r5⟩ This
holds for B_git too (M2-T01): its staged name is random, and its displaced name is
whichever of these its platform uses. Revision 4 made the lock name B_git's displaced
name, which on Windows was also where S had been claimed.

⟨r5⟩ **The `git_lock` step** (§5.6). Its path is `<global file>.lock`, its base and target
are `Absent`, `commit` is false, and its `content` is `LockHolder`. Its staged name is
random, and it has no displaced name. Its holder bytes, like the staged names, are fixed at
admission and are not part of `plan_digest`. `SetupIntent::validate` accepts a
`LockHolder` only in this exact form: one line, `heimdall setup lock, generation <N>,
<32 lowercase hex>`, with N the intent's generation. It allows exactly one `git_lock`
step, only when the plan has a `git_include` step, and only directly before it. The step
is in no resource and no `ProjectionSummary.files`. The preview names the lock it will
hold.

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
* ⟨r5⟩ **The materializer checks both digests itself** (M2-T02; §12.11 item 2). It takes
  the whole `FileStep`, not only its content, together with the bytes §5.3 step 2
  validated, or none when the base is absent:
  1. **Base.** A `Present` base needs bytes whose SHA-256 is `base.sha256`; otherwise the
     result is `CONFIG_CONFLICT` (`user_config_changed` or `managed_file_edited`), as in
     §5.3 step 2. An `Absent` base needs no bytes, and bytes given for it are refused.
  2. **An absent base is an empty splice input.** A splice over an absent base is applied
     to the empty byte string. Only an insert-only range is valid there: `offset` 0,
     `remove_len` 0, no `removed_sha256`, and a non-empty `insert`. This is the first
     adoption with no user SSH configuration, and B_git in a new global Git file.
  3. **Checked range arithmetic.** `offset` and `remove_len` are converted from `u64`
     with checked conversions. `offset + remove_len` is a checked addition, and the
     result must not exceed the input's length. `removed_sha256` is present exactly when
     `remove_len > 0` and must equal the removed range's SHA-256. The output length is
     computed with checked arithmetic and must stay within the bounds below. Any failure
     is `IntentInvalid`, and nothing is written.
  4. **Target.** The output's SHA-256 must equal `target.sha256`. A step whose target is
     `Absent` has nothing to materialize; the cleaner removes it (§5.8). The `git_lock`
     step's `LockHolder` is the exception: its bytes are written as they are, after the
     format check above.

  `SetupIntent::validate` runs every check that needs no base bytes when the intent is
  built and again when it is read: the variant matches the role, and an absent base
  carries only an insert-only splice.
* **Bounded.** A whole target is at most 256 KiB (P), 16 KiB (a key file) or 4 KiB
  (P_git). A splice inserts at most 4 KiB. ⟨r5⟩ A lock holder is at most 128 bytes. One
  intent holds at most 256 key files and 1 MiB of content in total. A plan beyond any bound is refused at preview with
  `CAPABILITY_UNAVAILABLE`, reason `projection_too_large`, and nothing is admitted.
* **Encoding.** Bytes are base64 (RFC 4648 §4, padded) on the wire, so a BOM and CRLF
  line endings survive exactly.

**Receipts** ⟨r3⟩ (§12.5 items 2 and 7). Each receipt is an M01 `StageReceipt` that
carries the typed payload `local` (m02-plan §5 item 17a). It is appended in its own store
transaction before the next step begins:

| Receipt | Written | Records |
|---|---|---|
| `file.staged` | after S was created and fsync'd; ⟨r5⟩ for the `git_lock` step, after K was created and fsync'd and before the lock name is claimed, which makes it the lock's ownership record (§5.6) | S's identity (K's for the `git_lock` step) |
| `file.validated` | after the boundary recheck, **before** the exchange | V, or `absent` |
| `file.exchanged` | after the exchange, or the no-replace create, returned | — |
| `file.post_validated` | after post-validation | `valid`; or `mismatch` with the identity observed at the displaced name |
| `file.restore_started` | before a restore exchange, ⟨r4⟩ after the check that the path still holds S with the target digest | cause: `file_mismatch` or `transaction_check` |
| `file.restored` | after the restore exchange, both identities verified; ⟨r4⟩ for a create, after the path entry's settlement | — |
| ⟨r4⟩ `file.held` | when the step reaches outcome H; again only when a later observation differs, and at most 16 times per step | the reason, and what each observed name held (∅, S, S′, V, V′, D, X or ?), by identity, never content. Replaces revision 3's `file.restore_conflict`. ⟨r5⟩ A record for the owner and for the repair preview only: recovery never reads it as a phase (`RecoveryState`, below) |
| `file.settling` | before the move into the quarantine | source (`displaced`, `staged` or `path`) ⟨r4⟩ and its name, expected identity, ⟨r4⟩ expected digest, quarantine name. ⟨r5⟩ K's release has source `path`, the lock name |
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
`reconcile(intent, receipts)` evaluates, for each file step, ⟨r5⟩
`decide(shape, recovery state, observation) -> action` over its whole domain:

* the step's **shape**: replace (base present, target present), create (base absent),
  ⟨r5⟩ the Git lock holder (the `git_lock` step, §5.6), or removal (target absent; the
  cleaner's). Revision 4's "B_git claim" shape is withdrawn: B_git is a replace or a
  create;
* ⟨r5⟩ its **recovery state** (`RecoveryState`, below), built from the receipt history.
  Revision 4 passed the last durable receipt, which after a `held` receipt no longer
  showed the phase the step was in (M2-T04);
* the **observation**, by identity ⟨r4⟩ and content, of three entries:
  * the *path*;
  * the *aside* name, which holds the step's other entry. Before the exchange and after
    a restore this is the staged name; after the exchange it is the displaced name. On
    Unix the two names are the same. On Windows recovery looks at both names, and both
    holding an entry is observed as X. ⟨r5⟩ For the `git_lock` step, the path is the lock
    name and the aside is K's staged name;
  * the quarantine *slot* named by `file.settling`.

⟨r5⟩ **The recovery state** (M2-T04; §12.11 item 4). `RecoveryState::build(step, receipts)`
is pure. It reads the step's own receipts and its item's receipts and returns:

* `phase`: the step's **effective phase**. That is its last receipt once every
  `file.held` receipt has been removed, or `none`. **`held` is never an effective phase**,
  so a held step is decided exactly as it would have been before it was held;
* `restore`: `not_due`; `due(cause)`, after `post_validated{mismatch}` (cause
  `file_mismatch`) or after `post_validated{valid}` with `item.rolling_back` (cause
  `transaction_check`); `started(cause)`, after `file.restore_started`; or `done`, after
  `file.restored`;
* `settlement`: for an open `file.settling`, its source (`displaced`, `staged` or `path`),
  and whether it is part of a create's restore, after which `file.restored` follows;
* `item`: the item state, open, `item.committed`, `item.rolling_back` or `item.finished`;
* for the `git_lock` step only, `release_due`: whether every other step of the Git item is
  final, meaning its rows have nothing left to do. That is `settled`, `settle_conflict`, a
  create's `restored`, handed to the cleaner, or never staged in an aborted item. K is
  released only then. Until then K2 decides `Forward(KeepLock)`, which has no effect.

The builder checks the history against the step's phase order (staged → validated →
exchanged → post_validated → restore_started → restored, and settling → settled or
settle_conflict; a create's restore runs its settlement before `restored`; a
`settle_conflict` may also follow a phase directly when nothing is left to settle, as in
rows F4e, F6a, K3 and K4). A history
that breaks the order is refused: an `exchanged` without `validated`, a `settled` without
`settling`, a phase after a final one, or both `item.committed` and `item.rolling_back`. The
step is then H with reason `contradictory_receipts`, and nothing is inferred. Revision 4's
row H0, "decide from the receipt before `held`", is withdrawn: the builder does that for
every step. The rows below name the effective phase in their "Phase" column.

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

⟨r5⟩ For the `git_lock` step, S and S′ are K and K′: K's identity with, or without, the
holder digest. At recovery on a Unix filesystem without birth time, the lock name is X
whatever it holds (§5.6, QR15).

⟨r5⟩ **Normalization** (M2-T05; §12.11 item 5). The symbols classify one observation; they
are not independent identities. `StepObservation` is therefore built only by one
normalizing constructor, which `observe_step` calls and the generated tests call too:

1. **Not Heimdall's shape.** An entry that is not a regular file, is owned by another
   user, or has a link count above 1 is X, whatever its identity.
2. **Role precedence.** Otherwise its identity is compared with the recorded identities in
   this order, and the first match names it:
   * Q, but only at the open settlement's source name and at its slot;
   * S;
   * D, only after `post_validated{mismatch}`, and only when that identity is neither S
     nor V. A mismatch that recorded V's own identity is observed as V′ or V;
   * V, only for a step whose base was present.

   The content part (S or S′, and so on) compares against that identity's expected digest:
   the target for S, the base for V, the recorded digest for Q. D has no content part.
3. **Impossible combinations are rejected** before enumeration and by the constructor:
   * one recorded identity at two names. A file with link count 1 has one name, and with
     a higher link count it is X at both;
   * Q at a name other than the settlement's source or slot;
   * D without a recorded mismatch, and V for a step whose base was absent;
   * an entry in a slot when no `file.settling` names one;
   * a `git_lock`-only state (`release_due`) on another shape.

   The generated tests count the rejected cells, and the filesystem-backed test builds
   each rejected identity combination it can (a hard link, for example) to show that the
   observation normalizes it as stated.

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
* **Every restart re-observes** the step from its ⟨r5⟩ `RecoveryState`, which ignores
  `held` receipts. If a row now gives a forward, restore or abort action, recovery
  continues with it. Otherwise nothing changes.
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
  * `unmatched`: no row lists the combination;
  * ⟨r5⟩ `contradictory_receipts`: the history breaks the phase order (above), or the
    item's receipts contradict each other (row TH).

**Repair path for a held operation** ⟨r4⟩. `setup status` and the doctor finding
`projection_held` list each held step:

* its role and path, and the reason;
* what each observed name holds: Heimdall's S, D or V, or a foreign entry, and whether the
  content matches.

⟨r5⟩ **Held previews carry content fingerprints** (M2-T03; §12.11 item 3). Recovery's
classification (S or S′, X) cannot show *which* content an entry holds. So the preview
of a repair binds, besides it, a **fingerprint** of every observed name:

* `absent`; `unobservable`; or `present` with the entry's identity, file type, owner (the
  user or not), link count, length, change time (Unix `st_ctime` in nanoseconds; Windows
  `ChangeTime`), and either the SHA-256 of its content or the marker `unreadable` when the
  content cannot be read within 1 MiB or the read fails;
* on Windows both aside names, and the slot when one is named.

The repair's `plan_digest` covers the canonical fingerprints of every held step. Two
successive in-place edits of S therefore give two digests; two different foreign
replacements give two identities or two digests; and an oversized entry changes its length
or change time when it is rewritten. Fingerprints hold digests and metadata only. Bytes
are never written to a receipt, a plan, a result or a log. Recovery itself still decides
from the classification alone, and `file.held` keeps its identity-only payload.

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

Both resolutions are previewed, and their plan digest binds the observed entries ⟨r5⟩ by
their fingerprints, so a change between preview and repair makes the repair stale, even
one that leaves the classification unchanged. `keep` changes no file, and
`retry` adds nothing the held operation was not approved for. Neither needs a new decision
under §5.2 (QR12).

*Replace step* (base present, target present). Within each phase's block the rows are
tried in order. A `*` matches any symbol except `?`. ⟨r5⟩ "Phase" is the effective phase of
`RecoveryState`, never `held`.

| Row | Phase (item state) | Path | Aside | Action |
|---|---|---|---|---|
| F0 | none | * | ∅ | Not staged. T0 |
| F0x | none | * | a regular file owned by the user, link count 1 | A crash between the exclusive create and `file.staged`. ⟨r4⟩ The evidence is the name, which is 128 random bits fixed in the intent, not the content. Write `file.staged` with its identity, then F1. Settlement checks the content, so a partly written file is kept and reported (§5.3 step 8.4). **Never used for the Git lock name** (⟨r5⟩ K0x applies it to K's random staged name only) |
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
| F5 | restore due ⟨r4⟩: `restore_started`, `post_validated{mismatch}`, or `post_validated{valid}` with `item.rolling_back` | S | D | Write `file.restore_started`, unless it is ⟨r5⟩ already the effective phase. Do the restore exchange, verify both identities, and write `file.restored` |
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

| Row | Phase | Source | Slot | Action |
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

For a create restore (`file.settling{source: path}`), the block's end is followed by
`file.restored`. ⟨r5⟩ Revision 4's row H0 (`held`: decide from the receipt before it) is
withdrawn, because `held` is never an effective phase (`RecoveryState`).

*Create step* (base absent). Nothing is displaced, so the aside name is the staged name.
Rows F0–F1a and the settlement block apply unchanged, and:

| Row | Phase (item state) | Path | Aside | Action |
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
| C7 ⟨r4⟩ | restore due: `restore_started`, or `post_validated{valid}` with `item.rolling_back` | S | * | Write `file.restore_started`, unless it is ⟨r5⟩ already the effective phase. Settle the path entry through the quarantine (`file.settling{source: path}`, then the settlement block, then `file.restored`) |
| C7a ⟨r4⟩ | restore due | S′ | * | The created file was edited after the create. Removing it would hide the edit: **H** (`active_entry_modified`; QR13) |
| C7b ⟨r4⟩ | restore due | any other | | **H** (`active_entry_replaced`) |
| C8 ⟨r4⟩ | `restored` | * | * | Done. The path's later state is only reported |

*The Git lock holder* ⟨r5⟩ (the `git_lock` step, §5.6; M2-T01). These rows replace revision
4's G0–G3 and are the only rows that look at the lock name. "Lock" is `<global
file>.lock`, the step's path; "staged" is K's random staged name, its aside. K is the
identity the step's `file.staged` recorded. "Provable" means: on Windows always, and on
Unix only when K's identity has a birth time (F25, QR15); otherwise K at the lock is X.

| Row | Phase | Staged | Lock | Action |
|---|---|---|---|---|
| K0 | none | ∅ | * | Not staged. T0 resume stages K and claims; abort has nothing to settle. An entry at the lock is foreign: never moved, reported `git_config_locked` |
| K0x | none | a regular file owned by the user, link count 1 | * | A crash between K's exclusive create and `file.staged`. The evidence is the random name, as for F0x. Write `file.staged` with its identity, then K1. Never applied to the lock name |
| K0z | none | X | * | A foreign entry at Heimdall's staged name: left in place and reported. Abort |
| K1 | `staged` | K, K′ | * | Not claimed. Release not due: T0 resume claims with K if it is unchanged (K′ cannot be continued: abort). A foreign entry at the lock makes the claim fail with `EEXIST`: abort, `git_config_locked`, the entry untouched. Release due: settle K from the staged name |
| K2 | `staged` | ∅, X | K, K′ (provable) | Claimed. Release not due: nothing moves; the lock stays held while the B_git step proceeds by its rows. Release due: settle K from the lock, which releases it. A K′ stays in the quarantine as a conflict artifact (§5.3 step 8.4). An X at the staged name is left in place and reported |
| K3 | `staged` | ∅, X | ∅ | K is gone. Write `file.settle_conflict{missing}`. If the Git item's commit step was never exchanged, abort (`concurrent_writer`). Otherwise the B_git step continues by its rows without the lock: restores and settlements check identity and content and need no lock, and T0 never resumes |
| K4 | `staged` | ∅, X | X (including K that is not provable) | The lock is not provably Heimdall's: never moved or removed. Write `file.settle_conflict{foreign}` naming it, and report `git_config_lock_held`. If the commit step was never exchanged, abort; otherwise as K3 |

Once K's `file.settling` is written, the settlement rows (F8–F9d) apply to it, with the
lock name, or the staged name before a claim, as the source. The Git item's B_git step
always uses the ordinary replace or create rows (§5.6 "Name transitions").

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
| T0 | The commit step was never exchanged (its row says so) | Nothing of the item is active. Resume forward under the same plan, ⟨r4⟩ with the bytes from the intent, only when every precondition still holds (§5.4 step 3). ⟨r4⟩ Resuming continues each step from its current phase. A step with no receipt is staged. A step at `staged` or `validated` keeps its S, which must still be unchanged: its path is revalidated (§5.3 step 2), and it continues at step 4. An S that is modified or gone cannot be continued, so the item aborts. A staged name is therefore never reused, and no entry appears at it without a receipt naming it. ⟨r5⟩ For the Git item, T0 resumes only under a lock Heimdall can prove it holds: the `git_lock` step is at K1, and its claim succeeds, or at K2. At K3 or K4 the item aborts. Otherwise abort: settle the staged files, hand the inactive files to the cleaner, and write `item.finished{not_applied}`. The result is `CONFIG_CONFLICT` with effect `none` |
| T1 | The commit step is at `post_validated{valid}`, with no `item.committed` and no `item.rolling_back`, ⟨r4⟩ and every exchanged step of the item observes path S or S′ and, for a replace step, aside V | The crash fell between post-validation and the outcome record (M2-R01). **Re-run the item's transaction check now** (§5.4). If it passes, write `item.committed`, then settle. If it fails, write `item.rolling_back` and restore (F5, C7). ⟨r4⟩ The restore proceeds only where F5 or C7 allows it; otherwise the step is H. Revision 3 called the restore "always possible", which a vanished D refutes (M2-S01) |
| T1h ⟨r4⟩ | As T1, but an exchanged step observes anything else | **H**. The transaction check is not run |
| T2 | `item.committed` | Finish forward: the item's remaining steps, then every settlement (F4d, F4e, C5b), ⟨r5⟩ then, for the Git item, the release of K (K2), last. Never restore. Write `item.finished{applied}` |
| T3 | `item.rolling_back`, ⟨r4⟩ or the commit step's file-level restore (`restore_started{file_mismatch}`) | Finish the restore of every exchanged step (F5–F6, C7), settle S, ⟨r5⟩ release K for the Git item, hand the inactive files to the cleaner, and write `item.finished{restored}`. ⟨r4⟩ A step that reaches H holds the item. Revision 3's `item.finished{conflict_preserved}` here is withdrawn |
| T4 | `item.finished` for every item | Settle the operation with the recorded outcomes |
| TH ⟨r4⟩ | A step of the item is at H, or the item's receipts contradict each other (for example both `item.committed` and `item.rolling_back`) | **H** for the item, and so for the operation. ⟨r5⟩ Contradicting receipts give the reason `contradictory_receipts` |

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

* ⟨r5⟩ every shape and every `RecoveryState` that `RecoveryState::build` returns for a
  generated receipt history. The histories are every phase sequence of each shape up to
  its full length, with every item receipt combination, and with `held` receipts inserted
  at every position. Revision 4 enumerated "every last receipt, `held` included", which
  made `held` an input (M2-T04). The inserted `held` receipts must leave the built state
  unchanged, and a contradictory history must build to `contradictory_receipts`;
* observations that no row names, and ones that need a hard link, a non-regular file or an
  unreadable directory to construct, ⟨r5⟩ all through the normalizing constructor. The
  impossible combinations it rejects are counted, never silently dropped.

A filesystem-backed run, `recovery_generated_observations_preserve_every_entry`, builds
each generated combination in a scratch directory and runs `reconcile`. It then repeats
the run with a crash injected after each write that `reconcile` makes. Both tests check
only properties that every correct table has.

⟨r5⟩ **The properties are stated over concrete effects** (M2-T05; §12.11 item 5). Every
action is a sequence of these effects, and the tests read the sequence, not the action's
name:

* `receipt(phase)`, which writes a receipt and moves nothing;
* `forward_exchange(path, aside)` and `forward_create(aside → path)`, the commit-point moves
  of §5.3 step 5;
* `restore_exchange(path, aside)` (§5.3 step 7);
* `claim(staged → lock)`, K's no-replace rename (§5.6);
* `move_to_slot(name → slot)`, a no-replace rename into the quarantine;
* `remove_from_slot(slot)`, the only removal;
* `put_back(slot → name)` and `keep_as_conflict(name → *.hm-conflict-*)`, both no-replace.

The properties:

1. **Totality:** exactly one action, and no panic or error other than H.
2. **No loss.** Every entry present before is present after, with its identity and bytes,
   at a name the result reports. The only exception is an entry removed by
   `remove_from_slot`, and only under one of two ownership rules:
   * **a setup step:** a durable `file.settled` for that slot precedes the removal, and
     at removal the entry has the identity and digest of that step's `file.settling`;
   * **the cleaner** (removal shape, rows R1 and R2): the entry has the identity and
     digest of its `ProjectionLocator`, and the resource's generation is the one being
     cleaned (§5.8). The cleaner writes no stage receipt; its locator is its durable
     ownership record. Revision 4 required a `file.settled` here, which a correct cleaner
     never writes.
3. **Foreign and modified content is preserved.** An X moves only by `put_back` or
   `keep_as_conflict`. An S′, V′, Q′, K′ or L′ is never the subject of `remove_from_slot`.
   A `move_to_slot` of such an entry leaves it in the slot as a reported conflict
   artifact.
4. **Performing a restore differs from recognizing one.** A `restore_exchange` is decided
   only when the restore is due or started, the path is S with the target digest, and the
   aside is D (V, V′ or the recorded mismatch identity). When the restore exchange has
   already happened (rows F5b and F5c: phase `restore_started`, the path D or X, the aside
   S or S′), the action only writes `receipt(restored)` and moves nothing. Revision 4
   allowed `Restore` only with S at the path, which the recognition rows break.
5. **The path changes only through the plan**, by exactly one of:
   * `forward_exchange` or `forward_create`, from a phase before `exchanged`, under T0 or
     T1;
   * `restore_exchange`, under property 4;
   * a **create rollback**: `move_to_slot(path)` of a create step whose path is S with the
     target digest, with the restore due or started (rows C7 and F8a). An S′ there is H
     (C7a). Revision 4 omitted this case;
   * the cleaner's `move_to_slot(path)` under its locator rule (row R1);
   * `claim`, for the `git_lock` step, whose path is the lock name: only from K1, with the
     lock name absent;
   * K's release, `move_to_slot(lock)` of a provable K or K′, only from K2 with the release
     due. A K′ stays in the slot (property 3).
6. **H performs no effect** except a `file.held` receipt when the observation changed, and
   it leaves the operation `outcome_unknown`.
7. **Outcomes match receipts:** `applied` only with `item.committed`; `restored` only
   with `file.restored` for every exchanged step; `not_applied` only when the commit step
   was never exchanged.
8. **Idempotence:** a second `reconcile` moves nothing more and writes nothing for an
   unchanged H.

⟨r5⟩ **Negative controls.** The assertions are not weakened to fit the table. The generated
domain includes, for every shape, cells with modified content (S′ at the path with a
restore due, V′ or Q′ in a settlement, L′ for the cleaner) and with foreign entries at
every name. Property 3 checks each of them. `recovery_properties_catch_seeded_faults`
runs the property checker against deliberately wrong variants of `decide`, and each must
fail at least one property: a restore over S′; a removal of a V′ or Q′; a removal by the
cleaner of an L′; an X moved anywhere but back; a forward exchange after
`item.rolling_back`; a create rollback of an S′; a second restore exchange where F5b
recognizes one.

m02-plan U4 test `recovery_table_rows_each_have_a_test_vector` keeps the other direction:
every row above has a vector, ⟨r4⟩ and the vector's action is the row's. ⟨r5⟩ The row IDs
are F0–F9d, C1–C8, K0–K4, R1–R6 and T0–TH; G0–G3 and H0 are withdrawn.

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
     as Heimdall's without a birth time (§5.6). ⟨r5⟩ Only K is ever there, and K's
     expected digest covers a random line that no other writer's lock contains, so even
     within one run no discard can remove another writer's lock.

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
* ⟨r5⟩ **Every call is bounded** (M2-T06; ADR-0006 §13.20 item 3; §12.11 item 6). These are
  the first real adapters, so the runtime bounds every `prepare`, `reconcile` and `revoke`
  call with `Limits.adapter_call_timeout`. The bound covers the adapter call itself, not
  the wait for an adapter slot and not the caller's bounded wait. A call that times out
  is answered `AdapterError::OutcomeUnknown`, and the M01 path for that answer runs:
  * a `prepare` is recorded `Uncertain`, its preparing marker is released, and, when its
    operation already left `running`, the same transaction decides cleanup ownership
    through `settle_effect_in`;
  * the supervisor's next pass processes the resulting cleanup intent in the same process,
    with no restart;
  * a timed-out `reconcile` is handled as its call site handles any `reconcile` error in
    M01. Recovery of an unresolved operation leaves it unresolved, and the check of an
    earlier attempt before a fresh one records it `Uncertain` (m02-plan U0b row 24);
  * a timed-out `revoke` counts as an unconfirmed answer. A tracked obligation keeps it,
    and the immediate best-effort call of an uncovered grant counts as made, as an error
    does in M01.

  The adapters' futures must stop all work when dropped, so that nothing they started can
  apply an effect after the timeout. M02's adapters have no external effect, and their
  agent listing is already bounded (2 s, m02-plan U6). The runtime part is m02-plan U0b
  row 24.
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
  of that write (for example `EPIPE` because the reader has closed) leaves `launching`
  last. ⟨§12.15 item 8⟩ std's `CommandExt::exec` resets SIGPIPE to the default action and
  clears the signal mask in the calling process before `execvp`, and nothing restores
  them when the exec fails. So after a failed exec, Heimdall reinstalls a SIGPIPE
  disposition that does not terminate the process before it writes `prelaunch_failed`.
  If that cannot be done, the fd protocol writes nothing more and `launching` stays
  last.
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
    `observe_held` (m02-plan §5 item 15). ⟨r5⟩ Each `HeldStep` it returns carries the
    content fingerprints of §5.7, which the repair's plan digest covers.
  * ⟨r5⟩ The port `CredentialAdapter` gains a documented contract: a dropped call stops all
    its work. The runtime bounds every adapter call (`Limits.adapter_call_timeout`, an
    application limit, not a wire field; §7).
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
    optional Unix `birth`. ⟨r5⟩ `FileStep.role` gains `git_lock`, and `StepContent` gains
    `lock_holder` (the Git lock holder K, §5.6). An absent base takes only an insert-only
    splice. `FileIdentity` equality treats a `birth` present on one side only as unequal.
  * ⟨r5⟩ **Recovery input:** `RecoveryState`, built from the receipt history, replaces the
    last receipt as `decide`'s input. `held` is not an input phase, and `HoldReason` gains
    `contradictory_receipts` (§5.7).
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
| ⟨r5⟩ Claiming Git's lock with B_git's own staged file S (revision 4) | The exchange then had no staged name to take S from. On Windows `ReplaceFileW` would have needed the lock name as both replacement and backup, or would have emptied the lock at the exchange. A create would have released the lock at its commit point (M2-T01). A separate holder K occupies the lock until settlement ends (§5.6) |
| ⟨r5⟩ An empty lock holder | Within one run on a filesystem without birth time, a lock that the user removed and Git re-created on the same inode, still empty, would pass K's identity and digest checks and could be discarded. K's random line makes that impossible. It is not an ownership proof (§5.6) |
| ⟨r5⟩ Deciding recovery from the last durable receipt (revision 4) | After a `held` receipt, the last receipt no longer shows the step's phase: a step held after `validated` and one held after `restore_started` looked the same (M2-T04). `RecoveryState` removes `held` receipts and carries the restore and settlement context (§5.7) |
| ⟨r5⟩ Binding a held repair's preview to the recovery classification only | S′ and X do not say which content or which foreign entry is there. A second in-place edit, or a different foreign replacement, would leave the preview valid (M2-T03). The preview binds identity and content fingerprints (§5.7) |
| ⟨r5⟩ Bounding only the caller's wait for a preparation | The preparation keeps running and keeps its preparing marker, so the supervisor never processes its cleanup intent before a restart (M2-T06). The bound applies to the adapter call (§7) |

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
* **QR15. The Git lock's ownership token** (§5.6; rows G0–G3, ⟨r5⟩ now K0–K4 with the
  token on the lock holder K, QR16). The ruling asks for an
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

### 12.11 Rulings on design review round 4 (orchestrator, 2026-11-01)

Source: `tests/evidence/artifacts/review-m02-design/round4.md` (verdict: proceed after
fixes; M2-T01, T02, T04 and T06 major; T03 and T05 medium; plus an interface
reconciliation list). Every fix is accepted:

1. **T01: Git name transitions are specified per platform.** For each of claim, forward
   replacement, restore and settlement, on Unix and on Windows, the design states which
   name holds S and which holds D.
   * On Windows a distinct displaced backup name is used. The lock name stays occupied
     by Heimdall's claimed file until settlement.
   * Crash vectors cover every transition, including the first creation of an absent
     global Git file.
2. **T02: materialization takes the full step.** `materialize` takes the `FileStep` (its
   expected base and target states) and verifies both digests. An absent base is an
   empty splice input that allows only an insert-only range. Range arithmetic is
   checked.
   * Tests: an absent SSH config and an absent global Git config, each with a fresh
     writer.
3. **T03: held previews carry content fingerprints.** A held preview binds the identity
   and content digest of every observed entry, with an explicit `unreadable` marker for
   content that cannot be read within bounds. Bytes are never written to receipts or
   output.
   * Controls: two successive in-place edits, and two different foreign replacements.
4. **T04: recovery input is normalized.** `decide` takes a `RecoveryState` built from the
   receipt history: the effective phase before any `held`, plus the restore and
   settlement context. `held` is not an input phase.
5. **T05: properties describe concrete effects.** Each generated-test property states the
   effect it permits:
   * performing a restore exchange is distinct from recognizing one already completed;
   * the cleaner's removal is authorized by its locator, under its own durable ownership
     rule;
   * a create rollback goes through quarantine and is content-checked.

   Observations are normalized: role precedence is defined, and impossible
   identity/link-count combinations are rejected before enumeration. Negative controls
   still prove that foreign or modified content is preserved.
6. **T06: real adapter calls are bounded.** A new integrator-owned task, U0b phase 2,
   carries ADR-0006 §13.20 item 3.
   * Every real-adapter call (prepare, reconcile, revoke) gets a bounded timeout.
   * A preparation that times out after its effect settles as `Uncertain` through
     `settle_effect_in`, and its preparing marker is released.
   * The supervisor then processes its cleanup intent without a restart.
   * Tests cover each of these.
7. **The interface reconciliation list is binding on U0b.** U0b must preserve:
   * the `admit` backpressure order;
   * the recovery paths that complete interrupted withdrawals and process cleanup
     intents;
   * `claim_seq`, `effect_seq` and `cleared_by_claim`;
   * the `CleanupIntent` store lifecycle and counters;
   * `settle_effect_in`;
   * `cleanup_pending`.

   The plan's descriptions are corrected to match. The `FileIdentity` birth rule gets
   tests for `Some`≠`None` in both directions.

Once these are applied, wave 0 starts. The integrator verifies T01–T07 against the code
as its first step; a further full design review is not required. The independent review
of wave 0's code covers them.

### 12.12 ⟨r5⟩ Questions raised by revision 5 (recommended answers)

Units build against the recommended answers; the integrator changes the affected unit if a
ruling differs.

* **QR16. Git's lock is held by a separate lock holder K** (§5.6; rows K0–K4). §12.11 item
  1 requires the lock name to stay occupied by Heimdall's claimed file until settlement,
  with a distinct Windows backup name. If S itself is claimed (revision 4), Windows'
  `ReplaceFileW` moves S off the lock name at the exchange, and a create moves it off at
  its commit point, so neither can keep the lock. **Recommended:** a separate `git_lock`
  step whose file K is created under a random name, receipted (`file.staged`, the
  ownership record of QR15), claimed by a no-replace rename, and released last, after
  B_git's settlement. B_git becomes an ordinary replace or create step with ordinary
  names. K's content is one line with 128 random bits fixed at admission. It is not an
  ownership proof: ownership stays K's identity, under QR15's birth-time rule. It only
  gives K's discard an expected digest that no Git lock has. *Why:* the lock is then held
  from the claim to the end of settlement on both platforms and for a create. The lock
  name is never an argument of an exchange, and only one small table looks at it.
  *Alternatives:* claim with S on Unix and with a second file only on Windows, which
  gives two protocols and still releases the lock at a Unix create's commit; or hold a
  lock only during a replace, which leaves a create unprotected between its commit point
  and `item.committed`.
* **QR17. What a timed-out `revoke` counts as** (§7; m02-plan U0b row 24). ADR-0006
  §13.20 item 3 bounds adapter calls but does not say how a timed-out `revoke` is
  counted. **Recommended:** exactly as an adapter error in M01:
  * in a revocation round and in a bounded cleanup call, it is an unconfirmed answer, so
    the obligation stays and the round counts as attempted (§13.12 item 1);
  * the immediate best-effort call for a grant that no record covers (§13.17 item 3)
    counts as made, and its intent is removed.

  *Why:* M01 already treats an error that way, and a timeout is an error whose answer
  was lost. M02's adapters have no remote effect: their `revoke` removes a local
  integration. *Alternative:* keep the intent after a timed-out immediate call and retry
  it on every supervisor pass. That is safer for a remote effect, and it is a candidate
  for M03, whose managed credentials have one. In M02 it would retry a local no-op
  forever.

### 12.13 Orchestrator rulings on §12.12 and m02-plan P12 (2026-11-01)

* **QR16:** accepted. A separate lock holder K keeps Git's lock from the claim until K is
  settled, which happens last. Ownership is decided by K's recorded identity and the
  birth-time rule; K's content never counts as proof.
* **QR17:** accepted for M02. A timed-out `revoke` counts as unconfirmed in rounds and in
  bounded cleanup, so the obligation stays. A timed-out immediate best-effort call for an
  uncovered grant counts as made. That is acceptable only because M02's existing-access
  adapters create no remote credential effect.
  * **Binding requirement for M03:** once a managed credential has a remote effect, a
    timed-out immediate call keeps its cleanup intent and is retried with bounded,
    jittered backoff (ADR-0006 §13.6 item 4). It never counts as made.
* **P12:** accepted. `adapter_call_timeout` defaults to 30 s, with a minimum of 1 s. It
  is internal and not a user configuration key in M02.
* **Design gate closed.** The design reviews close with revision 5 (§12.11). Wave 0
  (U0 + U0b phase 1) starts. Its first step verifies the reconciliation and T01–T07
  against the code, and an independent review of wave 0's code follows.

### 12.14 Rulings on the wave-0 verification and integration escalations (orchestrator, 2026-11-01)

Sources: `docs/architecture/m02-wave0-verify.md` (E1–E16) and the wave-0 integrator's
report (workflow `wf_ce8d2e38-72a`). Wave 0 is green: check.sh exits 0 from a clean
build, with 828 tests (M01's 735 plus 93 new).

1. **E7 and the restore cause, needed before U4.**
   * `RecoveryState::build(step, &[StageReceipt], &[FileStep])` is accepted. The step
     list is needed for the per-shape phase order and for `release_due`. The frozen
     signature changes accordingly.
   * `RestoreCtx::Done` carries its cause: whether a restore recorded a mismatch or
     completed cleanly. This amends §5.7: a recognized completed restore must know
     whether a conflict artifact exists.
   * U4 builds against these two changes.
2. **E8: port-crossing types live in `heimdall-domain`.** Confirmed:
   * `StepObservation` with `normalize`, `EntryObs`, `RecoveryState` and its parts,
     `StepShape`, `StepDecision`, `HoldReason`, `StepFingerprint` and `EntryFingerprint`
     are in `heimdall-domain`, owned by the integrator;
   * `decide`, `decide_item`, `observe_*` and `materialize` stay in `heimdall-localenv`.
3. **E1–E5, readings confirmed:**
   * **E1:** cancelling an open setup or catalog operation is refused with
     `CAPABILITY_UNAVAILABLE`/`driver_unavailable` while the drivers are off. Phase 2
     adds a U0b row: a setup cancel is allowed only before the first commit point (§5.4),
     and after it the answer is `OUTCOME_UNKNOWN` with `next: reconcile`.
   * **E2:** the per-operation `runtime_lifecycle` payload is
     `{phase: unresolved, operation_id, kind, state, reason}`.
   * **E3:** the field is `ErrorDetail.reason` (wire `data.error.reason`).
   * **E4:** the new `OperationKind` variants use the dotted wire name in serde too, so
     serde equals `as_str` for every kind, asserted by test.
   * **E5:** the exhaustive kind classifier lives inside `heimdall-contract`.
4. **E6, E9–E16:** each fail-closed reading is accepted.
   * **E6:** the CLI wave-0 test is hosted in the `heimdall` package. `m02_integration`
     and `wave0_fail_closed` are modules of `model_operations`.
   * **E9:** a source-scan test ensures `Rendered` is built only in
     `sshconf::render`, `localenv::materialize` and `localenv::projection::git`.
   * **E10:** `SetupIntent::validate` decodes the content and refuses armor. Tests scan
     the decoded bytes.
   * **E11:** at most one `git_lock` step, directly before `git_include`. It does not
     commit, and its holder line ends in exactly one `\n`.
   * **E12:** `BaseMissing` maps to `IntentInvalid`.
   * **E13:** M01 test literals may change only by adding the new fields at their
     default values.
   * **E14:** `Operations::start` does not enforce the 1 s floor, so tests may set a lower
     value. The production default is 30 s.
   * **E15:** restore recognition follows ADR property 4 and rows F5b/F5c.
   * **E16:** "T01–T07" means T01–T06 plus §12.11 item 7.
5. **Deviations accepted:**
   * Migration 0005 adds a `projection_records` table and an index on
     `operations(environment, kind)`. The §5 item 18 wording is amended to include them.
   * The bind hash is unchanged: materialize keeps the M01 input byte for byte, and
     launch hashes `{form, executable}` without the holder.
   * Inspect of identities and projections is owner-only, so U8's pre-launch check runs
     with the owner role.
   * `OpError.resource` is now boxed.
6. **Identity selection crosses the port in full.** `PrepareOutcome.integration` carries
   a full `IdentitySelectionReport` (its entries and `identities_only`), not only the
   verdict. Fallback clearance (QR8, §12.5 item 5) can then judge the inherited entries.
   * U6 implements it, and the U0b phase-2 row records it with the adapter timeout.
   * Until then, a fallback is never cleared, which fails closed.
7. **The duplicate skeleton run.** A coordination error by the orchestrator ran two
   instances of W0-skeleton. The combined tree builds, is clean under fmt and clippy on
   both the host and the Windows target, and passes its tests. The independent review of
   wave 0's code checks the semantics of `ports.rs`, `cli.rs`, `adapters` and `launch`
   against m02-plan U0, which is the authority; neither instance's text is.
8. **Later-unit items stay with their units:**
   * `Limits.adapter_call_timeout`: U0b phase 2, row 24;
   * `OperationsConfig.projection`: U5;
   * `HEIMDALL_TEST_CLOCK_OFFSET_S`: U8;
   * the 1Password socket-path excerpts are blocked until a live source can be pinned.
     Until then, detection uses `SSH_AUTH_SOCK` and IdentityAgent only.

### 12.15 Rulings on the wave-1 escalations (orchestrator, 2026-11-01)

Sources: the five wave-1 unit reports and the integrator's report (workflow
`wf_71536525-4b6`). Wave 1 landed in f704ce93. check.sh exits 0 with 1064 passed, 0
failed and 4 ignored, run four times by the integrator and once by the orchestrator. Every
reading below that a unit implemented fail-closed is accepted unless the item says
otherwise. Items naming **W2-U2r** are a wave-2 unit owning `crates/sshconf/**` and its
`tests/model/sshconf_*.rs` and `tests/adversarial/sshconf_hostile.rs`.

1. **Manifests and the production graph.** The units' manifest and lock edits are adopted
   (test targets, the sshconf dev-dependencies, testkit's `fixtures` feature; the lock
   only gained edges). The integrator's finding B is fixed in f704ce93: the `heimdall`
   binary takes `heimdall-testkit` with default features off and feature `app` only, so
   the U7 process fixtures are not compiled into the production graph.
2. **Command text is bound raw (U1; changes a frozen type).** `parse::Directive` gains
   `raw: Option<String>`. For `ProxyCommand`, `LocalCommand`, `RemoteCommand` and
   `KnownHostsCommand` it holds the rest of the line after the keyword and its separator,
   as OpenSSH's readconf keeps it: quotes and a trailing comment included. For every
   other keyword it is `None`. `relevant::behavior_digest` binds `raw` in place of `args`
   for those four keywords, so a change of quoting alone (`$X` against `'$X'`) changes the
   digest. Owner: W2-U2r. U3's `ssh -G` corpus test checks `raw` against the printed
   value.
3. **Source role (U2 gaps 1 and 2, U6 E-U6-1 and E-U6-5).** §5.2 requires each value's
   provenance reduced to its source role. The wave-1 digest leaves the role out, which
   is a defect against §5.2.
   * (a) `eval::Value` gains a `role` with the four §5.2 roles (`managed`, `user`,
     `system`, `default`). The managed role belongs to values read from the
     Heimdall-owned include file P. The evaluator learns P's path through its `Roots`.
     `behavior_digest` binds the role. Owner: W2-U2r.
   * (b) `IdentityEntry.provenance` and `IdentityEntry.source` are filled from that role.
     `identity_selection_with_spans` may remain as an additive API. Owner: W2-U2r.
   * (c) `PairIntegration` gains `identity_selection_report:
     Option<IdentitySelectionReport>` (serde default, skipped when `None`). The contract
     schema is regenerated, and `prepared_pair` uses it. This completes §12.14 item 6.
     Owner: U0b phase 2 (wave 3). Until then, a fallback is never cleared.
   * (d) `heimdall_domain::catalog::fallback_clearance` takes the adopted identity's
     fingerprint. A `Managed` entry is cleared only when its fingerprint equals it. U6's
     `integration::strict_clearance` becomes the domain rule, so readiness, U6 and U8's
     pre-launch check apply one rule. Owner: U0b phase 2.
4. **Retired keywords and expansion sets (integrator E).**
   * A retired keyword in `directive::OBSOLETE` is not invalid. The evaluator consults
     `directive::obsolete()` and records the line as ignored, with no effect on any
     value, as OpenSSH does. An `Unsupported` entry still produces a doctor note.
     Owner: W2-U2r.
   * Evidence obligation: U3's corpus test runs `retired.conf` through every client in
     the matrix. A supported client that refuses it reopens this item for that client.
   * `expands_env` and the token sets follow the pinned S01 text, not F7's shorter
     quotation, since F7 quotes S01. U3's corpus test checks each S01-wider keyword on
     every client in the matrix. A supported client that disagrees is a defect, fixed by
     gating on client version.
5. **Executing and code-loading constructs (U1, integrator J).** `XAuthLocation`,
   `PKCS11Provider` and `SecurityKeyProvider` make ssh run or load code when used.
   `relevant::executing_constructs` lists them when they may take effect; their value
   class stays first-wins. Owner: W2-U2r.
6. **Readings accepted as implemented:**
   * U1: the lexer's fail-closed differences (`MalformedKeyword` cases); limits that count
     every read; the root at depth 0; `Cycle` reported only by `walk`; the inert
     `@CORPUS_DIR@` corpus.
   * U2:
     * exclusive selection requires a determined `IdentitiesOnly yes` (F9);
     * the consent reason-kind order;
     * a BOM file is invalid with `byte_order_mark`;
     * opaque candidates for unreadable parts of the tree;
     * `find_blocks` reports `intact` structurally;
     * the additive render and edit APIs.
   * The Host-pattern case rule per pass, `Match canonical`/`final`, `HostName` not being
     set again in the final pass, and parse-only includes under a false section are
     `[I]`. U3's `sshconf_vs_ssh_g` corpus settles each on every client in the matrix.
   * U7:
     * the guard's extra refusals;
     * `FakeAgent::release_pending` semantics;
     * `HM_FIXTURE_SSHD_AUTHORIZED_KEYS` and `HM_FIXTURE_SSHD_LOG` are the U11 harness
       interface (this amends m02-plan §4);
     * the fixture `Running` types are the handles themselves.
   * The non-root sshd fixture runs the account's login shell for a session. Tests that
     need only authentication use `-N` (no session channel), so no shell startup file
     runs. A test that needs a session says so.
   * U6:
     * E-U6-2, the ipc-local `AgentLocator` and `ClientBounds`. The orchestrator adds
       the `heimdall-localenv → heimdall-ipc` edge before wave 2. U3's
       `probe::agent::list_identities` converts `EndpointLocator` to `AgentLocator`.
     * E-U6-3 and E-U6-7.
     * E-U6-8: the descriptor states the adapter's best case, and the achieved check
       after prepare is binding.
     * An empty listing reported as locked, with basis `inferred`.
   * U8:
     * E5's additive APIs (`with_ids`, `check_arguments`, debug-only test hooks);
     * every E6 resolution and environment reading.
7. **Wave-3 items (U0b phase 2, U5, U8 wiring):**
   * E-U6-4: an existing-access prepare error maps with `OpError::from_adapter_for(&e,
     "provider")`, reason `endpoint_absent`. `INTERACTION_REQUIRED` carries its reason
     and `next.provider_interaction` from the pair eligibility the runtime computes.
   * E-U6-6: after a restart, `reconcile` for an adapter with no external effect is
     answered from the operation's `PreparedFacts`, not from instance memory.
     Meanwhile `not_applied` fails closed.
   * U8 E3: `heimdall-launch` gains `serde_json` and replaces the hand encoder; the
     golden test stays.
   * U8 E7: `MAX_ARGV_BYTES` is enforced by the wiring before `ensure`.
8. **Process contract (U8 E1, E2, E4):**
   * E2: §8's SIGPIPE sentence was wrong and is amended there. U8's fix, which
     reinstalls a non-terminating disposition after a failed exec, is the rule.
   * E1: `sys::adopt_inherited_fd` is assigned to W2-U3. It also clears an inherited
     `O_NONBLOCK`.
   * E4: W2-U3 adds `sys::create_owner_only_exclusive(path) -> File`:
     * Unix: `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, 0600;
     * Windows: `CREATE_NEW` with `FILE_FLAG_OPEN_REPARSE_POINT` and an owner-only DACL
       through `SECURITY_ATTRIBUTES`;
     * it is entered in the `sys` unsafe inventory;
     * `--meta-file` uses it from wave 3.
9. **Wave-2 ownership (amends m02-plan U3 and U4 owner paths).**
   * The orchestrator splits `crates/localenv/src/sys.rs` before wave 2:
     * `sys/mod.rs` (U3's bodies, `adopt_inherited_fd`, `create_owner_only_exclusive`);
     * `sys/quarantine.rs` (U4's `replace_file`, `handle_identity`, `RemoveOutcome`,
       `QuarantineDir`, re-exported by `sys`, so every public path is unchanged).
     The orchestrator also pre-registers the wave-2 test targets and dev-dependencies
     in `crates/localenv/Cargo.toml`.
   * U4 is delivered by three units with disjoint files:
     * **W2-U4a, primitive:** `sys/quarantine.rs`, `projection/replace.rs`,
       `projection/content.rs`, `materialize.rs`; tests in
       `tests/integration/projection_replace.rs`.
     * **W2-U4b, recovery:** the bodies of `RecoveryState::build` and
       `StepObservation::normalize` in `crates/domain/src/projection.rs` (those two
       bodies only), and `projection/recovery.rs`; the pure recovery tests in
       `tests/model/projection_recovery.rs`.
     * **W2-U4c, transaction:** `projection/{mod,plan,apply,observe,cleaner,git}.rs`;
       `tests/integration/projection.rs` and `tests/integration/projection_git.rs`,
       including the filesystem-backed `recovery_generated_observations_preserve_every_entry`.
     The plan's U4 test list is divided by these files.

### 12.16 Rulings on the wave-1 code review (orchestrator, 2026-11-03)

Source: `tests/evidence/artifacts/review-m02-code/wave1.md` (Codex, independent, fix first;
Y01–Y06). Each finding was reproduced by the reviewer with a compiled probe or `ssh -G`. All
six are accepted as defects. Five lie in `crates/sshconf`, which W2-U2r edits during wave 2,
so they are fixed after wave 2 integrates, by one fixer unit (`W2b-fix`, owning
`crates/sshconf/**`, `crates/testkit/src/home.rs` and their tests). Each fix carries a
regression test that fails without it.

1. **Y01: environment references are not determined behaviour.** The runtime's environment
   is not the environment of a later `ssh` invocation, so a value that reads a variable
   cannot be known statically. This amends §5.2 and §6:
   * a relevant directive whose effective value contains `${VAR}` is `Undetermined`, with
     reason `environment_reference`, in `RelevantBehavior`, the behaviour state and the
     identity selection;
   * so is an `IdentityAgent` whose value begins with `$`, except `$SSH_AUTH_SOCK`;
   * so consent is never reused across it (§5.2: prior consent covers determined states
     only).
   * The literal `IdentityAgent SSH_AUTH_SOCK`, `IdentityAgent $SSH_AUTH_SOCK` and an unset
     `IdentityAgent` are the **default** agent. The default agent is determined, with role
     `default`. The decision summary shows it as "the session's `SSH_AUTH_SOCK`". Its
     endpoint is outside configuration; that residual is stated in §13.
   * Binding the runtime's expanded value instead is rejected, because it would claim a
     determination the runtime cannot make.
2. **Y02: the fixture guard covers every invocation.** `ScratchHome::check_alias` evaluates
   the alias under every `Invocation`: `Shell`, `Exec(None)`, `Exec(Some(_))` with a
   sentinel command, and `Subsystem("sftp")`. It also evaluates under each value a
   `SessionType` directive in the tree can give. It refuses when any one evaluation fails
   the guard. The `client_command` API is unchanged. Regressions: an exec-only, a
   subsystem-only and a `SessionType`-selected outside identity, and the same for
   `IdentityAgent`, are each refused.
3. **Y03: an Include target is literal or refused.** OpenSSH globs inside a quoted Include
   argument, and escaping is not verified across the client matrix. A rendered Include
   target is therefore refused when it contains `*`, `?`, `[` or `]`, in addition to the
   §4 path rules. This amends §4's paths row for `Include`. The refusal is
   `unmanageable{include_target_glob}`, which is manual mode, before any edit.
   `IdentityFile` and `IdentityAgent` are not globbed, so they keep the §4 rules.
   Regression: the reviewer's bracket case is refused, and a target without
   metacharacters renders as before.
4. **Y04: `Match sessiontype` reads the effective session type.**
   * When a `SessionType` directive is already in force in the pass, that value is used;
     otherwise the `Invocation` decides.
   * When the in-force `SessionType` is itself undetermined, the condition is `Unknown`.
   * U3's `sshconf_vs_ssh_g` corpus gains the reviewer's case and a `SessionType
     subsystem` case.
5. **Y05:** `RenderPath::home_relative` normalizes `\` only for the Windows style. On Unix,
   a backslash is refused by the Unix rule and never rewritten.
6. **Y06:** `strip_pipe_prefix` checks the character boundary before slicing. A proptest of
   at least 256 arbitrary Unicode strings asserts that the public `RenderPath`
   constructors never panic.
7. **Wave-2 interaction.** W2-U2r's wave-2 changes add `raw` and the source role. They do
   not overlap these findings in purpose, but they share `eval.rs`, `relevant.rs` and
   `render.rs`, hence the fix after wave 2. Until then, no wave-2 test may rely on the
   wave-1 behaviour these rulings change.

### 12.17 Rulings on the wave-2 escalations (orchestrator, 2026-11-03)

Sources: the five wave-2 unit reports and the integrator's report (workflow
`wf_2a33ac4a-86c`). check.sh exits 0: twice for the integrator and once for the
orchestrator, with 1278 tests passed and 0 failed.

The follow-up work is **wave 2b**, with three units of disjoint files:
* **W2b-fix**: `crates/sshconf/**`, `crates/testkit/src/home.rs` and their tests;
  §12.16 and items 9–10 below.
* **W2b-U4r**: `projection/replace.rs`, `projection/content.rs`, `materialize.rs`,
  `sys/quarantine.rs`, `projection/recovery.rs`, the bodies and docs of the recovery types in
  `crates/domain/src/projection.rs`, `tests/model/projection_recovery.rs` and
  `tests/integration/projection_replace.rs`.
* **W2b-U4t**: `projection/{mod,plan,apply,observe,cleaner,git}.rs`,
  `tests/integration/projection.rs` and `tests/integration/projection_git.rs`.

Item 2 runs across W2b-U4r and W2b-U4t, as that item describes.

1. **Name-taking replace API (U4a, U4b E5, U4c).** The additive `learn_step`,
   `exchange_at`, `observe_step_at`, `restore_with` and `rename_noreplace`, which take the
   step's `StepNames`, are the frozen API of `projection::replace`. The name-learning
   fallbacks are retired. This API is internal to `heimdall-localenv` and does not cross the
   port. Owner: W2b-U4r. W2b-U4t follows any rename.
2. **F0x/K0x have one home.** `observe_step_at` classifies an unrecorded, regular,
   user-owned, single-link entry at a step's staged name, for a step with no receipt, by
   digest: `Recorded{S}` or `Recorded{S′}`. It never does so at the lock name. Anything
   else there is `Foreign`. The engine's `unrecorded_staged` workaround is then deleted.
   Owners: W2b-U4r (the classifier) and W2b-U4t (deleting the workaround once the
   classifier change has landed; if it has not, the workaround stays and is reported).
3. **`release_due` in an abort (U4b E3, U4c (a)).** No new receipt is added. Release of K
   is due when either of these holds:
   * the receipts make it due (build);
   * `decide_item` decides the item's abort or restore, and every other Git step has
     reached its abort end in the current observation.
   `reconcile` computes the second condition from durable receipts and fresh
   observations each round. So a restart reproduces it, and §5.7's "release K last" holds.
   Regression: a crash after the hand-over and before K's release releases K at
   restart, and never earlier. Owner: W2b-U4t.
4. **`decide_item` inputs (U4b E4).** `StepState::Held(HoldReason)` carries the real
   reason. A new `StepState::CommitRestored` is the commit step after its own file-level
   restore (`restore_started{file_mismatch}` through `restored`), and T3 reads it. The
   `Unmatched` placeholder is retired. Owners: W2b-U4r (the type and `decide_item`) and
   W2b-U4t (the caller).
5. **A symlink substituted at the restore boundary is held (U4a, U4b, U4c).** Normalization
   rule 1 (r5) stands: a symlink is X whatever its identity, F5d holds with
   `third_writer`, and nothing moves. The test is renamed
   `a22_race_symlink_substitution_at_boundary_is_held`, and m02-plan U4's list is amended.
   Owner: W2b-U4t.
6. **§5.7 governs a failed first-adoption check (U4c).** A first-adoption transaction check
   can fail with an edited inactive P. The user file is then restored, unchanged inactive
   files are rolled back, the edited P is held (C7a), and a held Git item keeps K. The
   result is `OUTCOME_UNKNOWN` with the held repair options, not `CONFIG_CONFLICT` with
   effect `none`. §5.4's sentence is superseded by this item. An edited inactive P before
   commit means another writer touched Heimdall's file, and holding it for the owner
   fails closed.
7. **Readings accepted (U4a, U4b E1, E6, E7, U4c).**
   * The removal shape reads the locator as `Recorded{V}`.
   * For the removal shape, `Hold` means that nothing moves and the cleaner retries on
     its next pass. That is row R6. The cleaner writes no receipts and never escalates on
     its own, so `Hold(ThirdWriter)` there is not reported to the owner.
   * The contradictory-history list and the settlement-source pairings of E6.
   * The receipt-bounded effect sequence of E7.
   * U4a's fail-closed readings: group- or other-writable is `ForeignOwner`, the size
     bounds, and an owner-only DACL on Windows.
   * The primitive's foreign put-back name is `<name>.hm-conflict-<slot>`, because the
     primitive knows no generation. This amends §5.3. §5.5's rollback rename of an edited
     P keeps `ssh_config.hm-conflict-<gen>`, from the plan, which knows the generation.
   * The stale "open settlement" and "Body: U4 (unreachable…)" documentation is
     corrected by W2b-U4r. `RecoveryState.settlement` stays `Some` from `file.settling` until
     the slot is empty.
8. **U4c's open work, assigned to W2b-U4t and part of the wave-2 exit:**
   * §5.5: rollback renames an edited P to `ssh_config.hm-conflict-<gen>`, with a
     no-replace rename.
   * §5.6: the Git parse check `git config --file <N_s> --no-includes --list` runs before
     B_git's exchange. A failure aborts before the commit point.
   * The §5.2 consent waivers are computed in `preview` through `sshconf::consent`, and
     `ProjectionPlan.consent` is filled. A plan that needs no decision under §5.2 gets none.
   * The `RemoveDuplicateMarkers`, `MoveIncludeToTop` and `ManualMode` repair previews.
   * The manual-mode encoding check uses `ClientInventory::accepts_encoding` (U3 E6).
   * `recovery_generated_observations_preserve_every_entry` covers the GitLock and Removal
     shapes too.
   * The commit-point crash test runs once as a real child-process abort (`std::process::
     abort` at the hook), labelled as such, besides the in-process unwind. In-process
     unwinds stay labelled as unwinds in evidence.

   `recovery_table_rows_each_have_a_test_vector` is W2b-U4r's, in
   `tests/model/projection_recovery.rs`.
9. **sshconf semantics (W2-U2r 3–10, W2-U3 E1, E7), for W2b-fix with §12.16.**
   * `XAuthLocation` is listed by `executing_constructs` whenever it is set, `none`
     included, since `ssh -G` 10.3p1 shows `none` is a program name for it. There is no
     `ForwardX11` gate, which fails closed.
   * Accepted as implemented:
     * a command keyword's `none` is decided by its raw text;
     * `RemoteCommand` is in `RelevantBehavior`, with digest tag `heimdall.behavior.v2`
       (nothing is persisted yet);
     * a non-UTF-8 command line is `Keyword::Unreadable`;
     * the `IdentityEntry.source`/`provenance` reading;
     * the default role is the role of a value no file sets.
   * `RemoteCommand` joins the item-2 keyword list of §12.15.
   * **Include `~` (U3 E1, observed on 10.3p1):** OpenSSH expands `~` in an Include, and in
     the implicit `~/.ssh/` of a relative user Include, through `glob(3)` `GLOB_TILDE`,
     which reads `$HOME`. F19 still holds for `IdentityFile` and the other paths.
     Therefore:
     * The evaluator expands an Include's `~` with the account home when the runtime's
       `HOME` equals it. Otherwise that Include's resolution is undetermined (reason
       `environment_reference`, as §12.16 item 1), and the doctor reports `home_mismatch`.
     * The include block B's target is rendered as an **absolute** path, never `~`, so B
       loads P whatever `$HOME` is. This amends §4's home-relative row for the Include
       target only.
   * **Default identities (U3 E7):** sshconf's six-name default list stays a superset
     of 10.3p1's five. A larger list can only make a selection non-exclusive, which fails
     closed. U11 records the per-client list in the matrix.
10. **U3's settled observations and interface choices (E2–E9) are accepted.**
    * §5.6 and F22 are corrected: `git config --global` reads `~/.gitconfig` alone when
      that file exists. The static scan reads both files.
    * Wave 3 must honour:
      * `create_owner_only_exclusive` returns `io::Result<File>`;
      * `adopt_inherited_fd` allows one adoption per process, so wave-3 `--meta-fd`
        tests use subprocesses.
    * On Windows, the account home comes from `GetUserProfileDirectoryW`, and the sys
      inventory says so.
    * U9 fills the `LocalContext` and `ProbeContext` fields.
    * Non-interactive authentication probes are refused while selection is not
      exclusive, until U0b phase 2 lands `fallback_clearance`.
    * The doctor reports a command as `<command>`, and a proxied network level as
      refused with `CAPABILITY_UNAVAILABLE`.
11. **U4c's interface additions are accepted for wave 3:**
    * the `ProjectionConfig` fields and `PublicKeySource` (preview fails `Unavailable`
      without keys);
    * the `ItemCommit.record` placeholders, which the sink overwrites (the store refuses
      a mismatch);
    * `ItemRecord.files` lists only written files, and the sink merges the rest;
    * the test-only `git_item_any_default`;
    * the reasons `git_default_not_bundled_msys` and `verified_client_unavailable`.
    U5 adds those reasons to the contract's reason list.
    The three added dependencies (getrandom, serde_json, dev heimdall-store; all
    workspace-pinned) and W2-U2r's constructor edit in testkit `home.rs` are adopted.

### 12.18 Rulings on the wave-2 code review (orchestrator, 2026-11-03)

Source: `tests/evidence/artifacts/review-m02-code/wave2.md` (Codex, independent, fix first;
X01–X05). X01–X04 were reproduced by scratch probes; X05 is inferred from code. All five are
accepted as defects.

The orchestrator fixed X01 and X05 directly; no wave-2b unit owns those files. X02–X04 lie
in files that the wave-2b units W2b-U4r and W2b-U4t edit concurrently. They are fixed in
**wave 2c**, after wave 2b integrates, by one unit (`W2c-U4`) that owns the projection
files and their tests. Each fix carries a regression test that fails without it.

1. **X01: descriptor adoption duplicates, never takes.** `sys::adopt_inherited_fd` stays a
   safe function, with no new `unsafe` outside `sys`.
   * It returns an `OwnedFd` over `fcntl(F_DUPFD_CLOEXEC, 3)` of the named descriptor: a
     new number that nothing else in the process refers to. So it never creates a second
     owner, whoever owns the inherited number.
   * The inherited number is neither closed nor taken; it is set close-on-exec.
   * An inherited `O_NONBLOCK` is cleared on the shared open file description.
   * Both descriptors close at exec, so §8's protocol is unchanged.
   * The one-adoption guard stays.
   * Regression (`sys::tests::adopt_inherited_fd_checks_type_and_mode_once_and_clears_nonblock`):
     the reviewer's scenario. The adopted number differs from the caller's, and after the
     adopted descriptor is dropped and an unrelated file is opened, writes through the
     original owner still reach the pipe and the unrelated file stays empty.
   * `SideChannel::from_fd` is unchanged.
2. **X02: a create rollback never moves a changed active file.** Before moving an active
   path source into the slot, a create's rollback, or a continued path-source settlement,
   re-checks the entry's identity and target digest. A changed entry gives
   `ActiveEntryModified`: it stays at its path and the item holds (C7a). This is the same
   check §5.3 step 7 makes for a replace. Regression: the reviewer's scenario, an edit at
   `BeforeRestoreCheck`, leaves the edited configuration at its path and holds the
   operation. The crash-while-down C7a test stays. Owner: W2c-U4.
3. **X03: markers are reproducible.**
   * A first adoption's marker is derived, not drawn:
     * the first 128 bits of SHA-256 over `heimdall.marker.v1`;
     * the proposed generation;
     * the target file's role;
     * the canonical digest of the plan inputs: the spec, and the base digests of the
       files the plan reads.
   * The same inputs therefore give the same marker and plan digest, and §5.4 step 1's
     recomputation reproduces an approved preview. Any change of input changes the
     marker and the digest, as it must.
   * Markers were never secrets. A user's copy of a block is the duplicate-marker case
     either way.
   * The same rule applies to the Git block.
   * Regression: two unchanged first-adoption previews, for SSH and for Git, give equal
     plan digests. Changing any one input changes the plan digest.
   * Owner: W2c-U4.
4. **X04: the live path observes K before B_git's commit point.**
   * Before B_git's exchange, fresh apply observes the lock name and requires K's
     recorded identity there. Otherwise it applies K3 or K4 exactly as recovery does: an
     item whose commit step never exchanged aborts, and nothing is written to the global
     Git file.
   * Regressions, for both fresh apply and restart: K replaced by a foreign lock at
     `AfterLockClaim`, and K removed at `AfterLockClaim`.
   * Owner: W2c-U4.
5. **X05: name resolution is inside the network level's bound.**
   * A literal address needs no resolver.
   * A name is resolved on a helper thread that the probe waits on only until its
     deadline. The system resolver cannot be cancelled, so on a timeout that thread is
     left to finish on its own; it holds nothing but the lookup.
   * Regressions: `probe::network::tests::a_slow_resolver_is_bounded_by_the_deadline` and
     `…::a_literal_address_needs_no_resolver_and_a_failed_lookup_is_unreachable`.

### 12.19 Rulings on the wave-2b escalations (orchestrator, 2026-11-03)

Sources: the three wave-2b unit reports and the integrator's report (workflow
`wf_6f9a053c-b88`). The integrator's check.sh exited 0 three times; the final runs passed 1320
tests, with 0 failed. Every item of §12.16 and §12.17 is done except the two partials of
item 8 below. The orchestrator mutation-checked the §12.18 X01 and X05 regressions:
* with X01's duplicate removed, the test process aborts with "IO Safety violation: owned
  file descriptor already closed", which is the reviewer's defect;
* with X05's bound removed, the slow-resolver test fails after 5 s.

1. **Ratified (integrator):**
   * `probe::snapshot`'s `Digesting` source passes `include_home` through. This closes a
     fail-open under a non-UTF-8 `HOME`; regression
     `include_tilde_under_a_non_utf8_home_is_an_environment_reference`.
   * The m02-plan U4 note on the frozen name-taking replace API.
2. **Include `~` with `HOME` unset** resolves through the account home, as `glob(3)`
   `GLOB_TILDE` does when `HOME` is unset. A `HOME` that is set but differs from the account
   home, or is empty or relative, is undetermined (§12.17 item 9).
3. **An Include path holding `${VAR}`** is read under an unknown condition with an opaque
   point (§12.16 item 1), not as unreadable. Probes are not declined for it alone.
4. **Recorded, accepted:**
   * a `Subsystem` invocation ignores `SessionType`, as observed with `ssh -G -s`;
   * an invalid in-force `SessionType` gives `Unknown`;
   * `check_alias` makes at most 16 evaluations;
   * `home_mismatch` also fires for an empty or relative `HOME`;
   * an unset `IdentityAgent` is the default-agent item, with digest tag
     `heimdall.behavior.v2` (nothing persisted).
5. **Frozen-interface record.** These are part of the frozen sshconf, localenv and testkit
   surface:
   * `render_include_block` and `rendered_include_block` return `Result<_, RenderError>`;
   * the additive items `RenderError::Unmanageable`, `render::{INCLUDE_TARGET_GLOB,
     check_include_target}`, `RenderPath::absolute`, `ConfigSource::include_home` (a
     default method), `include::home_matches`, `ArgError::EnvironmentReference`,
     `UnresolvedReason::{EnvironmentReference, as_str}`, `relevant::{is_default_agent,
     agent_is_default, DEFAULT_AGENT_DISPLAY}`, `testkit::home::{guard_invocations,
     GUARD_EXEC_SENTINEL}` and `localenv::fs::include_home_for`.
6. **`decide_item` readings (W2b-U4r), accepted, all fail-closed:**
   * T1h holds as `displaced_replaced`, with `ExchangedInconsistent` carrying no payload;
   * `item.committed` with `CommitRestored` is `contradictory_receipts`;
   * the slot is observed as `?` when a settlement is on record but no `SettlingAt` is
     given;
   * `restore_with` holds (`third_writer`) when D's identity is on a symlink, a hard link
     or a foreign-owned entry.
7. **Repairs that take more than one operation (item 8d), accepted.** An intent allows one
   step per path, so `MoveIncludeToTop` inserts a fresh B at the top and reports
   `marker_duplicated`. A second `remove_duplicate_markers` operation then drops the old
   block, and P is never out of effect. `RemoveDuplicateMarkers` removes one duplicate per
   operation. U9 and U10 present a repair as complete only when doctor reports none left,
   and offer the next operation until then. Item 8d is done under this reading.
8. **Item 8 readings (W2b-U4t), accepted:**
   * §5.5's conflict rename is keyed on P's content digest and applies to P_git too
     (`gitconfig.hm-conflict-<gen>`).
   * When the Git parse check cannot run (local queries disabled, or no verified Git
     client), the Git item aborts with reason `verified_client_unavailable` (§12.17 item 11),
     not with `unmanageable_file`. Owner: W2c-U4.
   * Consent's affected set is the aliases whose P section changes. Key files are named by
     the key's fingerprint (`materialize::key_file_path`), so a different key changes the
     section and needs a decision. A key file rewritten with the same key needs none.
   * Stored consent counts only for items still in the record, so re-adoption after a
     rollback always needs a decision.
9. **For U5 (wave 3):**
   * the manual reasons outside `manual_reason::ALL` (`marker_edited`,
     `include_conditional`, and others) are added to the contract;
   * `include_target_glob` is reported as its own manual reason;
   * the sink refuses an `ItemCommit` whose consent `DecisionId` differs from
     `intent.approval.decision`;
   * a rollback commit removes the item;
   * aliases are merged when P is unchanged.
10. **The per-row recovery test (item 8, partial).** m02-plan U4 requires, for every §5.7
    row:
    * build the observed entries in a scratch directory together with the receipts;
    * run `reconcile`;
    * assert the action, the receipts written and the outcome.

    The wave-2b test checks each row through `build`, `normalize` and `decide` in memory
    only. That test is renamed `recovery_table_rows_each_decide_as_their_row` and kept.
    The plan's name, `recovery_table_rows_each_have_a_test_vector`, goes to the
    filesystem-backed test in `tests/integration/projection_recovery_rows.rs`. Owner:
    **W2c-rows**, a second wave-2c unit, which owns that file and
    `tests/model/projection_recovery.rs`.

### 12.20 Rulings on the wave-2c escalations; wave 3a (orchestrator, 2026-11-03)

Sources: the two wave-2c unit reports and the integrator's report (workflow
`wf_7ede658e-ecf`). check.sh exited 0 twice, with 1327 tests passed and 0 failed.
* §12.18 items 2–4 and §12.19 item 10 are done.
* The filesystem-backed row test builds all 80 rows of §5.7: 132 step and item vectors and 11
  cleaner vectors, and none was unbuildable on Unix.
* §12.19 item 8, second bullet, is partial; item 2 below completes it.

1. **High: K must be released without birth times.** The integrator confirmed this with a
   probe, now removed. Without a birth time, a successful live Git apply never releases K:
   the release goes through the recovery classifier, which treats every lock-name entry as
   X, and records K4. Git's lock then stays, and every later Git configuration write
   fails.
   * Ruling: within a run that claimed K, K's release classifies the lock name by K's
     identity and holder digest, as `Run::lock_held_by_k` already does (§5.6: within one
     run, identity and holder digest are checked at each step).
   * Restart still uses the recovery classifier.
   * Regression: a successful Git apply releases K with and without a birth time.
   * Owner: W3-U4. This item blocks the M02 exit.
2. **Outcome reasons.**
   * (a) The contract's `ConflictKind` gains `VerifiedClientUnavailable` (wire
     `verified_client_unavailable`), and the parse-check abort reports it.
   * (b) When recovery itself decides an abort, the outcome carries the reason the §5.7 row
     names:
     * `concurrent_writer` for F1a, F2g, C3, C4 and K3;
     * `user_config_changed` or `managed_file_edited` for F2e, F2j and a T0 precondition;
     * `git_config_locked` for K0 and K1 with a foreign lock.
   * (b) continued: the reason is durable. The `item.finished` receipt gains an optional
     `reason`, which is serde default and omitted when absent, so stored receipts stay
     valid. Restart reports the same reason the live run did.
   * The X04 abort reports `git_config_locked`.
   * The row-test vectors' ESCALATED expectations are updated to these reasons.
   * Owner: W3-U4, which may change only `ConflictKind` and the item receipt types in
     `crates/contract/src/setup.rs`.
3. **Marker width.** §12.18 item 3 is amended: the derived marker is the first **64** bits,
   because the frozen block form is `hm-<16 hex>` (§2). Markers are not secrets, and
   duplicates are `marker_duplicated`.
4. **Row K3 is amended.** An X at K's staged name, with the lock name empty, records
   `settle_conflict{foreign}`, naming the staged name. The entry is left in place and
   reported, as in K0z and K2. With nothing at either name, the receipt stays `{missing}`.
5. **Row K2 is narrowed (ratified).** B_git proceeds only while the lock name holds K with
   an unchanged holder digest. A K′ at the lock aborts before B_git's exchange, with
   `git_config_locked`. This is fail-closed (§5.6).
6. **Row F8d is amended.** The kept entry is `<name>.hm-conflict-<slot>`, as §12.17 item 7
   rules for the primitive.
7. **T1h.** `decide_item`'s T1h branch stays as a defensive arm of the total function.
   Through `reconcile` the case is reached as TH, by way of F4c's hold. The in-memory test
   covers the branch.
8. **Wave 3a.** The activation change set (m02-plan §2) plus the open items of §12.14–§12.20,
   built by three units of disjoint files, then integrated as one change:
   * **W3-U0b**, U0b phase 2 (m02-plan U0b, every phase-2 row and test). It also takes:
     * §12.14 item 3 E1, the setup cancel row;
     * §12.15 item 3(c), `PairIntegration.identity_selection_report`;
     * §12.15 item 3(d), `fallback_clearance` against the adopted fingerprint;
     * §12.15 item 7, E-U6-4 provider error mapping and E-U6-6 reconcile from
       `PreparedFacts`.
   * **W3-U5**, m02-plan U5 (the setup and catalog drivers, and runtime wiring). It also
     takes:
     * §12.14 item 8, `OperationsConfig.projection`;
     * §12.17 item 6, which reports a held item as `OUTCOME_UNKNOWN` with the held repair
       options;
     * §12.17 item 11, constructing `ProjectionConfig` and adding the two reasons to the
       contract's list;
     * §12.19 item 9: the manual reasons, `include_target_glob`, the sink's consent check,
       rollback commits, and the alias merge.
   * **W3-U4**: items 1 and 2 above, and the stale skeleton text in `launch/src/lib.rs` and
     `localenv/src/lib.rs`.

   U8 wiring follows as **wave 3b**, after wave 3a integrates (m02-plan §2), with §12.15
   items 7 and 8 (`serde_json`, `MAX_ARGV_BYTES`, `--meta-file` through
   `create_owner_only_exclusive`) and §12.17 item 10.

### 12.21 Rulings on the wave-2b/2c code review (orchestrator, 2026-11-03)

Source: `tests/evidence/artifacts/review-m02-code/wave2bc.md` (Codex, independent, fix first).
Y01–Y06 and X01–X05 are re-checked and closed. Two new findings, V01 and V02, were each
reproduced with a scratch probe and are accepted as defects. They lie in
`projection/plan.rs`, which W3-U4 owns during wave 3a, so they are fixed in **wave 3b** by a
unit `W3b-consent` that owns `crates/localenv/src/projection/plan.rs`,
`crates/sshconf/src/{relevant,consent}.rs` and their consent tests.

1. **V01: manual mode still classifies consent.**
   * Whether the user file may be edited, and whether it activates P, are separate facts.
   * In manual mode, preview evaluates the readable user configuration through the
     read-only source, exactly as for an editable one. It computes the affected aliases
     from every P change, and the §5.2 classification applies.
   * When activation or behaviour cannot be established, for example through an
     unreadable symlink target, the affected states are undetermined and a decision is
     required.
   * Regression: an active B in a symlinked user configuration, with a changed alias,
     requires a decision.
2. **V02: consent covers every invocation profile.**
   * A behaviour state is computed under each supported profile: `Shell`, `Exec(None)`
     (any remote command, the command unknown; this covers Git-over-SSH and SCP) and
     `Subsystem("sftp")`.
   * The state's digest is SHA-256 over the tag `heimdall.behavior.v3` and the ordered
     `(profile, per-profile digest)` pairs.
   * It is determined only when every profile is determined.
   * A condition on the command itself (`Match command`) is unknown under `Exec(None)`, so
     such a state is undetermined, which fails closed.
   * Digests of tag v2 are never compared with v3. No consent of either tag has been
     persisted before this change ships.
   * Regressions: the reviewer's two examples, an exec-only HostName change and a
     subsystem-only `IdentityAgent ${VAR}`, each require a decision on rollback. An
     unchanged configuration still waives.
3. **Wave 3b** is therefore:
   * `W3b-U8`, the m02-plan U8 wiring with the items §12.20 item 8 names;
   * `W3b-consent`, items 1 and 2 above.

### 12.22 Rulings on the wave-3a escalations (orchestrator, 2026-11-03)

Sources: the three wave-3a unit reports and the integrator's report (workflow
`wf_84d1745b-aed`). check.sh exited 0 three times; the final runs passed 1390 tests, with 0
failed. Setup is active: `setup/1` is offered. A scratch-home setup ran through the real
runtime and projection writer:
* preview;
* attended `APPROVAL_REQUIRED`;
* approve;
* apply;
* `inspect projections`;
* a rollback that needed no decision and restored the user file byte for byte.

1. **Setup cancel, stricter cut-off (ratified).** A setup or catalog cancel is honoured
   only while the driver has written no receipt, effect or local. Otherwise the answer is
   `OUTCOME_UNKNOWN` with `next: reconcile`. This amends §12.14 item 3 E1: releasing
   `setup_in_progress` with staged files still unsettled would admit a second setup over
   them.
2. **A rolled-back item is an empty record (amends §12.19 item 9d).**
   * The store's per-item generation check needs a monotonic generation, so a rollback
     commits an **empty `ItemRecord` at its generation**, with consent dropped. An empty
     record is "no item": re-adoption needs a decision.
   * `plan.rs` treats an empty record, Git included, as absent. The rerender
     `has_git` reading is corrected. Owner: W3b-consent.
3. **`verified_client_unavailable` is `CAPABILITY_UNAVAILABLE`.** A missing verified client
   cannot be fixed by retrying and is not a configuration conflict. The setup driver maps
   `ConflictKind::VerifiedClientUnavailable` to `CAPABILITY_UNAVAILABLE` with that reason.
   Every other conflict stays `CONFIG_CONFLICT`. Owner: W3b-gaps.
4. **W3-U4's outcome-reason readings (ratified):**
   * K4 in an abort reports `git_config_locked`;
   * F2a with V′ counts as a T0 precondition and reports the base's conflict;
   * the rows the §12.20 item 2 list does not name carry no reason.
   * Residual: a crash between the abort decision and `item.finished` loses the reason,
     and restart then reports none. The reason is diagnostic, never authority. The no-birth
     residual is already in §13: K left at the lock after a crash is the owner's to remove.
5. **Ownership deviations (ratified as integrated):**
   * `item.finished`'s optional `reason` lives in `domain/src/operation.rs`;
   * U5's crate-private `LocalDriver` seam and `OperationsConfig.projection` are in
     `operations.rs`;
   * test literals gained `None` fields;
   * `heimdall-runtime` gained the `heimdall-localenv` and `heimdall-adapters` edges.
6. **Test hooks.** The `#[doc(hidden)]` read-only hooks on `Operations`
   (`setup_insert_calls`, `preparing_operations`, `available_adapter_slots`) are accepted for
   M02. Before release (M09 hardening) they move behind a test-only feature, and the
   release build must not expose them. Recorded in the release checklist.
7. **Readings accepted:**
   * E-U6-6 overrides only for adapters without external side effects;
   * E-U6-4's `fallback_identity_interaction` attribution;
   * `PROVIDER_LOCKED` uses `provider_unlock`;
   * previewed intents live in a bounded in-process memory, so after a restart a non-held
     repair needs a fresh preview, which fails closed;
   * `OpError` keeps rendering a held error's `data.setup` through `Completed`, with the wire
     form unchanged. A typed `OpError.setup` field is optional cleanup for U9.
8. **The writer refuses an empty `key_file`.** `ManagedAliasSpec.key_file` empty is
   `PreviewError::Unavailable`, never an empty `IdentityFile`. `include_target_glob` is
   emitted by `plan.rs` directly as its own manual reason. Owner: W3b-consent.
9. **Expired setup and catalog decisions follow M01.** An operation in `awaiting_approval`
   whose decision passes its deadline moves to `expired`, as ADR-0006's `DeadlineReached`
   transition does. A new operation is new work. Owner: W3b-gaps.
10. **Gaps closed in wave 3b by `W3b-gaps`:**
    * `RemoveProfile`: the store gains profile removal and the catalog action works (one
      of U5's eight actions);
    * `[setup] declaration_validity_days` is wired, with default 30;
    * tests for E-U6-6's `continued_preparation` path, an unreadable receipt leaving the
      operation unresolved and reported, and `RemoveDestination`;
    * §12.17 item 10: the non-interactive authentication probe adopts the domain
      `fallback_clearance` rule now that it exists, and refuses only a selection the rule
      does not clear;
    * a supervisor-driven cleaner deletion after rollback, through the real service.
11. **Out of reach in-process:** the production `ProjectionWiring::Account` path (the real
    account home, `Env::capture`, the `ssh -V` query) is untested by design. Its evidence is
    U11's native run in a disposable account (m02-plan §7, owner input).

### 12.23 Rulings on the wave-3a code review (orchestrator, 2026-11-03)

Source: `tests/evidence/artifacts/review-m02-code/wave3a.md` (Codex, independent, fix first).
The two findings, U01 and U02, were each reproduced over production components and are
accepted as defects. They lie in `setup.rs`, `operations.rs` and `service.rs`, which wave-3b
units edit concurrently, so they are fixed in **wave 3c** after wave 3b integrates.

1. **U01: a held repair records its attempt before any work.**
   * `start_repair` moves the repair to `running` and records `setup.attempt` on the repair
     operation in one transaction. The transaction proceeds only if the repair is still
     runnable, and it runs before any reconcile or closure receipt is written against the
     original held operation.
   * A cancel after that point is `OUTCOME_UNKNOWN` with `next: reconcile`, under §12.22
     item 1.
   * The repair's `setup_in_progress` blocker stays until the repair settles, so a second
     repair of the same held operation is refused for as long as the first runs.
   * Regressions:
     * the reviewer's probe: a cancel while the repair is paused before the writer is
       refused, and the original operation completes with the repair recorded as such;
     * a second repair admission while the first runs is refused.
2. **U02: nothing that can block runs inside the adapter bound.**
   * The inputs an adapter call needs are read before the bound, in the same operation
     step:
     * selections, catalog identities, declaration rows and executables (store reads);
     * the projection observation (file reads).
   * The adapter receives them as an in-memory `IntegrationSources` snapshot. Inside the
     bound it does only its own passive work: evaluation over the snapshot and the endpoint
     `stat`. That work does not wait on a lock or on I/O beyond one metadata call.
   * A blocked store or a slow observation therefore delays the operation's own step, as any
     store wait does, never the bounded call, and the bound's timeout keeps its meaning.
   * No work is detached past the bound.
   * The behavioural regression is the reviewer's two probes over the real adapter and
     runtime sources:
     * store contention, with the snapshot taken before the bound;
     * a slow source callback, which can no longer run inside the bound.
     Each probe either returns within the bound or reports `OutcomeUnknown` at it, with the
     slot and marker released.
   * The source-scan test stays, and gains a check that the runtime builds the snapshot
     outside `bounded_adapter_call`.
   * Residual, stated in the matrix: an endpoint `stat` on a hung network filesystem is not
     interruptible.
3. **Wave 3c** is one unit, `W3c-fix`, owning `crates/app/src/{setup,operations}.rs`,
   `crates/adapters/src/{integration,native_agent,onepassword}.rs`,
   `crates/runtime/src/service.rs` and the matching tests. ⟨§12.24⟩ It is now two units;
   see §12.24 item 9.

### 12.24 Rulings on the wave-3b escalations (orchestrator, 2026-11-03)

Sources: the three wave-3b unit reports and the integrator's report (workflow
`wf_4b438985-0b9`).
* check.sh exited 0 on two consecutive runs, with 1480 passed and 0 failed. The integrator
  fixed the pty test hang, a spawn-overlap test flake and a holder-release race
  (`release_if_held_by`, in one transaction).
* No `todo!()` remains, and the workspace lint `todo` is now `deny`.
* `heimdall run` and `heimdall connect` work end to end through the real binary and
  runtime against the loopback fixture sshd:
  * 1 MiB plus every byte value round-trip;
  * sshd accepts only the adopted key;
  * the decoy agent is never contacted.

1. **`connect` and observed aliases.** `inspect profiles` and `inspect destinations` list
   the catalog: profiles, and destinations with their alias and definition (`managed`,
   `observed`). They no longer answer `NOT_LISTED`. `connect` then accepts an observed
   alias that the catalog lists, under the same pre-launch check. Owners: W3c-ops (the
   listing in `operations.rs`) and W3c-run (`connect`'s use of it).
2. **A replayed bind is re-checked.** Before writing `launching`, `run` and `connect`
   confirm with one inspect that the binding is still `active`. A binding the holder pass
   already released is refused with the replayed result's code, and never launched. Owner:
   W3c-run.
3. **Expiry of setup and catalog decisions (amends §12.22 item 9).** No operation state is
   called `expired`. The operation settles `failed` with `CREDENTIAL_EXPIRED`, `next:
   new_work`, effect `none`, consistent with ADR-0006 and M01's grant expiry. The
   supervisor's `next_wake` includes the earliest pending decision deadline, so expiry is
   not delayed up to `max_idle_sleep`. Owner of the wake: W3c-ops.
4. **Pre-launch refusal provenance.** The contract's `ErrorDetail` gains an additive
   `entries: Vec<ConfigProvenance>`, serde default and skipped when empty. The fallback
   refusal fills it with the refused entries' file and line. Owners: W3c-ops (contract and
   schema) and W3c-run (filling it). W3c-run builds against that exact field name and
   type.
5. **U8 readings (accepted):**
   * `run` and `connect` send an interactive hello unless `--non-interactive` is given
     without `--allow-provider-interaction`;
   * `run` requires `--profile`;
   * `--work-id` defaults to the request ID, so a retry replays the same ensure and bind;
   * the pre-launch check also refuses when the alias's effective `IdentityAgent`, from
     the fresh static pass, differs from the pair's endpoint or is undetermined.
   * Residual, stated in §13: a holder with no start-time token reads as exited when the
     same query succeeds for the runtime's own process. A permission failure on the
     holder could therefore read as an exit. The holder is the same user's CLI process.
6. **W3b-consent readings.**
   * `Match command` makes a state undetermined where it can reach a relevant directive:
     **accepted**.
   * "A manual first adoption whose configuration does not activate P needs no decision"
     is **rejected**. §5.2: a first adoption always needs a decision, manual mode
     included, because the owner's own Include then activates P without another Heimdall
     decision. Owner: W3c-run, in `projection/plan.rs`, with a regression.
7. **Accepted as implemented:**
   * `RemoveProfile` narrows. New work naming the profile is `NOT_FOUND`. Grants, bindings
     and policies pinned to profile snapshots stay, as M01's snapshot pinning intends.
   * The shared-file edits and the `Cargo.lock` edges listed by the integrator.
   * The holder-release race fix.
   * The spawn-guard test serialization.
   * The probe's adaptation of `CatalogIdentity`. U9 may pass domain records instead.
8. **Catalog `DeclareInteraction` with a stale decision.** It is reissued as the setup
   driver does: a fresh pending record bound to the current fingerprint and endpoint.
   Owner: W3c-ops.
9. **Wave 3c, two units:**
   * **W3c-ops:**
     * §12.23 U01 and U02;
     * items 1 (listing), 3 (wake), 4 (contract) and 8 above.
     * Owns `crates/app/src/{setup,catalog,operations,error}.rs`,
       `crates/adapters/src/{integration,native_agent,onepassword}.rs`,
       `crates/runtime/src/{service,supervisor}.rs` (`next_wake` only), the contract's
       `ErrorDetail`, their tests and the schemas.
   * **W3c-run:**
     * items 1 (`connect`), 2, 4 (fill) and 6 above;
     * the U8 tests wave 3b did not write: `a27_scp_and_sftp_binary_with_unicode_and_spaced_paths`,
       `a27_git_clone_and_push_over_ssh_with_binary_blob`,
       `a11_confirm_constrained_native_key_refused_before_agent_contact`,
       `a11_inherited_confirm_constrained_fallback_refused_noninteractive_before_agent_contact`
       and `a11_interactive_connect_succeeds_after_provider_approval`.
     * Owns `crates/heimdall/src/{run_cmd,connect_cmd}.rs`, `crates/launch/**`,
       `crates/localenv/src/projection/plan.rs`, `tests/e2e/run_m02.rs` and the consent
       tests in `tests/integration/projection.rs`.
   * `tui_handoff_ctrl_z_stops_and_fg_resumes_as_one_job` stays with U10 (wave 4).

### 12.25 Rulings on the wave-3b code review (orchestrator, 2026-11-03)

Source: `tests/evidence/artifacts/review-m02-code/wave3b.md` (Codex, independent, fix first).
T01–T04 were each reproduced through production components and are accepted as defects. They
touch files wave 3c edits concurrently, so they are fixed in **wave 3d** after wave 3c
integrates.

1. **T01: the no-interaction checks cover every invocation profile.**
   * The pre-launch check evaluates the alias under `Shell`, `Exec(None)` and
     `Subsystem("sftp")`, the consent v3 profile set (§12.21 item 2), for both `run` and
     `connect`. It requires the selection to be cleared in every profile. An uncleared or
     undetermined selection in any profile refuses.
   * The non-interactive authentication probe evaluates the invocation it actually runs.
   * Regressions: exec-only and subsystem-only fallback identities, and an `IdentityAgent`
     override behind each, are refused before launch.
2. **T02: `%u` and `Match localuser` come from the account database.**
   * Every query builder takes `local_user` from the OS account (`sys::account_name()`,
     the lookup `LocalContext::local_user` uses), never from `USER` or `USERNAME`. That
     covers projection observe and preview (consent), the pre-launch check, the probes and
     doctor.
   * When the account cannot be established, `Match localuser` is `Unknown` and `%u` is
     unavailable. Both are undetermined, and neither is an empty name.
   * Regressions: `USER` unset, and `USER` set to another name.
3. **T03: an exclusive selection is accepted only through its declared endpoint.**
   * Before either success path, the authentication probe establishes the effective
     `IdentityAgent` with the T01 profile and requires it to equal the adopted identity's
     declared endpoint. An unknown or different endpoint refuses.
   * The pre-launch check already makes the same comparison (§12.24 item 5).
   * Regression: an exclusive selection that changes only `IdentityAgent`.
4. **T04: one live holder per binding.**
   * A launch whose binding already has a live holder that is not this process is refused
     before `launching`: `REQUEST_CONFLICT`, reason `binding_in_use`, `next:
     new_request_id`. The existing holder is not overwritten.
   * The check and the holder registration happen in one transaction, so two overlapping
     invocations cannot both pass.
   * Sequential retries, after the first holder has exited and been released, keep their
     current behaviour, governed by §12.24 item 2's active re-check.
   * Regression: the reviewer's two overlapping invocations. The second is refused and the
     binding stays active until the first exits.
5. **Wave 3d**, two units:
   * **W3d-select:** items 1–3. Owns `crates/heimdall/src/launch_flow.rs`,
     `crates/localenv/src/projection/{observe,plan}.rs` (query construction only),
     `crates/localenv/src/probe/**`, `crates/localenv/src/doctor.rs`,
     `crates/launch/src/eligibility.rs` and their tests.
   * **W3d-holder:** item 4. Owns `crates/heimdall/src/run_cmd.rs`,
     `crates/heimdall/src/connect_cmd.rs`, `crates/app/src/{holders,operations}.rs` (the
     holder registration only) and `tests/e2e/run_m02.rs` (the holder tests).

### 12.26 Rulings on the wave-3c escalations (orchestrator, 2026-11-03)

Sources: the two wave-3c unit reports and the integrator's report (workflow
`wf_69e1c65c-1d4`). check.sh exited 0 twice, with 1502 tests passed and 0 failed. §12.23 U01
and U02 are done, each with the reviewer's probe as a regression. §12.24 items 1, 3, 4
(contract), 6 and 8 are done.

1. **Ratified integrator edits:**
   * `Txn::profiles()` in the store, with `inspect profiles` listing the catalog under
     `items`, owner-only;
   * the mechanical `entries: Vec::new()` literals;
   * `ErrorDetail.entries` is filled on the envelope, not on `OpError`.
2. **U02 extension (ratified):** `bounded_adapter_call` turns an answer that arrives after
   its deadline into `OutcomeUnknown`.
   * Residual closed: `CredentialAdapter::read_sources` and `prepare_from` lose their
     default bodies, so every adapter must implement both. The testkit fake implements
     them trivially.
   * The source scan also checks the adapters' `prepare_from` for store and live-source
     reads.
   * Owner: W3d-holder.
3. **§12.24 item 2, completed:**
   * (a) A released binding is refused with `CREDENTIAL_EXPIRED`, `next: new_work`,
     resource `binding`, and a new reason **`binding_released`**, added to the contract's
     reason list. Owner: W3d-holder.
   * (b) `connect` does not bind, so the active re-check applies to `run` only. §12.24
     item 2 is amended.
4. **§12.24 item 4: the runtime's own refusal names its line.** The no-interaction refusal
   at `ensure` (`operations.rs` `interaction_refusal`) fills `ErrorDetail.entries` as the
   CLI pre-launch refusal does. Owner: W3d-select, with a targeted edit to that function.
   * m02-plan's wording is amended: the provenance is the refused `IdentityFile` line,
     which may lie inside `Host *`, not the `Host *` line.
5. **A changed managed alias always needs a decision, in manual mode too.** §5.2 already
   says so: a new or changed managed alias always needs a decision. An inactive P is no
   exception, because the owner's own Include later activates it without another decision.
   Owner: W3d-select (`plan.rs`), with a regression.
6. **`connect` with an observed alias** takes its static selection from the passive doctor
   pass (no local queries). Accepted for M02. U9 may add an observed-alias mode to
   `projection::observe`.
7. **Privacy: refusal data never shows the account home's absolute path.**
   * `path_display` canonicalizes both the path and the account home before stripping,
     so a home behind a symlink is still shown as `~/…`.
   * A path outside the home is shown as written in the configuration.
   * Regression: a home reached through a symlink, with `/var` against `/private/var` as
     on macOS. The user name never appears in `data.error.entries` or in the message.
   * Owner: W3d-select.
8. **Wave 3d** is therefore:
   * **W3d-select:** §12.25 items 1–3 and items 4, 5 and 7 above;
   * **W3d-holder:** §12.25 item 4 and items 2 and 3(a) above. It also owns
     `crates/app/src/ports.rs`, `crates/adapters/src/**`, `crates/testkit/src/lib.rs` and
     the contract reason module for those items.

### 12.27 Ruling on the wave-3c code review (orchestrator, 2026-11-03)

Source: `tests/evidence/artifacts/review-m02-code/wave3c.md` (Codex, independent, fix first).
U01 and U02 are closed, with discriminating regressions. S01, a medium finding, is accepted.

1. **S01: activation enforces fresh non-interactive eligibility.**
   * In the final activation transaction, a request that requires no interaction is
     refused with `INTERACTION_REQUIRED` when any pair's fresh store eligibility
     (`Facts::with_eligibility`) is false. That includes a declaration withdrawn, lapsed or
     changed after the adapter's snapshot, and a fallback clearance that no longer holds.
   * The refusal comes before the grant is activated or its binding created. Its reason
     and `next.provider_interaction` are those of the fresh eligibility (§7's results table).
   * The snapshot design is kept: this is a check against the store inside the commit
     transaction, not a read inside the adapter bound.
   * Regression: the reviewer's withdrawal interleaving expects `INTERACTION_REQUIRED`, no
     active grant and no binding.
   * Owner: the orchestrator, after wave 3d integrates, because both wave-3d units edit
     `operations.rs`.

### 12.28 Rulings on the wave-3d escalations; wave 4 (orchestrator, 2026-11-03)

Sources: the two wave-3d unit reports and the integrator's report (workflow
`wf_04c83924-030`). check.sh exited 0 twice, with 1526 tests passed and 0 failed. Every item of
§12.25 and §12.26 is done, and each of the 30 named proving tests exists and passed.

1. **`OpError.entries` (ratified; amends §12.26 item 1).** The runtime's ensure refusal
   crosses IPC as an envelope built from an `OpError`. `OpError` therefore carries
   `entries`; `detail()` emits them and `from_detail()` keeps them, so a replayed stored
   refusal names the same lines. It is additive on the wire. The justified
   `large_enum_variant` allowance on the runtime's `ServiceError` is accepted.
2. **The live holder (T04, ratified; amends §12.25 item 4).** The bind path has no
   liveness port, so a holder row on an active binding counts as live until the holder
   pass releases it.
   * A same-request retry within about one holder-pass interval of the first holder's exit
     is refused as `binding_in_use`.
   * After the release, it is refused as `binding_released`.
   * Both refusals fail closed. The m02-plan U0b row-3 text is amended accordingly.
3. **An unknown local account (T02 refinement).** `sshconf::eval::Query.local_user` becomes
   `Option<String>`. With `None`:
   * `Match localuser` and `Match user` are `Unknown`;
   * `%u` and `%r` are `TokenUnavailable`.
   Only the affected conditions are undetermined, not the whole configuration. The
   current whole-configuration reading fails closed and stays until this lands. Owner:
   W4-fix.
4. **Windows account lookup** (`sys::account_name` matching Win32-OpenSSH's `pw_name`) is
   **blocked** on a native Windows host. Until then the account is unknown on Windows,
   which fails closed. U11 closes it natively.
5. **`ensure` readiness covers every profile.** The runtime's no-interaction readiness, the
   projection observation it reads, clears the selection under `Shell`, `Exec(None)` and
   `Subsystem("sftp")`, as the pre-launch check does (§12.25 item 1). An API caller that
   uses `ensure` without the CLI then gets the same guarantee. Owner: W4-fix.
6. **A path outside the home** is shown as written in the configuration, not in its
   canonical form, as §12.26 item 7 says. Owner: W4-fix.
7. **Cleanup accepted:** the `binding_released` mapping moves into
   `launch_flow::confirm_binding_active`. Owner: W4-fix.
8. **S01 (§12.27)** goes to W4-fix as well, since it sits beside item 5 in `operations.rs`.
9. **Wave 4**, three units:
   * **W4-fix:** items 3, 5, 6, 7 and 8. Owns:
     * `crates/sshconf/src/eval.rs` (`local_user`) and its callers' query construction;
     * `crates/app/src/operations.rs` (activation and readiness only);
     * `crates/localenv/src/projection/observe.rs`;
     * `crates/localenv/src/doctor.rs` (`path_display` only);
     * `crates/heimdall/src/{launch_flow,run_cmd}.rs`;
     * their tests.
   * **W4-U9:** m02-plan U9, the CLI surface for setup, doctor, catalog and uninstall. It
     also takes the U9 items in §12.17 item 10, §12.19 item 7, §12.22 items 7 and 10
     (the uninstall leg of the held-operation test), §12.24 item 6 and §12.25 item 2's
     doctor wiring.
   * **W4-U10:** m02-plan U10, the first useful TUI, plus
     `tui_handoff_ctrl_z_stops_and_fg_resumes_as_one_job` (§12.24 item 9).

### 12.29 Ruling on the wave-3d code review (orchestrator, 2026-11-03)

Source: `tests/evidence/artifacts/review-m02-code/wave3d.md` (Codex, independent, fix first).
T01–T04 are closed, with discriminating regressions. R01 is accepted.

1. **R01: an exclusive selection counts only for the adopted key.**
   * The authentication probe accepts `Exclusive` only when the selected entry's
     fingerprint, read from the public-key file at the probe, equals the adopted catalog
     identity's recorded fingerprint, and the effective agent is its declared endpoint
     (§12.25 item 3).
   * A file that cannot be read or parsed, or a fingerprint that differs, refuses with
     `interaction_unknown` before anything runs.
   * The pre-launch check binds the same way. If it already does, that is confirmed by a
     test.
   * Regressions: replacing only the adopted public-key file, for managed and observed
     aliases, refuses with no client run; the unchanged-key control runs.
   * Owner: the orchestrator, after wave 4 integrates, because W4-fix edits
     `crates/localenv/src/probe/**` concurrently.

### 12.30 Rulings on the wave-4 escalations (orchestrator, 2026-11-03)

Sources: the three wave-4 unit reports and the integrator's report (workflow
`wf_e8039e4d-ddd`). The integrator's check.sh exited 0 twice, with 1623 tests passed. An
orchestrator rerun of every test, without stopping at the first failure, gave 1623 passed and
0 failed. One earlier orchestrator check.sh run had one failing test, unidentified because its
log was deleted unread, and did not recur; the next full runs watch for it. Wave 4 delivered:
* the CLI for setup, doctor, catalog and uninstall (U9);
* the first TUI (U10);
* §12.27 S01 and §12.28 items 3, 5, 6 and 7.

No M02 command answers "not available in this build" any more.

1. **A decided operation resumes in its own request's interaction mode (defect, fixed by
   the orchestrator).**
   * `Operations::decide` resumed every waiting operation with `interactive = false`. An
     attended, interactive ensure that waited for the owner's approval was therefore
     prepared as non-interactive. A real adapter then refused it (`INTERACTION_REQUIRED`,
     `interaction_unknown`) right after the owner approved. U9 observed this in an
     interactive `run`.
   * Each waiter now resumes with the mode its own stored request asked for. A request
     that cannot be read resumes non-interactive, which fails closed. Restart recovery
     still leads non-interactive, because no caller is attending then.
   * Regression: `model_operations::r1230_1_decided_operations_resume_with_their_own_interaction_mode`
     (mutation-checked). The testkit fake records each `prepare` call's `interactive`
     flag.
   * U9's `a01_personal_profile_without_repository` returns to the plan's wording, an
     undeclared key with one attended decision. Owner: W5-U11, with the exit suite.
2. **§12.29 R01 is fixed by the orchestrator.**
   * The authentication probe accepts either success path only when the adopted key file
     still holds the recorded fingerprint.
   * Regression: `probe::auth::tests::a_replaced_adopted_public_key_is_refused_before_anything_runs`,
     mutation-checked.
   * The pre-launch check's equivalent is `eligibility::tests::exclusive_needs_the_adopted_managed_entry`.
3. **Ratified integrator edit (safety):** in debug builds, `testcfg::isolate_projection`
   keeps a CLI-started test runtime off the account's real `~/.ssh`. With any test
   variable set, it uses the scratch SSH home or no projection. Production is unchanged.
4. **Wave-0 not-available helpers.** The helpers are retired with their dead-code
   allowances. The two wave-0 tests are repurposed to assert that **no** M02 command
   answers that text, so they are no longer vacuous. Owner: W5-U11.
5. **A bare `heimdall` on a TTY opens the TUI** (overview §3). Without a TTY, or with
   `--json`, it remains `status`. Owner: W5-U11.
6. **A plan that reports a conflict but changes nothing is refused by the setup driver**
   with `CONFIG_CONFLICT` and the conflict's reason. The CLI's refusal stays. A
   `managed_file_edited` conflict is resolved by `rollback` (which keeps the edited P as
   `ssh_config.hm-conflict-<gen>`, §5.5) or by `manual_mode`; `rerender` never
   overwrites it. Owner: W5-U11.
7. **The first-adoption restore column comes from the preview itself.** A first adoption's
   `SetupPlan` carries its aliases, with an empty restore state for each (§5.1). The
   `<state>/backups/ssh_config.<ts>.orig` copy of §5.5 is implemented. Owner: W5-U11.
8. **The S01 refusal's `next.provider_interaction.kind`** is the refused pair's fresh
   interaction kind, the same as the pre-launch check's. Where that kind is unknown, it
   is `unknown`. The two paths are aligned. Owner: W5-U11.
9. **No new `UnresolvedReason` for an unknown local account.** The doctor's finding
   wording is enough. Recorded in §13.
10. **The doctor's `config_files` listing and include-failure provenance** show the path
    as written, through a written-path accessor on `ConfigSet` (§12.28 item 6 residual).
    Owner: W5-U11.
11. **API changes ratified:**
    * W4-fix's removed and added probe/observe functions;
    * `ProjectionWriter::observe` answering the fail-closed view combined over every
      profile;
    * `Query.local_user: Option<String>`;
    * ratatui 0.30.2 and crossterm 0.29.0 entering the lock at their pins.
12. **Additive CLI gaps:**
    * `identity adopt --from-agent --fingerprint <fp>` chooses one listed identity;
    * replaying `setup apply --request-id` after the projection changed stays
      `REQUEST_CONFLICT`. That is correct; the CLI says so.
    Owner: W5-U11.
13. **Evidence-dependent partials** go to U11's records:
    * the A35 matrix: executables, fingerprints and counts; the offered-key check, which
      needs an sshd log of offered keys, through `HM_FIXTURE_SSHD_LOG`;
    * the TUI's first-frame latency.

### 12.31 Rulings on the wave-4 code review (orchestrator, 2026-11-03)

Source: `tests/evidence/artifacts/review-m02-code/wave4.md` (Codex, independent, fix first). S01
and R01 are closed. Q01–Q04 are accepted. They are fixed in **wave 5b**, after wave 5
integrates and before the final native runs at the M02 exit build.

1. **Q01: purging state needs its own attended confirmation (Q6).**
   * `uninstall --purge-state` shows what it will discard: the state database with counts
     of operations, grants, decisions and catalog records, the backups, and any quarantine
     or conflict copies it would remove.
   * It requires an attended typed `y`/`yes`. Non-TTY, `--non-interactive`, EOF,
     interruption, timeout and any other answer keep everything and exit 3,
     `INTERACTION_REQUIRED` (client-side, no `decision_ref`).
   * The `--allow-config-commands` exception does not apply here.
   * Regressions: refused without a typed yes, and done with one.
2. **Q02: a skipped authorization never authorizes.**
   * The authorization step reports one of two outcomes: authorized (a typed yes, or
     `--non-interactive` with the flag, as documented) or not authorized.
   * "Nothing runnable" and "the configuration could not be read" are not authorized.
     Every real-tree level of that invocation is then declined (`ProbeOutcome::Declined`,
     with the reason), whatever a later pass sees.
   * Regression: the reviewer's unreadable-to-readable interleaving runs no evaluation.
3. **Q03 and Q04: the owner can see everything before typing yes.**
   * Decision and authorization content is never truncated. Long cells wrap, the layout
     falls back to stacked columns when needed, and the content scrolls (arrows,
     PgUp/PgDn, Home/End) while the prompt stays fixed.
   * A modal shows how much is left below. A typed `yes` is accepted only once the last
     line of the content has been on screen; before that the answer is refused, with the
     modal saying so.
   * Regressions, at 120×40 and 40×12:
     * a diff whose meaningful suffix lies beyond the cell width can be read in full;
     * the last entry of a 15-construct inventory can be reached;
     * `yes` is refused until it has been shown.
4. **The intermittent pipe test** (`heimdall-launch`
   `meta::tests::fd_protocol_writes_whole_lines_and_epipe_is_an_error_not_a_signal`) failed
   once in the reviewer's run and very probably once in the orchestrator's (§12.30). The
   wave-5b unit diagnoses its cause and fixes the test or the code, with evidence. A flaky
   test is never retried away or ignored. Hypothesis to check, not a finding: another
   test's child process inherits the pipe's read end.
5. **Wave 5b:** one unit, `W5b-fix`, owning `crates/heimdall/src/{uninstall_cmd,doctor_cmd}.rs`,
   `crates/heimdall/src/tui/{view,model}.rs`, `crates/launch/src/meta.rs` and their tests.
   Then the native runs are repeated at the resulting exit build.

### 12.32 Rulings on the wave-5 escalations and native runs; wave 5c (orchestrator, 2026-11-06)

Sources: the four wave-5 unit reports, the integrator's report and the native-run report
(workflow `wf_aec0e2ec-a5e`). check.sh exited 0 three times for the integrator, with 1665
tests passed and 0 failed. Every item of §12.30 and §12.31 is done, except item 6's
`manual_mode` (item 1 below).
* The intermittent pipe test is diagnosed and fixed (§12.31 item 4). Cause: a sibling test's
  `spawn()` copies every open descriptor into the child until its exec. Failures were 44 in
  1000 runs before the fix and 0 in 1000 after.
* The native runs at bcad82de plus the uncommitted tree:
  * macOS: 1664 passed, 1 failed (`a27_ctrl_c_reaches_child_once`, intermittent);
  * Linux devbox: 1519 passed, 29 failed (mostly a test-harness defect; four real
    findings);
  * Windows and WSL: blocked, because the PC's WSL SSH endpoint did not accept
    connections.
* Fourteen `m02-*.json` records were written, all `blocked` under the lowest-row rule.

1. **An edited P is resolved by `rollback` only (amends §12.30 item 6).** Manual mode
   concerns the user file, not Heimdall's own P, so it is not a resolution of
   `managed_file_edited`. `rollback` keeps the edited P as `ssh_config.hm-conflict-<gen>`
   (§5.5), and a later apply needs a decision. Item 6 is done.
2. **The §5.5 snapshot is the writer's, not the CLI's.** `ProjectionConfig` gains
   `state_dir`.
   * The writer copies the original user file to `<state>/backups/ssh_config.<ts>.orig`
     before its first user-file step, through `sys::create_owner_only_exclusive`. It
     copies the original global Git file the same way, to
     `<state>/backups/gitconfig.<ts>.orig`.
   * API callers and the TUI's held repairs are covered as well.
   * The CLI hook is removed, keeping its stale-base refusal as a writer precondition.
   * Owner: W5c-app.
3. **`HM_REPO_ROOT` is the harness interface for repository paths.** Tests that read the
   repository (schemas, golden files, snapshots, the hook binary) resolve it through one
   testkit function. It honours `HM_REPO_ROOT` at run time and otherwise falls back to the
   compile-time path. The native harnesses set it, so those tests run on Linux and
   Windows. `case-index.json`'s `build_host_paths` then shrinks to the tests that truly
   need the build host. Owner: W5c-harness.
4. **Windows coverage of the CLI cases.**
   * The `--json` and `--non-interactive` cases of `cli_m02` (uninstall, doctor, setup
     preview and status, catalog) run on every platform.
   * The pty cases are `platform_only` macOS and Linux, with a rationale, as M01 did for
     its pty cases (ADR-0006 §13.13 item 5).
   * Windows interactive confirmation is the pseudoconsole drivers' row, which waits on B5.
   * Owner: W5c-harness.
5. **A plan whose diff does not fit is refused, never cut.** A preview whose full diff
   exceeds `MAX_DIFF_BYTES` is refused before anything is journaled:
   `CAPABILITY_UNAVAILABLE`, reason `plan_too_large`. No client ever receives a truncated
   diff (ADR-0006 §3.1; the Q03 class). Owner: W5c-app.
6. **The e2e pty keeps its window size.** `Pty` holds its slave descriptor for its
   lifetime, so the cases that open it at 40×120 or 24×80 really run at that size. The
   affected cases are re-run, and their assertions are corrected where the real size
   changes them. Owner: W5c-harness.
7. **Q01's prompt counts every table it discards.** The store gains read-only per-table
   counts. The prompt shows operations, grants, decisions, catalog records, events and
   idempotency records. Owner: W5c-app.
8. **Ratified:**
   * Q01 confirms before the rollback, so `--non-interactive uninstall --purge-state`
     exits 3 whether or not the rollback would complete;
   * the TUI discards a `yes` typed before the end has been shown;
   * the integrator's `stop_runtime` fix waits for `instance.json` to be removed;
   * check.sh's test step uses `--no-fail-fast`;
   * the TUI wrapping property uses proptest.
9. **`a27_ctrl_c_reaches_child_once`** failed on macOS natively and in two harness runs.
   It is diagnosed and fixed at its cause, as §12.31 item 4 was. A retry or `#[ignore]`
   is not a fix. Owner: W5c-harness.
10. **Harness defects, all fixed by W5c-harness:**
    * the e2e `Pty::start` helpers clear the environment and so lose `HEIMDALL_E2E_BIN`;
      they pass it explicitly;
    * `run-macos.sh` puts its scratch under `/tmp`, because the per-user TMPDIR
      overflows `SUN_LEN`;
    * `a27_exec_failure_with_failed_meta_write_is_indeterminate` opens its FIFO with a
      bound;
    * `run-windows.sh` redacts before it exits on an unreachable host;
    * host-name redaction replaces whole words only;
    * the evidence generator does not count tests of a platform the run marks
      unavailable.
11. **OpenSSH 9.6p1 (the devbox client) disagrees in three ways.** The evaluator gates
    these on the client version (§12.15 item 4):
    * (a) a client that refuses `Match sessiontype` makes such a file invalid for that
      client (`invalid`, nothing determined);
    * (b) `${VAR}` expansion of `User` and `SetEnv`, and of `Include`, applies only to
      clients that do it. The version boundary is taken from the corpus test on both
      clients, never assumed;
    * (c) the first-pass and final-pass `IdentityFile` difference is diagnosed against
      9.6p1's `ssh -G` and fixed or gated.
    * An unknown client version takes the strictest reading.
    * The corpus test runs on both clients. W5c-sshconf may run `ssh -G -F <scratch>` on
      the devbox, in a scratch directory, for this.
12. **Default identities: the superset rule is restored (amends §12.17 item 9).**
    9.6p1's default list contains `id_xmss` and `id_dsa`, which Heimdall's six-name list
    lacks. A list that is not a superset can let an unknown default key be offered, which
    breaks fail-closed. `DEFAULT_IDENTITIES` becomes the union over the supported clients
    and the pinned manuals. The per-client lists are recorded in the matrix. Owner:
    W5c-sshconf.
13. **git 2.43.0 refused both Git items as `unmanageable_file`.** This is diagnosed on the
    devbox in scratch. If Heimdall misreads git 2.43, the fix is in Heimdall. If git 2.43
    lacks a behaviour Heimdall needs, the Git item is gated on the git version with its
    own reason and recorded in the matrix. Owner: W5c-git.
14. **The Docker supplementary arm64 row is `deferred_with_decision`.** It is
    supplementary and not part of the exit evidence. Linux arm64 stays blocked on B9, and
    the matrix says not tested.
15. **Windows and WSL: the remote route into WSL is gone.** A read-only diagnostic on the
    PC, run through T3 with no elevation and no change, found the following:
    * Ubuntu (WSL 3.0.3, systemd) is running, and its `sshd` listens on `0.0.0.0:2222`.
    * WSL is in NAT mode, and the only Windows-side forward of 2222 is `wslrelay` on
      `127.0.0.1` (loopback only).
    * There is no portproxy rule, and nothing listens on 2222 for other machines.
    * Windows' own `sshd` holds port 22.

    Restoring a remote route needs one of the following, each requiring elevation or
    `wsl --shutdown`, which the delegation does not allow the orchestrator:
    * mirrored networking with a Hyper-V firewall rule;
    * an elevated `portproxy` with a firewall rule;
    * Tailscale inside WSL.

    That is an **owner input**. Meanwhile, the Windows run may go through a T3 agent on the
    PC itself (local mode, item 16), if the PC has the toolchain for it. That keeps the
    same scratch-only, non-elevated rules, and the fixture `sshd` stays on WSL loopback.
16. **Wave 5c**, four units, then the integrator, then the native runs at the resulting
    exit build:
    * **W5c-sshconf:** items 11 and 12;
    * **W5c-git:** item 13;
    * **W5c-app:** items 2, 5 and 7;
    * **W5c-harness:** items 3, 4, 6, 9 and 10, plus the **Windows local-mode runner**
      (item 17).
17. **Windows local mode.**
    * The PC has rustup with Rust 1.98.1 (msvc), Visual Studio Build Tools 2026,
      PowerShell 7 and Git 2.55. WSL has `sshd`, OpenSSH 9.6p1 and git 2.43.
    * `tests/native/m02/run-windows-local.ps1` runs **on the PC**, launched by a T3 agent
      there. Its steps:
      1. Clone the public repository at the exit commit into a fresh scratch directory.
      2. Install the pinned toolchain into that scratch directory (`RUSTUP_HOME` and
         `CARGO_HOME` point there), never into the owner's rustup.
      3. Build the workspace tests natively for `x86_64-pc-windows-msvc`.
      4. Start the fixture `sshd` in WSL scratch on `127.0.0.1` through `wsl.exe`.
      5. Run every test binary and the e2e suites with timeouts and real exit codes.
      6. Record `ssh -V` (Windows and WSL), `git --version` and the toolchain.
      7. Redact `<winuser>`, `<winhost>`, `<winhome>` and SIDs; scan for canaries.
      8. Write one results bundle with per-test results in the format `m02-evidence.py`
         reads.
      9. Remove the build and toolchain scratch and the WSL scratch, keeping only the
         bundle until it has been imported.
    * Nothing is elevated, and no service, firewall, registry, ssh-agent, `~/.ssh` or
      WSL configuration is touched. There is no `wsl --shutdown`.
    * The bundle reaches the build host inside the T3 agent's report as gzip and base64,
      and is decoded into `tests/evidence/artifacts/m02/<label>/windows/`.
    * The evidence names the target honestly: native msvc build and run on the Windows 11
      x64 PC, Windows OpenSSH 10.3p1. The plan's in-box 9.5p2 was not present.
    * The orchestrator runs it after wave 5c integrates, together with the macOS and
      devbox runs.

### 12.33 Rulings on the wave-5 code review (orchestrator, 2026-11-06)

Source: `tests/evidence/artifacts/review-m02-code/wave5.md` (Codex, independent, fix first).
* Q01–Q04 are closed, and the pipe-test fork gate is sound.
* All 14 m02 records are consistent with the lowest-row rule, and regenerating them
  reproduced them exactly.
* P01 and P02 are accepted. Both lie in `tests/native/m02/**`, which W5c-harness edits
  concurrently, so the orchestrator fixes them after wave 5c integrates and before the
  exit-build native runs.

1. **P01: the harness tears down only what it created.**
   * `run-macos.sh` takes ownership of the Docker fixtures only after `up.sh` has succeeded.
   * `up.sh` reports "fixtures already exist" with its own exit code. On that code the
     harness leaves everything untouched, and the macOS rows that needed the fallback
     are `blocked`, naming the conflict.
   * Cleanup after a partial startup of this run's own fixtures still runs.
   * Regression: `M17b`. A stubbed refusal leaves the pre-existing fixtures in place, runs
     no `down.sh`, exits 3 and records `blocked.txt`. M17b fails when ownership is taken
     before `up.sh` returns.
   * `up.sh` exits 3 for both "already exist" refusals: containers or networks, and the
     image. It does so before it creates anything.
   * *Done by the orchestrator, 2026-11-06.*
2. **P02: Git in the harness reads no owner configuration.**
   * Every scenario Git invocation (init, add, commit, ls-remote, clone) runs with `HOME`
     and `XDG_CONFIG_HOME` both inside the scratch home, and with `GIT_CONFIG_NOSYSTEM=1`.
     Both of Git's global lookups, `$HOME/.gitconfig` and `$XDG_CONFIG_HOME/git/config`,
     are then scratch files.
   * An empty `GIT_CONFIG_GLOBAL` is not used, because it would also bypass the scratch
     home's own global file, where setup writes B_git.
   * `git --version` reads no configuration.
   * Regression: `S17` in `tests/native/m02/selftest.sh` gives the scenario a foreign
     `XDG_CONFIG_HOME` whose template and `hooksPath` hooks would leave a marker. The
     marker never appears, and S17 fails when the pin is removed.
   * *Done by the orchestrator, 2026-11-06.*

### 12.34 Rulings on the wave-5c escalations; wave 5d (orchestrator, 2026-11-06)

Sources: the four wave-5c unit reports and the integrator's report (workflow `wf_6ad18190-1ba`).
check.sh exited 0 three times, with 1704 tests passed and 0 failed. Every §12.32 item assigned
to wave 5c is done.

**Outcomes worth recording:**
* §12.32 item 13: git 2.43.0 behaves like 2.54.0. The refusal came from the devbox's umask
  of 0002, which made the fixture's Git directory group-writable, and the writer correctly
  refuses that. Preview now runs the writer's own manageability check on the global Git file
  (`check_global_file`). An account with umask 0002 therefore gets the Git item as
  `not_applicable` (`unmanageable_file`), named at preview, while SSH still applies.
* §12.32 item 9: `a27_ctrl_c_reaches_child_once` was a test defect. A test binary started
  with SIGINT ignored passed that disposition to the pty child's shell, which cannot trap a
  signal ignored on entry. Failures were 100 in 100 before the fix and 0 in 200 after.
* §12.32 item 11 found more 9.6p1 gaps than ruled: `Match command` and `Match version` are
  refused, `RefuseConnection`, `VersionAddendum` and `WarnWeakCrypto` are unknown keywords,
  and `%` tokens in `Include` are taken literally. Each is gated on the observed client
  version (`heimdall_sshconf::client::OBSERVED_CLIENTS`).

1. **Client version in passes (escalation A).** A pass takes the version of the selected
   `ssh` client from the client inventory. `run`, `connect` and setup query it with
   `ssh -V`, a permitted local query.
   * Where local queries are off (`doctor --no-local-exec`) or the version query fails,
     the strictest reading applies: gated criteria refused, `${VAR}` expanding. That fails
     closed. Recorded in the matrix: on such a pass, a user `Match sessiontype|command|version`
     makes the selection undetermined.
2. **The extra gating is ratified (escalation B).**
   * A client the corpus has not observed takes the strictest reading of every gated
     construct.
   * Windows OpenSSH 10.3p1 therefore reads `command`, `version` and the three keywords
     as refused until a Windows corpus run records otherwise.
   * U11's Windows local-mode run includes the corpus test for exactly this reason.
3. **Agent-endpoint discovery and Include expansion (escalation C)** is
   `deferred_with_decision` to M03. `agents::identity_agent_references` lists candidate
   endpoints for the doctor only and grants nothing. An Include expanded where the client
   would not expand it can list an extra candidate, never hide one. Recorded in §13.
4. **The matrix and design documents are the orchestrator's (escalation D).**
   * They are updated with the M02 exit record: per-client default identity lists, the
     gated constructs, the encoding observations for 10.5p1 and 9.6p1, the umask-0002
     Git outcome, `plan_too_large`, and the writer-owned snapshots.
   * The §5.5 text gains the writer-owned `gitconfig.<ts>.orig`.
5. **Edits outside owner paths are ratified (escalation E):**
   * W5c-app: `cli.rs`, `runtime/service.rs` and `testcfg.rs` (`with_state_dir`), and
     `contracts/m02.rs`;
   * W5c-harness: the testkit dev-dependencies in contract, domain, launch and sshconf,
     and the four lock lines.
6. **Snapshots without `state_dir` (escalation F).** Every production constructor of a
   writing `ProjectionConfig` (the runtime service and the debug test configuration) sets
   `state_dir`. A guard test that scans the source for writing constructors without it is
   added (W5d-app). Refusing an edit without `state_dir` is left for M03 hardening and
   recorded in §13.
7. **Rollback and uninstall must never be blocked by size (escalation G).**
   * The diff of a plan that **removes** Heimdall's own files (P, P_git, key files) shows
     each removal as a summary: name, line count and SHA-256 of the removed content.
     Their content was shown in full when the owner approved it.
   * Changes to files the owner owns (the user SSH configuration, the global Git file)
     are always shown in full. Only those count toward `MAX_DIFF_BYTES`.
   * A plan whose owner-file changes alone exceed the bound is still `plan_too_large`.
   * Regression: a rollback of a P well over 64 KiB is previewed and applied, while a
     too-large owner-file change is refused.
   * Owner: W5d-app.
8. **Git follow-ups (escalation H).**
   * (1) After the Git item is applied, `observe_global` counts Heimdall's own P_git
     through the include as a user `core.sshCommand`. A re-preview then reports
     `git_ssh_command_present`, and an update or re-render can never be planned. Values
     whose origin is P_git are Heimdall's own and do not make the item not applicable.
     Regression: apply, change an alias, re-preview, and an update is planned.
   * (2) `plan_git_rollback` runs the same manageability check at preview as apply does.
   * Owner: W5d-git.
9. **§12.33 P01 and P02** are fixed by the orchestrator in the same wave.
10. **Scan note (escalation J):** the public repository URL, which contains the
    repository owner's login, is already public. It is allowed in committed files; the
    pre-push scan treats it as expected.
11. **Wave 5d:** W5d-app (items 6 and 7) and W5d-git (item 8), with the orchestrator on
    P01 and P02, then the exit build and the native runs.

### 12.35 Rulings on the wave-5c code review (orchestrator, 2026-11-06)

Source: `tests/evidence/artifacts/review-m02-code/wave5c.md` (Codex, independent, fix first).
N01–N05 are accepted.

1. **N01: an Include whose expansion depends on unestablished client behaviour is opaque.**
   This amends §12.32 item 11 and §12.34 item 1. "Strictest" means *undetermined*, not one
   of the two readings.
   * Gates of the first kind (a construct is refused or accepted) take the reading that
     refuses.
   * Gates of the second kind (two different results) make the affected value
     undetermined: `%` tokens or `${VAR}` in `Include`, `User` or `SetEnv` on a client whose
     version is unknown or unobserved.
   * For an Include, the argument is recorded as unresolved, with reason
     `client_behaviour_unknown`, and an opaque point is added, as for an
     environment-dependent Include.
   * Regression: the reviewer's `inc-%h.conf` case is undetermined for an unknown version,
     and the model test's expectation is corrected.
   * Owner: W5e-sshconf.
2. **N02: an existing snapshot must be a valid one.**
   * The writer opens `<state>/backups` without following links and refuses a symlink,
     non-directory, foreign owner or group- or other-writable directory.
   * It accepts an existing `ssh_config.*.orig` only as a regular, owner-owned file of
     mode 0600 that it opened without following links.
   * It refuses any other entry with that name before the first user-file edit,
     `unmanageable_file`, and names it. The source is read without following links too.
   * The same rules apply to `gitconfig.*.orig`.
   * Regressions: the reviewer's directory and symlinked-backups cases refuse, and a
     valid snapshot is accepted.
   * Owner: W5e-snapshot.
3. **N03–N05, harness and importer:** fixed by the orchestrator.
   * N03: the importer validates every persisted field, the label included, against the
     same rules as the file bodies. It also rejects private-key armor and unredacted home
     paths. The runner redacts its metadata before serializing it.
   * N04: input and compressed sizes are bounded, and decompression is incremental, with
     a stop at `MAX_PAYLOAD + 1`.
   * N05: the toolchain install and the builds pin `TEMP` and `TMP` to the run's scratch
     temporary directory.
   * *Done by the orchestrator, 2026-11-06*:
     * the importer's `sensitive()` covers every file body and the label. It adds
       private-key armor and unredacted Windows, WSL, Unix and macOS home paths;
       placeholders and Windows' own profile folders are accepted.
     * Sizes are bounded, and inflating is incremental, with the stop at
       `MAX_PAYLOAD + 1` (`zlib.decompressobj`).
     * The runner redacts its label, and `Get-ToolEnvironmentOverrides` pins `TEMP`, `TMP`
       and `TMPDIR`; runner self-test E01.
     * Regressions in `test_m02_evidence.WindowsBundle`. Each was mutation-checked: without
       the label check the label cases fail, and with unbounded inflating the bound test
       fails.

### 12.36 Rulings on the wave-5e escalations (orchestrator, 2026-11-06)

Sources: the two wave-5e unit reports (workflow `wf_485f9ce9-99c`). N01 and N02 are implemented,
with regressions that the units mutation-checked (5 and 10 mutants).

1. **Per-fact gating (ratified, stricter than §12.35 item 1's wording).** A client row that
   records nothing for a fact does not settle it. So `%` in `Include`, `User` or `SetEnv`
   on OpenSSH 10.3p1 is undetermined until a corpus run on 10.3p1 records it; the Windows
   local-mode run includes that corpus test. `${VAR}` on 10.3p1 stays determined as
   expanding, because that fact is recorded.
2. **An Include made opaque by unknown client behaviour** follows the environment-dependent
   Include exactly (ratified).
   * The opaque point appears in `executing_constructs`, so an authorization prompt says
     that an unread part may run commands.
   * `unreadable_includes` does not list it, and a `Match exec` inside the unread file is
     not recorded.
   * That residual is the same as for `${VAR}`, and is stated in §13.
3. **`User u%h` on a client observed to expand tokens** stays determined as written. The
   value is deterministic per alias, and the digest binds it as written. Not a defect.
4. **N02 details (ratified):**
   * the refused entry is named in the writer's error, and the item outcome carries
     `unmanageable_file`;
   * the copy is made relative to the validated directory handle (create-new, then a
     no-replace rename) instead of the path-based `create_owner_only_exclusive`. That is
     stronger, and amends §12.32 item 2. A state directory on a filesystem without a
     no-replace rename refuses the edit (`unmanageable_file`), which is recorded in the
     matrix;
   * refusal is per item: an invalid `gitconfig.*.orig` refuses only the Git item;
   * an existing snapshot must also have one link, and every matching entry must be valid.
5. **Process hygiene:** a test binary from a unit's earlier run, blocked on a since-fixed
   FIFO test, was found by exact PID, parent and start time, and stopped by the
   orchestrator. Its cargo parent finished its remaining targets.
6. **e2e fixture:** `tests/e2e/cli_m02.rs` `plant_backup` creates its planted snapshot with
   mode 0600, so later tests that edit the user file are not refused by N02. Fixed at
   integration.

### 12.37 Rulings on the wave-5d escalations; wave 5f (orchestrator, 2026-11-06)

Sources: the two wave-5d unit reports and the integrator's report (workflow `wf_fee3f6a2-e53`).
check.sh exited 0 twice, with 1744 tests passed and 0 failed.
* §12.34 item 7: a removal of Heimdall's own file is one summary line,
  `~ removed <name>: <N> lines, sha256 <hex>`. Owner files are shown whole, and only they
  count toward the bound. A rollback and an uninstall over a 94 KB P apply.
* §12.34 item 6: the `state_dir` guard is in place, with one reviewed passive exception,
  `launch_flow::static_config`, which its test confines to read-only callers. Ratified.
* §12.34 item 8: done; Heimdall's own P_git value no longer blocks a re-preview.

1. **Doctor and Heimdall's own Git value.**
   * The doctor uses `observe_global_for` with P_git's path. A value reached once through
     an intact B_git is Heimdall's own: it is reported as the projection's Git selection,
     never as `git_ssh_command_present`.
   * A user value elsewhere is still reported, with its origin.
   * Owner: W5f-git.
2. **`git_user_value_shadowed` is emitted** (m02-plan U4,
   `git_xdg_created_after_apply_shadowed_value_reported`; §5.6).
   * When Heimdall's own value is the effective one (Git's last occurrence wins) and a
     user `core.sshCommand` exists in another global file, the doctor reports
     `git_user_value_shadowed` with both origins. Their values are never shown, only
     digests, as the observation records them.
   * When the user's value wins, the item is `not_applicable` as before.
   * The named test asserts the finding.
   * Owner: W5f-git.
3. **A rollback finds B_git where it was written.**
   * `plan_git_rollback` reads the Git item's projection record for the path of the file
     its B_git step wrote, and plans the removal there.
   * When the record names no path, for a record written before this change, both global
     files are searched, and exactly one intact block with Heimdall's marker must exist;
     otherwise the item is manual mode.
   * Regression: B_git in `~/.gitconfig`, the XDG file created after the apply, then a
     rollback, after which `~/.gitconfig` is byte for byte the original.
   * Owner: W5f-git.
4. **Documentation:**
   * `contract::setup::FileChange.diff`'s doc comment, and so the exported schema
     description, states the summary-line form for a removal of Heimdall's own file
     (W5f-git, regenerating the schemas).
   * §5.1, §5.6 and §5.8 are amended here (item 5).
   * The matrix records the summary lines and the new Git behaviour with the exit record.
5. **Amendments:**
   * §5.1: a removal of Heimdall's own file is shown as a summary line.
   * §5.6, Applicability: P_git's own value, reached once through an intact B_git, does
     not make the item not applicable.
   * §5.8: the Git update arm obeys `managed_file_edited`. A rollback preview checks the
     global Git file's manageability and reports `unmanageable_file` as a manual reason
     with a problem finding.
6. **Native scenario expectations:** the orchestrator checks `tests/native/m02/**` for a
   scenario that expects a second `setup --include-git` to report `git_ssh_command_present`,
   before the exit-build runs.

### 12.38 Rulings on the wave-5d/5e code review (orchestrator, 2026-11-06)

Source: `tests/evidence/artifacts/review-m02-code/wave5de.md` (Codex, independent, fix first).
P02, N01, N02, N05, the removal summaries and the Git re-preview are closed. L01–L04, all in
the harness and the importer, are accepted and fixed by the orchestrator.

1. **L01: the Docker fallback is opt-in and exclusive.**
   * `run-macos.sh` no longer falls back to the shared M00 Docker fixtures by default:
     `HM_DOCKER_FALLBACK=1` must be set. Without it, a fixture `sshd` that cannot start
     makes the rows that need it `blocked`.
   * With it, the harness first takes an exclusive ownership lock, an atomic `mkdir` of
     `tests/fixtures/ssh/runtime.owner.lock`, and holds it until its cleanup has run.
   * `up.sh` returns 3 for every "already exist" refusal, including the image check
     after the pull.
   * The harness tears down only when it holds the lock and `up.sh` did not refuse.
   * Residual, stated in the harness header: a non-M02 caller of `up.sh` does not take the
     lock, so the opt-in is for a host with no other fixture user.
   * Regressions:
     * a refusal (3) after the preflight runs no teardown;
     * a held lock blocks the run without touching anything;
     * the default run never starts Docker.
2. **L02:** the runner counts and masks canaries in its metadata, together with the file
   bodies, and fails the run on any it finds. Runner self-test check E02.
3. **L03:** only exact system profile components are exempt (`Public`, `Default`,
   `Default User`, `All Users` and `Shared`, followed by a separator or the end of the
   component). `Public-Alice` and `Default.Bob` are rejected.
4. **L04:** the importer's command line reads at most `MAX_REPORT + 1` bytes from the open
   file and refuses more, before decoding. A CLI-level regression checks the amount read.
5. *Done by the orchestrator, 2026-11-06.* Each fix was mutation-checked, and the harness
   self-test gives 274 passed, 0 failed.
   * L01: self-test cases M16b, M17b, M17c and M17d. M17c fails with a non-exclusive lock.
   * L02: runner self-test check E02.
   * L03 and L04: `test_m02_evidence.WindowsBundle`. The word-boundary form fails the
     Public/Default cases, and an unbounded read fails the CLI test.
   * The macOS home rule no longer matches a drive-letter path, so `C:/Users/...` is judged
     by the Windows rule only, a gap the new tests found.

### 12.39 Rulings on the wave-5f escalations; wave 5g (orchestrator, 2026-11-06)

Source: the wave-5f unit report (workflow `wf_ebca271f-51b`). check.sh exited 0 twice, with 1755
tests passed and 0 failed. §12.37 items 1–4 are done, each mutation-checked (12 mutants).

1. **`ItemRecord.include_file` is ratified.** It is additive and serde-defaulted, so an old
   record reads back as `None`. The writer fills it from the written `git_include` step, and
   the sink keeps it across a P_git-only update and empties it on rollback.
2. **Readings ratified, for a record without a path:**
   * exactly one block in total is used where it is;
   * a single edited block stays the `marker_edited` conflict;
   * no block removes P_git alone;
   * more than one block is manual mode (`marker_duplicated`).
3. **The re-preview uses the recorded file too (the twin of §12.37 item 3).** `plan_git_apply`
   looks for B_git in the file the record names, with the same fallback as the rollback, so
   a second `setup --include-git` after the XDG file appears can plan an update. Owner:
   W5g-git.
4. **The rollback consent sees the shadowed case.** When Heimdall's value is the effective one
   and a user value sits in another global file, a rollback changes Git's effective value
   from Heimdall's to the user's. The Git item's before and after selections must say so,
   and §5.2 applies: a rollback that exposes a value the owner's configuration gained after
   the apply decision needs a decision. Treating it as "no change" was not fail-closed.
   Regression: shadowed case, then a rollback preview, and a decision is required. Owner:
   W5g-git.
5. **Shadowing needs a local query.** `git_user_value_shadowed` needs
   `git config --show-origin`, so with `--no-local-exec` the doctor reports nothing about
   shadowing. Stated in the matrix.

### 12.40 Ruling on the wave-5f code review (orchestrator, 2026-11-06)

Source: `tests/evidence/artifacts/review-m02-code/wave5f.md` (Codex, independent, fix first). The
wave-5f Rust changes are sound, and L01, L02 and L04 are closed.

1. **K01: an exempt system profile is an exact component.** The name must be followed by a
   separator, a quote, a bracket or the end, never by whitespace, which can sit inside a
   personal name. The longer names (`Default User`, `All Users`) are tried first.
   `Public Alice`, `Default User.Alice` and `Shared Alice` are rejected, and `Default User`
   and `All Users` are accepted.
   *Fixed by the orchestrator, 2026-11-06*: regressions in `test_m02_evidence.WindowsBundle`,
   which fail with whitespace allowed.

### 12.41 Rulings on the wave-5g escalations (orchestrator, 2026-11-06)

Source: the wave-5g unit report (workflow `wf_d87f0ae7-de4`). check.sh exited 0 twice, with 1760
tests passed and 0 failed. §12.39 items 3 and 4 are done, each mutation-checked (9 mutants).

1. **The apply searches when the recorded file holds no block (ratified).** If the owner moved
   B_git, or its file is gone, the re-preview searches both global files with the §12.37
   item 3 fallback, rather than inserting a second block beside the moved one.
2. **The rollback trusts the recorded file (accepted as a residual).** When the recorded file
   no longer holds a block, the rollback removes P_git alone. A block the owner moved to the
   other global file stays there, and Git skips an include whose file is missing. Recorded
   in §13.
3. **A first adoption reuses one Heimdall-marked block found in the other global file
   (ratified).** This applies only when that block is intact, with the bytes rendered for
   P_git; it is used where it is instead of inserting a second.
4. **§5.6 Rollback is amended** to state the shadowed case (done in §5.6 above).
5. **Residuals recorded in §13:**
   * the update arm does not detect an intact-shaped B_git whose target was edited to
     another file, when Heimdall's value is not reached;
   * a user value only in a conditional include that `git config` does not follow outside a
     repository is read conservatively, and requires a decision.

### 12.42 Rulings on the wave-5g code review (orchestrator, 2026-11-06)

Source: M02-W5g-code-review (Codex GPT-6.1 Sol, independent;
`tests/evidence/artifacts/review-m02-code/wave5g.md`), range `cb5139e4..1f5b8156`: fix first,
R01–R03. Each was reproduced by the reviewer, and the orchestrator fixed each and
mutation-checked the regression.

1. **R01: only the persistent scopes decide who wins.** §5.6 setup selections cover the
   system and global files. A command-scope value (`-c`, `GIT_CONFIG_COUNT`,
   `GIT_CONFIG_PARAMETERS`) belongs to one process, and a repository's own scopes belong to
   one repository. Neither ever waives a decision on a persistent change. `winning_origin`
   (used by both the rollback and the doctor's `git_user_value_shadowed`) queries
   `--show-scope --show-origin` and takes the last system or global occurrence.
   Regression: the shadowed case with a `GIT_CONFIG_COUNT` value in Heimdall's environment
   still needs a decision.
2. **R02: an incomplete observation is undetermined.** If the walk could not read the whole
   include graph, or could not establish Git's global file, the selection after a rollback
   is `undetermined` whether or not a user value was found. A decision is then required
   (`undetermined_state`). Regression: an XDG include of a path that is not a file.
3. **R03: the reverse move is a regression.** B_git applied into the XDG file and moved by
   the owner into `~/.gitconfig` (the XDG file put back) is found only by the search. A
   mutant that skips the search when the recorded file holds no block now fails.

### 12.43 Rulings on wave 6w, the first native Windows run (orchestrator, 2026-11-06)

**Source.** The M02 exit build at cb16c2d6 ran natively on the Windows 11 PC for the first time (`tests/evidence/artifacts/m02/exit-cb16c2d6/windows/`). 56 tests failed in 12 binaries.

**How the fixes were made.** Wave 6w ran as T3 units on the PC, natively, in a dev scratch at Medium integrity. Its patches were integrated in 491d8f5a, f0635b44 and 3fe6119f. The orchestrator ran check.sh on macOS for each, and every run exited 0. Most causes were Unix assumptions in tests: a `\\?\` canonical scratch root, `/bin/sh`, `/tmp/…`, `/` separators, Unix file-name rules, `cmd` quoting, LF-only output.

1. **Displays use `/` on every platform.** This extends §12.26 item 7 to `paths::display_path`, and through it to Git origins and probe provenance. The w6-sshconf unit found one Windows doctor report mixing `~\.ssh\config` with `/` paths, and no contract specified the separator.
2. **The native Windows test build keeps line tables only.** With full debug info, the MSVC program database of `heimdall-runtime`'s `model_operations` test binary exceeded the linker's limit (LNK1140). This happened in the native dry run at 3fe6119f.
   - **Scope:** the local runner sets `CARGO_PROFILE_DEV_DEBUG` and `CARGO_PROFILE_TEST_DEBUG` to `line-tables-only` for its own build. It records this as the host fact `build-debuginfo`, and its self-test checks it (E03).
   - **Not workspace-wide:** a workspace-wide `[profile.dev]` setting was tried first (5111a09f) and reverted. It removed the v0 test-function names from the debug info of the Windows cross build, and `refresh-inventory.sh`'s `platform-tests.py` reads those names, so the inventory could no longer resolve `e2e_run_m02::windows_holder_*`. The cross builds and every other build keep full debug info.
   - **Release builds:** unchanged.
3. **Product defects fixed, each with a native regression:**
   - **Rooted Windows `IdentityFile`:** a rooted path (`/…`, no drive) is absolute, as Win32-OpenSSH treats it (`sshconf::relevant`).
   - **Agent locators:** `agents::locator_for` decides a Unix socket path by a leading `/`, not by the host's `Path::is_absolute`.
   - **Quarantine pins (`sys/quarantine.rs`, §5.3):**
     - Live pins of the quarantine open without DELETE, so two pins coexist.
     - They open with `FILE_LIST_DIRECTORY`; observed natively, a metadata-only open does not enforce the no-delete-sharing exclusion.
     - Removing the quarantine closes the pin and then opens with DELETE separately. It revalidates identity, kind, owner and the exact DACL before deleting.
   - **Owner-only DACL check:** it compares against the form for the handle's own kind (a file has no `OICI`). Before this, setup rejected its own snapshot file.
4. **Test-only changes, each recorded with its native evidence:**
   - **Windows run records:** a run is recorded as `launching, spawned, exited`, the §8 Windows sequence.
   - **Displaced names:** the projection tests read Windows' displaced names.
   - **Residual window:** the residual-window test asserts the sharing violation (os error 32) that a held checked-delete handle causes.
   - **Counting proxy:** a silent pipe client is not counted on Windows. It cannot be identified before it writes (`ERROR_CANNOT_IMPERSONATE`, 1368).
   - **Testkit hook:** it disinherits its standard handles, as `runtime` already does.
5. **Harness changes:**
   - **The WSL fixture sshd's stop:** it matches the retitled daemon (` -f <cfg> `) and can report `still-running`. The cb16c2d6 run's `fixture-sshd-at-end=mismatch` left that sshd running; w6-fixtures found it and stopped it by its exact PID.
   - **The local runner's clone:** it keeps `core.autocrlf=false` in the clone's own configuration, records it in host.txt, and stops if a sampled file holds a CR. Git for Windows' system configuration on the PC sets `autocrlf=true`.
   - **`HM_FIXTURE_SSHD_USER`:** not needed. No Windows test uses the harness sshd today; every `LoopbackSshd::start` caller is `cfg(unix)`. It becomes needed if those tests are ungated on Windows.
6. **Fixed (w6-ipc, ADR-0006 §13.21): the Windows pipe listener identified a client before the client had written.**
   - **The defect:** `ipc::windows` `accept` calls `ImpersonateNamedPipeClient` right after `ConnectNamedPipe`, which completes when the client opens the pipe. A same-user client that writes slightly later can therefore be refused (1368).
   - **The ruling:** identify a client only after its first write. The wait is bounded, and a silent client never blocks other clients.
   - **Status:** fixed by unit w6-ipc. A native reproduction failed before the fix (1368 for a default-flags client that writes late; a silent SQOS client was "verified") and passed after it. There are five new Windows tests; each fails with the readiness wait removed. Native results: `heimdall-ipc` 37 passed, the adversarial frame suites passed, `integration_runtime` 52 passed.

### 12.44 Rulings on the WSL local run and the Windows pseudoconsole drivers (orchestrator, 2026-11-08)

**Sources.** The WSL disposable-distribution run in local mode (b024b994), which ran the prebuilt
exit-build binary (sha256 09d04d50…), and the second Windows run of 1e69263d with `-ArgvDump`.

**What the runs showed.**
- **WSL run.** The scenario passed: 10 of 10 tests. The user's `~/.ssh/config` was byte-identical
  after uninstall, and the registered set was unchanged. The script still exited 1, from its own leak
  scan.
- **Windows run.** `resize` and `ctrlc.break` passed. `ctrlc.event` and `ctrlc.keystroke` failed:
  the child saw no interrupt.

1. **The controller distribution's name is personal only when the owner chose it.**
   - **Cause:** the WSL harness redacted and leak-scanned that name as a case-insensitive substring.
     The default name `Ubuntu` therefore matched:
     - the pinned, public image URL in `build.txt`;
     - the client version string, which was rewritten as `<owner-distro>-3<owner-distro>13.20`.
   - **A default name:** one equal, case-insensitively, to the controller's own os-release `NAME` or
     `ID`, or to `NAME-VERSION_ID` (`Ubuntu`, `Ubuntu-24.04`). It identifies nothing about the owner.
     It is recorded as `controller-distro-name=default (os-release)` and is neither redacted nor
     leak-scanned.
   - **Any other name:** personal. It is redacted as a whole word only, as host names are under item
     10, and leak-scanned the same way.
2. **Ctrl-C in the pseudoconsole drivers: a harness defect, ruled as for Unix SIGINT in §12.32 item 9.**
   - **Why it is the harness:** Windows passes a process's "ignore Ctrl-C" attribute
     (`SetConsoleCtrlHandler(NULL, TRUE)`, or a new process group) on to the processes it creates.
     Ctrl-Break cannot be ignored that way, and Ctrl-Break worked, which fits an attribute inherited
     from the agent's process environment. Heimdall's own behaviour is transparent: its child gets
     the disposition it would get if launched directly.
   - **The fix:** the driver creates heimdall with Ctrl-C processing enabled. The inherited state is
     recorded as a host fact (`ctrl-c-inherited=ignored|processed`).
   - **Confirm first:** the unit confirms the cause natively before fixing it, by running the same
     drivers with processing restored. If the cause is anything else, it escalates.

### 12.45 Ruling on the Windows file-symlink row of A22 at the M02 exit (orchestrator, 2026-11-08)

**Status:** `deferred_with_decision` (not counted). Handed to M04 (plan §5 M04, native realization), which is to add the test and run it natively.

**What changed.** A22's Windows file-symlink reparse-point row was `blocked` on B10, "Windows Developer Mode, or one elevation". That input is now satisfied: the exit runs observed `developer-mode=on`, read only. A blocked status no longer describes the row.

**What is missing.** The row has no Windows-native test. The projection tests that cover symlinked user files are `cfg(unix)`, and `integration_projection` has no tests on Windows. Heimdall's Windows handling of a reparse-point user file, which is manual mode under the §5.3 checks, therefore has unit coverage only, with no native row.

**M04's task.** Add the test: a file symbolic link created in scratch under Developer Mode, standing in for the user configuration. It must assert manual mode, and that nothing is written through the link.

### 12.46 Rulings on the wave-6w code review; the M02 exit is held (orchestrator, 2026-11-08)

**Sources.**
- M02-W6-code-review (Codex GPT-6.1 Sol, independent): `tests/evidence/artifacts/review-m02-code/wave6w.md`. It says "fix first", with W6W-R01–R03 and one weakened assertion.
- The exit-record pass. It found Windows rows that read `verified` although their declared coverage never ran natively.

1. **W6W-R01 (fixed): the importer exempts only a fixture home's dotfile inside a redacted root.**
   - A `/home/<name>` path is refused wherever a name may start.
   - Directly after a placeholder (`<scratch>/home/…`), only a dotfile is exempt.
   - A bare `/home/.name` is refused, because a home directory need not follow user-name rules. So is `<scratch>/home/name` and `/home/.private/alice/…`.
   - Regressions were added and mutation-checked. The imported Windows and WSL artifacts were re-scanned with the corrected rule: 0 findings.
2. **The argv-canary comparison (fixed).** It is exact on Unix. On Windows only `echo`'s own `" \r\n"` suffix is allowed.
3. **W6W-R02 and W6W-R03 (to the Windows fix wave).**
   - **R02:** the counting fixture gains an observation of opens that happen before identification. The passivity and no-contact assertions use that count, and the accepted count stays separate.
   - **R03:** the silent-client test observes the client's EOF concurrently with `accept()`. It asserts that the EOF arrives neither before the bound nor long after it, and the test is mutation-checked with a shortened bound.
4. **The M02 exit is held.** The evidence generator rates a platform row from the tests that exist for that platform. A planned Windows test that was never written, or that is `cfg(unix)` with no ruling, therefore reads as covered. A coverage audit lists every declared Windows and WSL claim against what ran at ce21a76f, and proposes a case-index mechanism that keeps such a row from `verified` until its test exists and passes. The Windows fix wave then closes the gaps. Known so far:
   - A35's in-box `ssh`, `scp`, `sftp` and Git transport against a server;
   - R-SE-04 host-key substitution;
   - the projection integration binaries, including the `ReplaceFileW` Git name transitions;
   - the junction reparse row;
   - `sys::account_name` (§12.28 item 4).

   M02 exits only on a build where those rows ran natively, or were ruled out by a recorded decision.

### 12.47 Rulings on the M02 Windows coverage audit; wave 6x (orchestrator, 2026-11-08)

**Source.** `tests/evidence/artifacts/review-m02-code/windows-coverage-audit.md`, a read-only audit of the declared Windows and WSL coverage at ce21a76f.

**The finding.** 314 required tests do not exist on Windows. Of those, 295 are excluded only by the inventory scan, with no rationale. The generator drops them before it builds a row, so a Windows row read `verified` on model-level tests alone. Specifically:
- five test files are `#![cfg(unix)]`;
- no Windows test connects a client to a server;
- six planned tests were never written;
- there are two product gaps:
  - **account name:** `sys::account_name` is missing on Windows;
  - **encoding data:** 9.5p2's BOM and CRLF behaviour is missing from the encoding table.

The WSL rows are covered, apart from the WSL ext4 birth-time observation.

1. **The guard (WU-6).** The audit's two rules both apply:
   - **(R1)** a required test that the scan alone excluded on a declared platform keeps that row `in_progress`, unless `case-index.json` gives a rationale for the exclusion;
   - **(R2)** `platform_required` holds exact test names per case and platform. It is not resolved against the inventory, so a planned test that does not exist reads as not run.

   Rows report `excluded_on_this_platform`. Every Unix-only test that stays Unix-only gets a written rationale; none is left to the scan.
2. **D1:** the `e2e_cli_m02::ssh::` rationale entry is deleted. It contradicts §12.43 item 5.
3. **D2 and D3: deferred to M04** (`deferred_with_decision`). These are the TUI pty tests and the interactive `connect` pty test after provider approval. Their model-level twins ran natively. The Windows pseudoconsole path of `heimdall run` is proven natively by `windows_launch` (§12.44 item 2). M04 adds a pseudoconsole driver for the TUI and for `connect`.
4. **D4:** T06's Windows half is split into JSON tests: the kept quarantine, and the refused purge.
5. **D5: Windows 9.5p2 joins the client and encoding observation tables** (WU-7). It was observed natively at ce21a76f: BOM and CRLF user configurations load. Such configurations then stop falling to manual mode.
6. **D6: every other gapped row is fixed in M02.** That covers:
   - A35's transport;
   - A01's scratch `-F`;
   - R-SE-04;
   - A21's `cmd /c` canary, job containment and authorization;
   - the projection and Git transactions;
   - the setup drivers;
   - A11's fresh eligibility;
   - the account lookup.

   Only D2 and D3 are deferred.
7. **D7: the §12.45 deferral is withdrawn.** Developer Mode is on, so the file-symlink row becomes a test in WU-2a. Its row is a `platform_required` entry, not a deferral.
8. **The units.** Wave 6x takes the audit's units and ownership as given:
   - WU-0 (fixture sshd: user, strictness, the shared keys lock, log offsets);
   - WU-1 (CLI transport, plus D4);
   - WU-2a (projection);
   - WU-2b (Git projection);
   - WU-3 (setup drivers);
   - WU-4 (the doctor and `account_name`);
   - WU-5 (`run` and `connect`);
   - WU-6 (the guard, on the build host);
   - WU-7 (encoding data).

   Each runs natively in its own scratch clone on the PC, at Medium integrity. WU-0, WU-2a, WU-2b, WU-3, WU-6 and WU-7 start now; WU-1, WU-4 and WU-5 start after WU-0 is integrated. A unit removes its build and toolchain when it reports, which avoids repeating the 150 GB of wave 6w.

### 12.48 Rulings during the wave-6x integration (orchestrator, 2026-11-08)

1. **`adopted_key` compares a record path in the renderer's form (product fix).**
   - **The defect:** P names a managed key file with `/` separators on Windows (`RenderPath::windows`), while the projection record keeps the path as written, with `\`. `projection::observe::adopted_key` compared them byte for byte. On Windows the alias observation therefore had no identity selection, and a non-interactive ensure was refused with `fallback_identity_interaction` instead of `AccessReady`.
   - **Found by:** WU-3 natively (`e2e_setup_dispatch` `declaration_changes_between_ensure_and_bind_are_seen_through_the_dispatcher`).
   - **The fix:** on Windows a record path is compared with `\` read as `/`. On Unix `\` is a file-name character, and the comparison stays exact.
   - **Tests:** `key_matches` unit tests cover both platforms. The native Windows proof is the e2e test above, at the next Windows run.
2. **Test-only `unsafe` in `heimdall-testkit` is inventoried** (WU-0's escalation, option (a)). `overview.md` §9 lists `testkit/src/win.rs` (DACL helpers) and the `hook.rs` handle-inheritance site as test-only modules. `heimdall-testkit` is a dev-dependency only, so neither reaches a release build.
3. **WU-0's other readings are accepted:**
   - **The Unix Docker-fallback harness** refuses settings it cannot honour: a `MaxAuthTries` other than 6 or 3, and LogLevel INFO.
   - **`run-windows.sh`'s remote mode** is unsupported, because its route into WSL no longer exists (§12.32 item 15). It neither starts the strict sshd nor exports `HM_FIXTURE_SSHD_USER`.
   - **On Windows without the runner's sshd variables,** the login tests report `SshdUnavailable` instead of compiling out.
4. **Windows DACLs for directories Heimdall creates (WU-2a's E-1).** The owner of the directory decides its DACL.
   - **Heimdall's own private directories** (the backups directory, the quarantine, and anything else under its state or config directory) get the protected owner-only DACL `D:P(A;OICI;FA;;;<sid>)` when Heimdall creates them, as the quarantine already does. The backups directory lacked it, which is a product defect.
   - **A `~/.ssh` directory or user configuration file that Heimdall creates** follows Win32-OpenSSH's own rule instead: the user, SYSTEM and Administrators only, and no other principal. An owner-only `~/.ssh` would stop a Windows sshd, which runs as SYSTEM, from reading `authorized_keys`.
5. **The preview validates the quarantine in P's directory (WU-2a's E-2).** An invalid quarantine there makes the item manual mode at preview (§5.3 item 9). Before this, it was found only after the commit, where settlement failed with `Unavailable`.
6. **The LF question in §4 is settled for Windows.** An LF-only rendered P loads in `OpenSSH_for_Windows_9.5p2` (`ssh -G`, `rendered_file_loads_on_target_client`), observed natively by WU-2a.

### 12.49 Rulings on the wave-6x unit escalations (orchestrator, 2026-11-08)

1. **The launch check compares one pipe spelling on Windows (product fix, found by WU-1).**
   - **The defect:** P renders a managed alias's agent as `IdentityAgent //./pipe/<name>` (`RenderPath::pipe`). `launch_flow::identity_agent` copied that value as written, and the eligibility check (`eligibility.rs`, step 3) compared it as a string with the declaration's adopted endpoint, `\\.\pipe\<name>`. Both name the same pipe object. On Windows, every non-interactive `run` over a managed alias whose key is declared `none` was therefore refused with `interaction_unknown`.
   - **The fix:** on Windows, the observed value is read through `agents::locator_for`, which already accepts both spellings. That gives the `\\.\pipe\<name>` form.
   - **Why it fails closed:** a value that names no pipe keeps its raw form and still fails to match. On Unix nothing changes.
   - **Native proof:** `e2e_cli_m02` went from 24 of 26 passing to 26 of 26 (WU-1's configurations A and C). The two tests that needed the fix were `ssh::a35_matrix_ssh_git_scp_sftp_ordinary_alias_and_run_bound` and `ssh::host_key_substitution_fails_closed_and_nothing_written_to_known_hosts`.
2. **T06's Windows half (D4, §12.47 item 4).** These two JSON tests are T06's Windows `platform_required`:
   - `e2e_cli_m02::json::uninstall_with_incomplete_rollback_keeps_the_quarantine_json`
   - `e2e_cli_m02::json::uninstall_with_incomplete_rollback_purge_state_is_refused_json`

   Under `--non-interactive`, the purge is refused with exit 3 (`interaction_required`, effect `none`) before anything runs. The second test asserts that refusal, in the incomplete-rollback state, with nothing purged or changed.

   The exit-6 refusal needs a typed yes on a terminal. On Windows that is deferred to M04's pseudoconsole driver, together with D2 and D3.
3. **WU-8's pipe fixture design is accepted (W6W-R02).** `PipeFixture` works like this:
   - it takes the random pipe name with the reviewed `Listener::bind` (protected owner-only DACL, first-instance flag);
   - it serves further instances through tokio's safe `ServerOptions`, which take the pipe's own descriptor;
   - it identifies each client after the client's first write, with the reviewed `client_sid` and `verify_peer`, under `FIRST_WRITE_WAIT` and `MAX_PENDING_IDENTIFICATIONS`;
   - it counts every open before identification, as `opens()`.

   The alternative was a hidden connect hook in `Listener`. That would add a product surface only for tests, so it is not taken. The `crates/testkit/Cargo.toml` comment now describes this design.
4. **`ssh::a01_personal_profile_without_repository` stays Unix-only and is deferred with D3 to M04.** Two of its parts have no faithful Windows form yet:
   - its attended `run` decision needs a terminal on stdin, which on Windows needs M04's pseudoconsole driver;
   - `connect` launches the pinned in-box `ssh.exe`. That client finds the account's real profile from the token, so no scratch home can stand in for it, and without `-F` it would read the owner's real configuration (§9 item 5).
5. **Intermittent `integration_adapters::prepared_facts_from_outcome_drop_interaction_fields` on Windows.**
   - **Observed by WU-8:** at baseline 421c8f41 it failed 3 of 50 runs and then 4 of 50 ("agent endpoint absent"). With WU-8's fixture it failed 0 of 50.
   - **Inferred cause:** the old fixture's handling of pipe instances; this is not proven.
   - **Rule:** a recurrence in any run reopens this item as a defect owned by the adapters.
6. **WU-2a sets the protected DACL on a `~/.ssh` it creates, instead of inheriting one.** This applies item 4 of §12.48. The DACL grants the user, SYSTEM and Administrators only.
   - **Why:** a scratch home under `%LOCALAPPDATA%` inherits a read ACE for another local account, so inheritance alone would break the rule.
   - **Effect on a real profile:** a real profile's `~/.ssh` inherits exactly those three principals, so the explicit DACL is the same there.
7. **Declined:** a `LoopbackSshd::authorized_keys()` accessor (WU-1, optional). `a01_no_remote_change` reads the runner's `HM_FIXTURE_SSHD_AUTHORIZED_KEYS` directly.

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
  `config_tree_changed` (§6). ⟨r5⟩ It also records Git's lock holder K, and that a lock
  left after a crash on a filesystem without birth time is the owner's to remove.
* ⟨r5⟩ The runtime bounds every real adapter call (`Limits.adapter_call_timeout`, §7).
* ⟨§12.41⟩ Git residuals, for M03:
  * a rollback whose recorded file no longer holds B_git, because the owner moved the block,
    removes P_git alone and leaves the moved block. Git skips the missing include, and the
    owner removes the block;
  * an intact-shaped B_git whose include target was edited to another file is not detected
    by the update arm while Heimdall's value is not reached, so the doctor then shows no
    Heimdall value;
  * a user value only in a conditional include is read conservatively.
* ⟨§12.36 item 2⟩ Residual: an `Include` that is opaque, because it needs `${VAR}` or
  because the client's `%` behaviour is unknown, is not read. A `Match exec` inside it is not
  listed by file and line; the authorization prompt lists the opaque point instead.
* ⟨§12.34 items 3 and 6⟩ Deferred to M03 with a decision:
  * `agents::identity_agent_references` expands `Include` regardless of the client, so the
    doctor may list an extra candidate agent endpoint. It grants nothing.
  * Refusing an edit when a writing `ProjectionConfig` has no `state_dir` is left for M03
    hardening. Every production constructor sets it, which a guard test checks.
* ⟨§12.30 item 9⟩ An unknown local account has no dedicated `UnresolvedReason`. Conditions
  that read the account (`Match localuser`, `Match user` while the remote user may be the
  local account, `%u`, `%r`) are `Unknown` or `TokenUnavailable`, and the doctor words its
  `identity_selection_undetermined` finding from that. The account is unknown on Windows
  until the native lookup lands (§12.28 item 4).
* ⟨§12.16⟩ Residual, stated in the compatibility matrix: the **default** agent is the
  `SSH_AUTH_SOCK` of whatever session runs `ssh`. Consent to a state that uses the default
  agent covers "the session's agent", not a particular endpoint. An explicit variable
  reference is undetermined, and so always needs a new decision (§12.16 item 1).

## 14. Reopen conditions

Reopen this ADR if any of the following happens:

* a target client contradicts F1–F3, F20 or the include-state inference (corpus test);
* Win32-OpenSSH refuses the rendered P or the `ReplaceFileW`-preserved file;
* a supported user layout needs the include somewhere other than the top;
* the owner rules differently on Q1–Q8, QR1–QR6 or ⟨r3⟩ QR7–QR11 ⟨r4⟩ or QR12–QR15 ⟨r5⟩ or
  QR16–QR17;
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
  forward, restore or abort action and that violates one of its properties (§5.7);
* ⟨r5⟩ a target Git reads, removes or renames a lock it did not create, so that K does
  not keep its writers out (F22);
* ⟨r5⟩ an adapter's effect can land after its call was dropped at the timeout (M03's
  managed credentials), so that the bound of §7 no longer ends the effect.

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

### 15.3 ⟨r5⟩ Change log (revision 5, task M02-T00-design-fix-4)

Source: `tests/evidence/artifacts/review-m02-design/round4.md`, rulings §12.11.

| Finding | Ruling (§12.11) | Sections changed here | m02-plan.md |
|---|---|---|---|
| M2-T01 claiming the Git lock breaks the replacement's names | item 1 | F22 (a lock whose content is not configuration); §5.3 steps 3 and 5 (B_git uses ordinary names); §5.6 lock protocol rewritten around the lock holder K, "Who owns the lock name", **name-transition tables** (replace, restore, abort, create; Unix and Windows) and **crash vectors**, receipts and recovery, rollback; §5.7 `git_lock` role, `LockHolder` content, names, `file.staged`/`file.settling` rows, rows **K0–K4** replacing G0–G3, T0/T2/T3; §5.9 item 5; §11 rows; §13; §14; QR16 | U0 frozen list and wire tests; U4 `git::{lock_holder, claim_lock}`, `ReplaceHook::BeforeLockRelease`, `git_name_transitions_crash_at_every_point_reconciles` and the revised Git tests; §5 items 17, 17a |
| M2-T02 the materializer cannot check its digests; absent base undefined | item 2 | §5.3 step 3; §5.7 "Bound to the digests" (the whole step, absent base as an empty insert-only input, checked range arithmetic, `validate` checks), bounds | U4 `content::materialize(&FileStep, Option<&[u8]>)`, `ContentError`; tests `materialize_*` and the fresh-writer creates of an absent SSH config and an absent global Git file; U0 wire tests; §5 item 17 |
| M2-T03 held previews do not bind content | item 3 | §5.7 "Repair path" (fingerprints with identity, digest or `unreadable`, length and change time; the plan digest binds them; no bytes anywhere) | U4 `observe_held` fingerprints; U5 `keep_held` staleness and the two controls; §5 items 2, 15 |
| M2-T04 `decide` cannot recover from `held` | item 4 | §5.7 `RecoveryState` (effective phase, restore, settlement, item, `release_due`), its order check and `contradictory_receipts`, "Phase" columns, F5/C7 wording, H0 withdrawn, Outcome H restart, the generated domain | U0 frozen list; U4 `recovery::decide(shape, &RecoveryState, &StepObservation)`, `RecoveryState::build`, tests; §5 item 17a (`HoldReason`) |
| M2-T05 the generated properties reject permitted behaviour | item 5 | §5.7 normalization (shape, role precedence, rejected impossible combinations); properties restated over concrete effects (restore exchange vs recognition, the cleaner's locator rule, the create rollback, K's claim and release); negative controls and seeded faults | U4 generated tests, `recovery_properties_catch_seeded_faults`, normalization tests |
| M2-T06 no owner for ADR-0006 §13.20 item 3 | item 6 | §7 "Every call is bounded"; §10 ports; §11 row; §13; §14; QR17 | U0b row 24 (phase 2) and its tests; U6 drop contract and test; §5 item 15; §6 P12; §8 |
| Interface reconciliation | item 7 | §10 `FileIdentity` equality | U0b "Today" descriptions corrected (rows 1, 4, 6, 11, 16, 17, 21 and 23), the **preserve** list, U0 migration test over the M01 meta records and counters, `FileIdentity` `Some`≠`None` tests |
