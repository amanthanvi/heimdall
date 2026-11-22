//! `activate [--hook] --cwd <PATH>` and `shell init <zsh|bash>` (M05 U4, U9a; ADR-0011 §3.2,
//! §3.3, §5.3, §10 item 3; m05-plan U4, U9).
//!
//! **The shell hook never prompts** (ruling 3, the client half). `activate --hook` is
//! noninteractive whatever the terminal: its hello declares `non_interactive`, it never
//! sends `Attend`, never writes a prompt, never sends `Decide`, reads nothing from stdin,
//! and its whole run is bounded by [`HOOK_BUDGET`] (1 s). Its only requests are
//! `ensure` with `context {cwd}` and `covered_only` (the runtime activates what the saved
//! policy already covers and never creates a decision record), `bind` of what was
//! activated, held by the shell, and a read of `inspect workspace` to word an uncovered
//! answer ([`hook_flow`]). It never starts the runtime: with none serving, it does nothing.
//!
//! * **It warms the personal default** (orchestrator ruling I-13, option 2; ADR-0011 §3.2
//!   (a), R4): beside that session it sends the environment signing endpoint — the one
//!   every ordinary managed alias names in `IdentityAgent` — one
//!   `SSH_AGENTC_REQUEST_IDENTITIES`, exactly what the next ordinary `ssh` sends, and
//!   ignores the answer ([`warm_default`]). The endpoint's identities path (U5) runs the
//!   covered-only activation of the environment's `default` personal policy, so the
//!   ordinary alias's slot is materialized before the user types `ssh` (OpenSSH reads the
//!   alias's `IdentityFile` before it asks the agent, so a free slot fails the first `ssh`
//!   otherwise). It is that same activation, reached the same way: no new request, no
//!   decision, no prompt, nothing beyond what the next `ssh` would trigger. It runs in
//!   every context (ordinary aliases are environment-level and governed by the personal
//!   default wherever the shell is: ADR-0011 §3.1, §5.2), shares [`HOOK_BUDGET`] with the
//!   session (the activation keeps running in the runtime after the hook stops waiting:
//!   ADR-0011 §10 item 7), and fails silently: no endpoint, no runtime, a refusal or the
//!   budget's end prints nothing and leaves the hook's answer and exit status as they are.
//! * **The holder** is the shell: its PID (`--shell-pid`, which the script passes as `$$`;
//!   default the parent process) and its OS start time, so the binding is released when
//!   the shell exits (ADR-0007 Q5) and a reused PID never counts.
//! * **The work ID** is `shell:<pid>.<start>.<n>` (ADR-0011 §3.3). The script keeps `n`;
//!   when the runtime answers that the work's binding has ended (`CREDENTIAL_EXPIRED` with
//!   no reason), the hook starts the next work `n + 1` once: automatic re-entry within the
//!   saved limits. A **stopped** work (`work_stopped`) is never re-entered: that is what
//!   `access stop --work` means, and only a new shell is new work.
//! * **Mechanism groups** (ADR-0011 §5.3): a `mixed_mechanisms` answer is re-requested one
//!   `next.groups` group at a time under the same work ID, still `covered_only`.
//! * **Output.** stdout is one line `<state> <n> <recheck>` for the script (`state` one of
//!   [`HookState`]'s tokens, `recheck` the seconds until the activated access is due
//!   again, 0 for none); `--json` prints the envelope instead. One status line goes to
//!   stderr only when the state differs from `--last` and is `untrusted`, `paused` or
//!   `needs_review`; it states a fact and names a command, and never asks a question. The
//!   exit status is always 0: a hook never fails the shell's prompt.
//!
//! **`shell init`** prints [`ZSH_SCRIPT`] or [`BASH_SCRIPT`]: static text, with no
//! interpolation of anything (no path, no repository text, no environment value). It runs
//! the hook on each directory change (zsh `chpwd`, bash `PROMPT_COMMAND` when `$PWD`
//! changed) and when the activated access is due again, passes `"$PWD"` as one quoted
//! argument, and treats Heimdall's answer as data: three fields, each checked against a
//! fixed pattern, never evaluated. ⟨M05; finding A29-F2⟩ Its own state variables
//! (`__heimdall_seq`, `__heimdall_state`, `__heimdall_due`) are checked against the same
//! patterns before each use, falling back to their initial values, so a value a
//! repository's tooling exported into the environment can neither make the hook print an
//! error on every prompt nor stop it activating.
//!
//! **`activate` without `--hook`** is a foreground activation by working directory, as
//! `run` without `--profile` is: `ensure` with `context`, the attended decision flow on a
//! terminal (`cli::ensure_flow`), and the same request again after an approval.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::time::Duration;

use heimdall_contract::envelope::{Envelope, reason};
use heimdall_contract::ids::WorkId;
use heimdall_contract::ipc::capability;
use heimdall_contract::request::{
    AccessPairRef, BindForm, BindRequest, EnsureData, EnsureRequest, InteractionMode,
    LaunchBinding, ProcessHolder, Request, RequiredCapabilities, WaitMode,
};
use heimdall_contract::trust::{ContextKind, WorkContext, WorkspaceMatchView};
use heimdall_contract::{Code, ExitCode, Timestamp};
use heimdall_ipc::agent_client::{self, AgentLocator, ClientBounds};

use crate::cli::{ActivateArgs, Session, ShellArg, TerminalPrompt, ensure_flow, fresh_request_id};
use crate::client::Ctx;
use crate::m05_cmd;
use crate::output;

/// The hook's whole budget, connection included (ADR-0011 §3.2).
pub(crate) const HOOK_BUDGET: Duration = Duration::from_secs(1);

/// The bounded wait of the hook's `ensure`, inside [`HOOK_BUDGET`].
const HOOK_ENSURE_WAIT_MS: u64 = 700;

/// The longest `recheck` the hook reports (a day): the script re-runs the hook at the
/// first prompt after it.
const MAX_RECHECK_S: i64 = 86_400;

/// What the hook found (the first field of its output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookState {
    /// Covered access is active.
    Active,
    /// The workspace is not trusted and nothing (more) of its request is covered.
    Untrusted,
    /// A pause, a cutoff or a stop blocks it.
    Paused,
    /// A trusted workspace asks for more than its policy covers, its manifest is refused,
    /// or it partly matches a trusted workspace: the owner reviews it in the foreground.
    NeedsReview,
    /// Nothing to activate here (no workspace and no covered personal default).
    None,
    /// No answer: no runtime, the budget ran out, or an error the shell cannot act on.
    Unavailable,
}

impl HookState {
    /// The token the script reads.
    #[must_use]
    pub(crate) fn token(self) -> &'static str {
        match self {
            HookState::Active => "active",
            HookState::Untrusted => "untrusted",
            HookState::Paused => "paused",
            HookState::NeedsReview => "needs_review",
            HookState::None => "none",
            HookState::Unavailable => "unavailable",
        }
    }

    /// The status line shown when the shell enters this state (a fact and a command,
    /// never a question).
    #[must_use]
    pub(crate) fn line(self) -> Option<&'static str> {
        match self {
            HookState::Untrusted => Some(
                "heimdall: this workspace is not trusted; nothing new was activated. To review it: heimdall project trust",
            ),
            HookState::Paused => Some(
                "heimdall: access here is paused, stopped or past its cutoff; nothing was activated. To resume: heimdall access resume",
            ),
            HookState::NeedsReview => Some(
                "heimdall: this workspace asks for access its saved policy does not cover; only covered access was activated. To review it: heimdall access allow --workspace",
            ),
            _ => None,
        }
    }
}

/// The hook's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hooked {
    pub(crate) state: HookState,
    /// The work sequence number to keep (`n`, or `n + 1` after a re-entry).
    pub(crate) seq: u64,
    /// Seconds until the activated access is due again (0: none).
    pub(crate) recheck_s: u64,
    /// The work ID used last.
    pub(crate) work_id: Option<String>,
}

impl Hooked {
    fn of(state: HookState, seq: u64) -> Hooked {
        Hooked {
            state,
            seq,
            recheck_s: 0,
            work_id: None,
        }
    }
}

/// The shell's work ID for sequence `n`.
fn shell_work_id(holder: &ProcessHolder, n: u64) -> Option<WorkId> {
    WorkId::parse(&format!("shell:{}.{}.{n}", holder.pid, holder.started_at)).ok()
}

/// How the hook reads one `ensure` answer.
enum Answer {
    Ready(Box<EnsureData>),
    Groups(Vec<Vec<AccessPairRef>>),
    Expired,
    Paused,
    NotCovered,
    Review,
    Quiet,
    Unavailable,
}

fn read_answer(env: &Envelope<serde_json::Value>) -> Answer {
    let why = env.data["error"]["reason"].as_str();
    match env.code {
        Code::AccessReady => match serde_json::from_value::<EnsureData>(env.data.clone()) {
            Ok(d) => Answer::Ready(Box::new(d)),
            Err(_) => Answer::Unavailable,
        },
        _ if why == Some(reason::MIXED_MECHANISMS) => {
            let groups: Vec<Vec<AccessPairRef>> = env
                .next
                .as_ref()
                .map(|n| n.groups.iter().map(|g| g.pairs.clone()).collect())
                .unwrap_or_default();
            if groups.len() > 1 {
                Answer::Groups(groups)
            } else {
                Answer::Unavailable
            }
        }
        Code::CredentialExpired if why == Some(reason::WORK_STOPPED) => Answer::Paused,
        Code::CredentialExpired => Answer::Expired,
        Code::PolicyPaused | Code::PolicyCutoff => Answer::Paused,
        Code::InteractionRequired if why == Some(reason::NOT_COVERED) => Answer::NotCovered,
        // Any decision reference here is never shown or decided: the owner reviews in the
        // foreground (ruling 3).
        Code::InteractionRequired | Code::ApprovalRequired => Answer::Review,
        _ if matches!(
            why,
            Some(
                reason::MANIFEST_INVALID
                    | reason::MANIFEST_AUTHORITY_KEY
                    | reason::MANIFEST_PROFILE_UNKNOWN
                    | reason::WORKSPACE_AMBIGUOUS
            )
        ) =>
        {
            Answer::Review
        }
        Code::CapabilityUnavailable if why == Some(reason::WORKSPACE_IDENTITY_UNAVAILABLE) => {
            Answer::NotCovered
        }
        // No profile here (no manifest, no default profile), or nothing of it known.
        Code::UsageError | Code::NotFound => Answer::Quiet,
        _ => Answer::Unavailable,
    }
}

/// The `ensure` of a hook (module docs).
fn hook_ensure(cwd: &str, work_id: WorkId, scope: BTreeSet<AccessPairRef>) -> Option<Request> {
    let request_id = fresh_request_id().ok()?;
    Some(Request::Ensure(EnsureRequest {
        profile: None,
        profile_revision: None,
        scope,
        environment: None,
        work_id,
        until: None,
        required_capabilities: RequiredCapabilities::default(),
        request_id,
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::Sync {
            timeout_ms: HOOK_ENSURE_WAIT_MS,
        },
        connection: None,
        context: Some(WorkContext {
            cwd: cwd.to_owned(),
        }),
        covered_only: true,
        pair_issuers: Vec::new(),
    }))
}

/// The state an uncovered answer means: a trusted workspace needs review, an untrusted or
/// ambiguous one is untrusted, no workspace is quiet.
async fn uncovered_state<S: Session>(s: &mut S, cwd: &str) -> HookState {
    match m05_cmd::workspace(s, cwd).await {
        Ok(v) => match v.matched {
            WorkspaceMatchView::Trusted | WorkspaceMatchView::Member => HookState::NeedsReview,
            WorkspaceMatchView::Ambiguous => HookState::NeedsReview,
            WorkspaceMatchView::Untrusted => HookState::Untrusted,
            _ => HookState::None,
        },
        Err(_) => HookState::Unavailable,
    }
}

/// The hook on a connected session (module docs). Sends only `ensure`, `bind` and
/// `inspect`: never `Attend`, never `Decide`.
pub(crate) async fn hook_flow<S: Session>(
    s: &mut S,
    cwd: &str,
    holder: &ProcessHolder,
    seq: u64,
    executable: &str,
    now: Timestamp,
) -> Hooked {
    let mut seq = seq;
    let mut reentered = false;
    let (work_id, ready) = loop {
        let Some(work_id) = shell_work_id(holder, seq) else {
            return Hooked::of(HookState::Unavailable, seq);
        };
        let Some(request) = hook_ensure(cwd, work_id.clone(), BTreeSet::new()) else {
            return Hooked::of(HookState::Unavailable, seq);
        };
        let env = s.request(request).await;
        let ready = match read_answer(&env) {
            Answer::Ready(d) => vec![*d],
            Answer::Groups(groups) => {
                let mut ready = Vec::new();
                for pairs in groups {
                    let scope: BTreeSet<AccessPairRef> = pairs.into_iter().collect();
                    let Some(request) = hook_ensure(cwd, work_id.clone(), scope) else {
                        return Hooked::of(HookState::Unavailable, seq);
                    };
                    let env = s.request(request).await;
                    if let Answer::Ready(d) = read_answer(&env) {
                        ready.push(*d);
                    }
                }
                if ready.is_empty() {
                    return Hooked::of(uncovered_state(s, cwd).await, seq);
                }
                ready
            }
            Answer::Expired if !reentered => {
                // Automatic re-entry (ADR-0011 §3.3): the next work, once.
                seq = seq.saturating_add(1);
                reentered = true;
                continue;
            }
            Answer::Expired | Answer::Unavailable => {
                return Hooked::of(HookState::Unavailable, seq);
            }
            Answer::Paused => return Hooked::of(HookState::Paused, seq),
            Answer::NotCovered => return Hooked::of(uncovered_state(s, cwd).await, seq),
            Answer::Review => return Hooked::of(HookState::NeedsReview, seq),
            Answer::Quiet => return Hooked::of(HookState::None, seq),
        };
        break (work_id, ready);
    };
    // The shell holds what was activated; a bind that fails leaves the activation to its
    // own deadline.
    for d in &ready {
        let Ok(request_id) = fresh_request_id() else {
            break;
        };
        let _ = s
            .request(Request::Bind(BindRequest {
                binding_id: d.binding_id.clone(),
                form: BindForm::Launch(LaunchBinding {
                    executable: executable.to_owned(),
                    holder: Some(holder.clone()),
                }),
                request_id,
            }))
            .await;
    }
    let uncovered = ready.iter().any(|d| !d.uncovered.is_empty());
    let in_workspace = ready.iter().any(|d| {
        d.context
            .as_ref()
            .is_some_and(|c| c.kind == ContextKind::Workspace)
    });
    let state = match (uncovered, in_workspace) {
        (false, _) => HookState::Active,
        (true, true) => HookState::NeedsReview,
        (true, false) => match uncovered_state(s, cwd).await {
            HookState::None | HookState::Unavailable => HookState::Active,
            other => other,
        },
    };
    let due = ready
        .iter()
        .map(|d| d.expires_at.as_second())
        .min()
        .map_or(0, |end| (end - now.as_second()).clamp(1, MAX_RECHECK_S));
    Hooked {
        state,
        seq,
        recheck_s: u64::try_from(due).unwrap_or(0),
        work_id: Some(work_id.to_string()),
    }
}

/// The parent process of this one (the shell, when the hook runs directly from it).
fn parent_pid() -> Option<u32> {
    #[cfg(unix)]
    {
        Some(std::os::unix::process::parent_id())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// What `bind` names as the program under the binding: the shell's own image when it can
/// be read, else this executable (never the verified `ssh`, so no owned connection is
/// registered for it).
fn holder_executable(pid: u32) -> Option<String> {
    let image = heimdall_localenv::sys::ProcessPin::open(pid)
        .ok()
        .flatten()
        .and_then(|pin| pin.image())
        .or_else(|| std::env::current_exe().ok())?;
    image
        .is_absolute()
        .then(|| image.to_str().map(str::to_owned))
        .flatten()
}

/// Everything the hook needs before it connects, or `None` (nothing to do).
async fn hook_run(ctx: &Ctx, a: &ActivateArgs, cwd: &str) -> Hooked {
    let unavailable = Hooked::of(HookState::Unavailable, a.seq);
    let Some(pid) = a.shell_pid.or_else(parent_pid).filter(|p| *p > 1) else {
        return unavailable;
    };
    let Some(started_at) = heimdall_runtime::platform::process_start_time(pid) else {
        return unavailable;
    };
    let holder = ProcessHolder { pid, started_at };
    let Some(executable) = holder_executable(pid) else {
        return unavailable;
    };
    // Noninteractive whatever the terminal, and never starting the runtime.
    let Ok(mut client) = crate::client::connect_as(
        ctx,
        false,
        &[capability::TRUSTED_WORK_V1],
        InteractionMode::NonInteractive,
    )
    .await
    else {
        return unavailable;
    };
    hook_flow(
        &mut client,
        cwd,
        &holder,
        a.seq,
        &executable,
        Timestamp::now(),
    )
    .await
}

/// The environment signing endpoint: the one every ordinary managed alias names in
/// `IdentityAgent` (the projection renders the managed layout's environment endpoint,
/// `credential::endpoints::EndpointLayout::rendered_environment`). Unix: the runtime
/// directory's `signing.sock`, a pure function of the Heimdall home. Windows: the pipe
/// the serving runtime advertises (its validated `instance.json`; the pipe name holds the
/// installation's token). `None` when it cannot be named; nothing is created or started.
fn environment_endpoint(ctx: &Ctx) -> Option<AgentLocator> {
    let paths = ctx.paths().ok()?;
    #[cfg(unix)]
    {
        let endpoints = heimdall_ipc::EndpointPaths::for_runtime(&paths.runtime_dir, "");
        Some(AgentLocator::UnixSocket(endpoints.signing))
    }
    #[cfg(windows)]
    {
        let info = heimdall_runtime::instance::InstanceInfo::read_valid(&paths.runtime_dir)
            .ok()
            .flatten()?;
        Some(AgentLocator::NamedPipe(info.signing_endpoint))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = paths;
        None
    }
}

/// Warm the personal default (module docs; ruling I-13, option 2): one
/// `SSH_AGENTC_REQUEST_IDENTITIES` to `endpoint` through the bounded agent client (its only
/// write is that constant frame; it checks the endpoint is the user's own before writing),
/// waiting for the answer no later than `deadline`, then ignoring it. Every outcome is
/// silent: nothing is printed and nothing is returned.
async fn warm(endpoint: &AgentLocator, deadline: tokio::time::Instant) {
    let _ = tokio::time::timeout_at(
        deadline,
        agent_client::list_identities(endpoint, &ClientBounds::default()),
    )
    .await;
}

/// [`warm`] on this home's environment endpoint (nothing when it cannot be named).
async fn warm_default(ctx: &Ctx, deadline: tokio::time::Instant) {
    if let Some(endpoint) = environment_endpoint(ctx) {
        warm(&endpoint, deadline).await;
    }
}

/// `activate --hook` (module docs).
fn hook(ctx: &Ctx, a: &ActivateArgs) -> ExitCode {
    let ctx = Ctx {
        non_interactive: true,
        stdin_tty: false,
        ..ctx.clone()
    };
    let cwd = m05_cmd::cwd_of(Some(&a.cwd)).ok();
    let hooked = match crate::service_cmd::current_thread() {
        Ok(rt) => {
            // The timers are created inside the executor (they need its reactor). The
            // warm-up and the session run together and share the one budget: the hook
            // ends by its deadline, and the session's answer is kept whatever the warm-up
            // is still waiting for.
            let hooked = rt.block_on(async {
                let deadline = tokio::time::Instant::now() + HOOK_BUDGET;
                let flow = async {
                    let Some(cwd) = &cwd else {
                        return Hooked::of(HookState::None, a.seq);
                    };
                    tokio::time::timeout_at(deadline, hook_run(&ctx, a, cwd))
                        .await
                        .unwrap_or_else(|_| Hooked::of(HookState::Unavailable, a.seq))
                };
                let ((), hooked) = tokio::join!(warm_default(&ctx, deadline), flow);
                hooked
            });
            rt.shutdown_background();
            hooked
        }
        Err(_) if cwd.is_none() => Hooked::of(HookState::None, a.seq),
        Err(_) => Hooked::of(HookState::Unavailable, a.seq),
    };
    // Unavailable keeps what the shell last showed: nothing is printed for it.
    let last = a.last.as_deref().unwrap_or("none");
    if hooked.state.token() != last
        && let Some(line) = hooked.state.line()
    {
        output::diagnostic(line);
    }
    if ctx.json {
        let env = Envelope::ok(serde_json::json!({
            "state": hooked.state.token(),
            "seq": hooked.seq,
            "recheck_s": hooked.recheck_s,
            "work_id": hooked.work_id,
        }));
        output::emit(&env, true);
    } else if hooked.state != HookState::Unavailable {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(
            out,
            "{} {} {}",
            hooked.state.token(),
            hooked.seq,
            hooked.recheck_s
        );
        let _ = out.flush();
    }
    ExitCode::Success
}

/// Handle `activate`.
pub(crate) fn activate(ctx: &Ctx, a: &ActivateArgs) -> ExitCode {
    if a.hook {
        return hook(ctx, a);
    }
    let cwd = match m05_cmd::cwd_of(Some(&a.cwd)) {
        Ok(c) => c,
        Err(o) => return o.emit(ctx),
    };
    let request_id = match fresh_request_id() {
        Ok(r) => r,
        Err(d) => {
            output::emit(&d.env, ctx.json);
            return d.exit;
        }
    };
    let Ok(work_id) = WorkId::parse(request_id.as_str()) else {
        return crate::setup_cmd::usage("invalid work ID").emit(ctx);
    };
    let request = EnsureRequest {
        profile: None,
        profile_revision: None,
        scope: BTreeSet::new(),
        environment: None,
        work_id,
        until: None,
        required_capabilities: RequiredCapabilities::default(),
        request_id,
        interaction: ctx.interaction(),
        wait: WaitMode::Sync { timeout_ms: 30_000 },
        connection: None,
        context: Some(WorkContext { cwd }),
        covered_only: false,
        pair_issuers: Vec::new(),
    };
    let done = match crate::service_cmd::current_thread() {
        Ok(rt) => rt.block_on(async {
            match m05_cmd::session(ctx, true).await {
                Ok(mut client) => {
                    ensure_flow(&mut client, &mut TerminalPrompt, ctx, request, false).await
                }
                Err(o) => crate::cli::Done::of(o.env),
            }
        }),
        Err(env) => crate::cli::Done::of(output::error_value(env)),
    };
    output::emit(&done.env, ctx.json);
    done.exit
}

/// The zsh integration (`heimdall shell init zsh`): static text (module docs).
pub(crate) const ZSH_SCRIPT: &str = r#"# Heimdall shell integration for zsh (`heimdall shell init zsh`; ADR-0011 §3.2).
#
# This text is static: it holds only Heimdall's code, never anything read from a
# repository, and it evaluates nothing it is given. On each directory change, and when
# the access it activated is due again, it runs `heimdall activate --hook`, which never
# prompts, never asks for an owner decision, activates only what your saved policy
# already covers and gives up after one second. Heimdall prints one status line when
# the state changes (untrusted, paused, needs review).
#
# Enable it in ~/.zshrc with:  eval "$(heimdall shell init zsh)"

__heimdall_hook() {
  emulate -L zsh
  command -v heimdall >/dev/null 2>&1 || return 0
  local out state rest seq recheck prev last
  prev="${__heimdall_seq:-0}"
  case "$prev" in ''|*[!0-9]*|0?*|??????????*) prev=0 ;; esac
  last="${__heimdall_state:-none}"
  case "$last" in active|untrusted|paused|needs_review|none) ;; *) last=none ;; esac
  out="$(command heimdall activate --hook --cwd "$PWD" --shell-pid "$$" \
    --seq "$prev" --last "$last" </dev/null)"
  state="${out%% *}"
  rest="${out#* }"
  seq="${rest%% *}"
  recheck="${rest#* }"
  case "$state" in
    active|untrusted|paused|needs_review|none) ;;
    *) return 0 ;;
  esac
  case "$seq" in ''|*[!0-9]*|0?*|??????????*) return 0 ;; esac
  case "$recheck" in ''|*[!0-9]*|0?*|??????????*) return 0 ;; esac
  __heimdall_state="$state"
  __heimdall_seq="$seq"
  if [ "$recheck" -gt 0 ]; then
    __heimdall_due=$(( SECONDS + recheck ))
  else
    __heimdall_due=0
  fi
}

__heimdall_due_check() {
  emulate -L zsh
  local due="${__heimdall_due:-0}"
  case "$due" in ''|*[!0-9]*|0?*|???????????*) due=0 ;; esac
  if [ "$due" -gt 0 ] && [ "$SECONDS" -ge "$due" ]; then
    __heimdall_hook
  fi
}

autoload -Uz add-zsh-hook
add-zsh-hook chpwd __heimdall_hook
add-zsh-hook precmd __heimdall_due_check
__heimdall_hook
"#;

/// The bash integration (`heimdall shell init bash`): static text (module docs).
pub(crate) const BASH_SCRIPT: &str = r#"# Heimdall shell integration for bash (`heimdall shell init bash`; ADR-0011 §3.2).
#
# This text is static: it holds only Heimdall's code, never anything read from a
# repository, and it evaluates nothing it is given. On each directory change, and when
# the access it activated is due again, it runs `heimdall activate --hook`, which never
# prompts, never asks for an owner decision, activates only what your saved policy
# already covers and gives up after one second. Heimdall prints one status line when
# the state changes (untrusted, paused, needs review).
#
# Enable it in ~/.bashrc with:  eval "$(heimdall shell init bash)"

__heimdall_hook() {
  command -v heimdall >/dev/null 2>&1 || return 0
  local out state rest seq recheck prev last
  prev="${__heimdall_seq:-0}"
  case "$prev" in ''|*[!0-9]*|0?*|??????????*) prev=0 ;; esac
  last="${__heimdall_state:-none}"
  case "$last" in active|untrusted|paused|needs_review|none) ;; *) last=none ;; esac
  out="$(command heimdall activate --hook --cwd "$PWD" --shell-pid "$$" \
    --seq "$prev" --last "$last" </dev/null)"
  state="${out%% *}"
  rest="${out#* }"
  seq="${rest%% *}"
  recheck="${rest#* }"
  case "$state" in
    active|untrusted|paused|needs_review|none) ;;
    *) return 0 ;;
  esac
  case "$seq" in ''|*[!0-9]*|0?*|??????????*) return 0 ;; esac
  case "$recheck" in ''|*[!0-9]*|0?*|??????????*) return 0 ;; esac
  __heimdall_state="$state"
  __heimdall_seq="$seq"
  if [ "$recheck" -gt 0 ]; then
    __heimdall_due=$(( SECONDS + recheck ))
  else
    __heimdall_due=0
  fi
}

__heimdall_prompt() {
  local __heimdall_rc=$? due="${__heimdall_due:-0}"
  case "$due" in ''|*[!0-9]*|0?*|???????????*) due=0 ;; esac
  if [ "${__heimdall_pwd-}" != "$PWD" ]; then
    __heimdall_pwd="$PWD"
    __heimdall_hook
  elif [ "$due" -gt 0 ] && [ "$SECONDS" -ge "$due" ]; then
    __heimdall_hook
  fi
  return "$__heimdall_rc"
}

case ";${PROMPT_COMMAND-};" in
  *";__heimdall_prompt;"*) ;;
  *) PROMPT_COMMAND="__heimdall_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
"#;

/// Handle `shell init`: print the static script (`--json`: in the envelope).
pub(crate) fn shell_init(ctx: &Ctx, shell: ShellArg) -> ExitCode {
    let (name, script) = match shell {
        ShellArg::Zsh => ("zsh", ZSH_SCRIPT),
        ShellArg::Bash => ("bash", BASH_SCRIPT),
    };
    if ctx.json {
        output::emit(
            &Envelope::ok(serde_json::json!({ "shell": name, "script": script })),
            true,
        );
    } else {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(script.as_bytes());
        let _ = out.flush();
    }
    ExitCode::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use heimdall_contract::envelope::{MechanismGroup, NextAction};
    use heimdall_contract::ids::{AccountName, DestinationId};

    /// Every message the hook sends, in order; scripted answers per request kind.
    struct Recorder {
        sent: Vec<String>,
        answers: std::collections::HashMap<&'static str, Vec<Envelope<serde_json::Value>>>,
    }

    impl Session for Recorder {
        async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            if let Request::Ensure(e) = &request {
                // The hook's request: by context, covered only, never interactive.
                assert!(e.covered_only && e.context.is_some() && e.profile.is_none());
                assert_eq!(e.interaction, InteractionMode::NonInteractive);
                self.sent.push(format!("ensure {}", e.work_id));
            } else {
                self.sent.push(request.kind().to_owned());
            }
            let queue = self.answers.entry(request.kind()).or_default();
            if queue.is_empty() {
                Envelope::ok(serde_json::json!({}))
            } else {
                queue.remove(0)
            }
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            self.sent.push("attend".to_owned());
            Envelope::ok(serde_json::json!({}))
        }
    }

    fn refused(
        code: Code,
        why: Option<&str>,
        decision: Option<&str>,
    ) -> Envelope<serde_json::Value> {
        let mut e = heimdall_app::OpError::new(code, "refused".to_owned());
        if let Some(r) = why {
            e = e.with_reason(r);
        }
        if let Some(d) = decision {
            e = e.with_decision(d.to_owned());
        }
        output::error_value(e.into_envelope())
    }

    fn ready(uncovered: bool, workspace: bool) -> Envelope<serde_json::Value> {
        let mut v = serde_json::json!({
            "binding_id": "binding_00112233445566778899aabbccddeeff",
            "environment_id": "env_00112233445566778899aabbccddeeff",
            "profile_revision": 1,
            "grant_id": "grant_00112233445566778899aabbccddeeff",
            "expires_at": "2026-11-18T12:00:00Z",
            "usable_until": "2026-11-18T12:00:00Z",
            "offline_until": "2026-11-18T12:00:00Z",
            "refresh_dependency": "none",
            "credential_mechanism": "fake_agent",
            "enforcement": {
                "destination_scope": "client_routing",
                "new_authentication_expiry": "signer_only",
                "workload_isolation": "shared_os_user",
                "existing_connections": "graceful_dedicated_connections",
                "revocation": "local_applied"
            },
            "consumer": {},
            "context": {"kind": if workspace { "workspace" } else { "personal" },
                        "provenance": "same_user_context"},
        });
        if uncovered {
            v["uncovered"] = serde_json::json!([{"destination": "h3", "account": "deploy"}]);
        }
        Envelope {
            code: Code::AccessReady,
            ..Envelope::ok(v)
        }
    }

    fn workspace_view(matched: &str) -> Envelope<serde_json::Value> {
        Envelope::ok(serde_json::json!({
            "cwd": "/w", "match": matched, "provenance": "same_user_context"
        }))
    }

    fn holder() -> ProcessHolder {
        ProcessHolder {
            pid: 4242,
            started_at: "1700000000.000001".into(),
        }
    }

    fn run(
        answers: Vec<(&'static str, Envelope<serde_json::Value>)>,
        seq: u64,
    ) -> (Hooked, Vec<String>) {
        let mut r = Recorder {
            sent: Vec::new(),
            answers: std::collections::HashMap::new(),
        };
        for (k, e) in answers {
            r.answers.entry(k).or_default().push(e);
        }
        let now: Timestamp = "2026-11-18T09:00:00Z"
            .parse()
            .unwrap_or_else(|_| unreachable!());
        let hooked = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| unreachable!())
            .block_on(hook_flow(&mut r, "/w", &holder(), seq, "/bin/zsh", now));
        (hooked, r.sent)
    }

    /// Ruling 3, the client half, in process: whatever the runtime answers — a decision
    /// reference included, which the hook must never show or decide — the hook sends only
    /// `ensure` (by context, `covered_only`, noninteractive), `bind` and `inspect`, never
    /// `attend` or `decide`, and maps the answer to its state.
    #[test]
    fn the_hook_never_attends_or_decides_whatever_the_answer() {
        let dec = Some("dec_00112233445566778899aabbccddeeff");
        type Case = (Vec<(&'static str, Envelope<serde_json::Value>)>, HookState);
        let cases: Vec<Case> = vec![
            (vec![("ensure", ready(false, true))], HookState::Active),
            (vec![("ensure", ready(true, true))], HookState::NeedsReview),
            (
                vec![
                    ("ensure", ready(true, false)),
                    ("inspect", workspace_view("untrusted")),
                ],
                HookState::Untrusted,
            ),
            (
                vec![
                    (
                        "ensure",
                        refused(Code::InteractionRequired, Some(reason::NOT_COVERED), None),
                    ),
                    ("inspect", workspace_view("untrusted")),
                ],
                HookState::Untrusted,
            ),
            (
                vec![
                    (
                        "ensure",
                        refused(Code::InteractionRequired, Some(reason::NOT_COVERED), None),
                    ),
                    ("inspect", workspace_view("trusted")),
                ],
                HookState::NeedsReview,
            ),
            (
                vec![(
                    "ensure",
                    refused(
                        Code::ApprovalRequired,
                        Some(reason::WORKSPACE_UNTRUSTED),
                        dec,
                    ),
                )],
                HookState::NeedsReview,
            ),
            (
                vec![(
                    "ensure",
                    refused(
                        Code::InteractionRequired,
                        Some(reason::DECISION_COOLDOWN),
                        dec,
                    ),
                )],
                HookState::NeedsReview,
            ),
            (
                vec![("ensure", refused(Code::PolicyPaused, None, None))],
                HookState::Paused,
            ),
            (
                vec![(
                    "ensure",
                    refused(Code::CredentialExpired, Some(reason::WORK_STOPPED), None),
                )],
                HookState::Paused,
            ),
            (
                vec![("ensure", refused(Code::ServiceUnavailable, None, None))],
                HookState::Unavailable,
            ),
        ];
        for (answers, expected) in cases {
            let (hooked, sent) = run(answers, 0);
            assert_eq!(hooked.state, expected, "{sent:?}");
            assert!(
                sent.iter()
                    .all(|k| k.starts_with("ensure shell:4242.1700000000.000001.")
                        || k == "bind"
                        || k == "inspect"),
                "{sent:?}"
            );
            assert!(
                !sent.iter().any(|k| k == "attend" || k == "decide"),
                "{sent:?}"
            );
        }
    }

    /// ADR-0011 §3.3: a work whose binding ended starts the next work once (`n + 1`); a
    /// stopped work never does; mixed mechanisms are re-requested one group at a time under
    /// one work ID, and each activation is bound to the shell.
    #[test]
    fn the_hook_reenters_after_expiry_never_after_a_stop_and_splits_groups() {
        let (hooked, sent) = run(
            vec![
                ("ensure", refused(Code::CredentialExpired, None, None)),
                ("ensure", ready(false, true)),
            ],
            4,
        );
        assert_eq!(hooked.state, HookState::Active);
        assert_eq!(hooked.seq, 5);
        assert!(hooked.recheck_s > 0 && hooked.recheck_s <= 3 * 3600);
        assert_eq!(
            sent,
            [
                "ensure shell:4242.1700000000.000001.4",
                "ensure shell:4242.1700000000.000001.5",
                "bind"
            ]
        );
        let (hooked, sent) = run(
            vec![(
                "ensure",
                refused(Code::CredentialExpired, Some(reason::WORK_STOPPED), None),
            )],
            4,
        );
        assert_eq!((hooked.state, hooked.seq), (HookState::Paused, 4));
        assert_eq!(sent, ["ensure shell:4242.1700000000.000001.4"]);
        let pair = |d: &str| AccessPairRef {
            destination: DestinationId::parse(d).unwrap_or_else(|_| unreachable!()),
            account: AccountName::parse("deploy").unwrap_or_else(|_| unreachable!()),
        };
        let mut mixed = refused(Code::ConfigConflict, Some(reason::MIXED_MECHANISMS), None);
        mixed.next = Some(NextAction {
            action: "fix_request".into(),
            groups: vec![
                MechanismGroup {
                    mechanism: "managed_certificate".into(),
                    pairs: vec![pair("h1")],
                },
                MechanismGroup {
                    mechanism: "native_agent".into(),
                    pairs: vec![pair("h2")],
                },
            ],
            ..NextAction::default()
        });
        let (hooked, sent) = run(
            vec![
                ("ensure", mixed),
                ("ensure", ready(false, true)),
                ("ensure", ready(false, true)),
            ],
            0,
        );
        assert_eq!(hooked.state, HookState::Active);
        let w = "ensure shell:4242.1700000000.000001.0";
        assert_eq!(sent, [w, w, w, "bind", "bind"]);
    }

    /// Ruling I-13, option 2: the warm-up writes exactly one `SSH_AGENTC_REQUEST_IDENTITIES`
    /// frame (what ordinary `ssh` sends; no other request), waits for an answer that never
    /// comes only until the hook's deadline, and returns at once when no endpoint exists
    /// (no runtime): it never holds the prompt beyond the hook's budget.
    #[cfg(unix)]
    #[test]
    fn the_warm_up_sends_only_request_identities_and_ends_by_the_deadline() {
        use tokio::io::AsyncReadExt as _;
        let dir = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let path = dir.path().join("signing.sock");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| unreachable!());
        rt.block_on(async {
            let listener = tokio::net::UnixListener::bind(&path).unwrap_or_else(|_| unreachable!());
            // An endpoint that reads everything and never answers.
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap_or_else(|_| unreachable!());
                let mut seen = Vec::new();
                let _ = s.read_to_end(&mut seen).await;
                seen
            });
            let wait = Duration::from_millis(300);
            let start = tokio::time::Instant::now();
            warm(&AgentLocator::UnixSocket(path.clone()), start + wait).await;
            let took = start.elapsed();
            assert!(took >= wait && took < wait * 4, "{took:?}");
            let seen = server.await.unwrap_or_else(|_| unreachable!());
            assert_eq!(seen, agent_client::REQUEST_IDENTITIES_FRAME);

            let start = tokio::time::Instant::now();
            warm(
                &AgentLocator::UnixSocket(dir.path().join("absent.sock")),
                start + Duration::from_secs(5),
            )
            .await;
            assert!(start.elapsed() < Duration::from_secs(1));
        });
    }

    /// The status lines state a fact and name a command; none asks a question, and only
    /// the three states the ADR names have one.
    #[test]
    fn status_lines_never_ask() {
        for s in [
            HookState::Active,
            HookState::Untrusted,
            HookState::Paused,
            HookState::NeedsReview,
            HookState::None,
            HookState::Unavailable,
        ] {
            if let Some(line) = s.line() {
                assert!(!line.contains('?'), "{line}");
                assert!(!line.to_ascii_lowercase().contains("[y/n]"), "{line}");
            }
            assert_eq!(
                s.line().is_some(),
                matches!(
                    s,
                    HookState::Untrusted | HookState::Paused | HookState::NeedsReview
                )
            );
        }
    }

    /// The scripts are static: no `eval`, no unquoted `$PWD`, and Heimdall's answer is only
    /// ever compared with fixed patterns before use.
    #[test]
    fn the_scripts_never_evaluate_what_they_read() {
        for script in [ZSH_SCRIPT, BASH_SCRIPT] {
            let code: Vec<&str> = script
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .collect();
            for line in &code {
                assert!(!line.contains("eval"), "{line}");
                assert!(!line.contains('`'), "{line}");
                if line.contains("PWD") {
                    assert!(!line.contains(" $PWD") && !line.contains("=$PWD"), "{line}");
                }
            }
            assert!(script.contains(r#"--cwd "$PWD""#));
            assert!(script.contains("</dev/null"));
        }
    }
}
