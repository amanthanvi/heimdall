//! M04 command surface (ADR-0010 §2, §3, §9 items 2 and 9; m04-plan U3).
//!
//! * `wsl enable|disable|status` (U3b): Mode A through the runtime's `wsl_enable` and
//!   `wsl_disable` and the M02 setup flow for the distribution's Git item. ⟨U4b⟩ `enable
//!   --mode-b` goes through the decision flow as `container add` does: the session is
//!   attended first, the exact recorded `AddEnvironment` decision is shown with its three
//!   disclosures, a typed `yes` is required, and only then is `Decide approve` sent;
//!   `disable` ends Mode B too (the environment's bindings end and withdraw, the helper
//!   stops).
//! * `internal wsl-helper` (U3a): the in-distribution helper of `heimdall-wsl/1`.
//! * [`refusal_envelope`]: the wave-0 refusal (`USAGE_ERROR`, "planned for M04"), now only
//!   the unreachable `internal wsl-helper` arm of `m03_cmd::internal` answers it; every M04
//!   command is built.

use heimdall_contract::envelope::Envelope;
use heimdall_contract::{Code, ExitCode};

use crate::client::{Ctx, error};
use crate::output;

/// The message of the refusal, assembled at run time (the M02 and M03 source guards scan
/// for the unassembled text).
pub(crate) fn refusal_message() -> String {
    [
        "this command is not available",
        "in this build (planned for M04)",
    ]
    .join(" ")
}

/// The envelope an M04 command answers until its unit lands.
pub(crate) fn refusal_envelope() -> Envelope<serde_json::Value> {
    output::error_value(error(Code::UsageError, &refusal_message()))
}

/// The refusal of `internal wsl-helper` run by a person: the helper is started by the Windows
/// runtime on a pipe, inside a distribution (ADR-0010 §3 item 3). A terminal on stdin names
/// the terminal; a non-Linux host without the test configuration cannot run it at all.
pub(crate) fn internal_helper_envelope(stdin_tty: bool) -> Envelope<serde_json::Value> {
    let message = if stdin_tty {
        "internal wsl-helper is started by the runtime and refuses a terminal on stdin"
    } else {
        "internal wsl-helper runs only as the runtime's child inside a WSL distribution"
    };
    output::error_value(error(Code::UsageError, message))
}

/// ⟨M04 U3a⟩ `heimdall internal wsl-helper` (ADR-0010 §3 items 3–4, 8): the Linux helper that
/// serves the `heimdall-wsl/1` channel over stdin and stdout, so stdout carries nothing but
/// protocol frames. Guards, as `internal issuer`'s: a terminal on stdin is refused with the
/// envelope; a non-Linux host is refused unless a debug build carries the `HEIMDALL_TEST_WSL_*`
/// configuration (the channel tests run the helper on macOS); a release build refuses every
/// test variable. The status is the helper's: 0, [`EXIT_PROTOCOL`] after a protocol error,
/// usage (2) for a refused configuration, unavailable (5) when the account cannot be read.
///
/// [`EXIT_PROTOCOL`]: heimdall_wsl::proto::EXIT_PROTOCOL
pub(crate) fn helper(ctx: &Ctx) -> ExitCode {
    let env = |name: &str| std::env::var_os(name);
    let refuse = || {
        let env = internal_helper_envelope(ctx.stdin_tty);
        output::emit(&env, ctx.json);
        output::exit_code_for(env.code, false)
    };
    if ctx.stdin_tty
        || crate::testcfg::refusal(
            crate::testcfg::AVAILABLE,
            crate::testcfg::requested_by(&env),
        )
        .is_some()
    {
        return refuse();
    }
    let status = match helper_env(&env) {
        Ok(Some(henv)) => heimdall_wsl::helper::serve(&henv, std::io::stdin(), std::io::stdout()),
        Ok(None) if !cfg!(target_os = "linux") => return refuse(),
        Ok(None) => match heimdall_wsl::helper::HelperEnv::production() {
            Ok(henv) => heimdall_wsl::helper::serve(&henv, std::io::stdin(), std::io::stdout()),
            Err(_) => heimdall_wsl::helper::EXIT_UNAVAILABLE,
        },
        Err(_) => heimdall_wsl::helper::EXIT_USAGE,
    };
    match status {
        0 => ExitCode::Success,
        heimdall_wsl::helper::EXIT_USAGE => ExitCode::Usage,
        heimdall_wsl::helper::EXIT_UNAVAILABLE => ExitCode::Unavailable,
        other => std::process::exit(other),
    }
}

/// The helper's test environment: debug builds read `HEIMDALL_TEST_WSL_*`; a release build has
/// none (and has already refused the variables).
#[cfg(debug_assertions)]
fn helper_env(
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<Option<heimdall_wsl::helper::HelperEnv>, String> {
    crate::testcfg::wsl_helper_env(env)
}

#[cfg(not(debug_assertions))]
fn helper_env(
    _env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<Option<heimdall_wsl::helper::HelperEnv>, String> {
    Ok(None)
}

// --- ⟨M04 U3b⟩ wsl enable | disable | status (ADR-0010 §2, §9 item 2) ---------------------------

/// The WSL host this command reads: the platform's (Lxss and `wsl.exe` on Windows, none
/// elsewhere), with the debug-only test configuration's helper path.
fn wsl_host() -> heimdall_wsl::WslHost {
    // ⟨M04 W2⟩ The test configuration's directly started stand-in, when it names one (a
    // malformed one answers as no WSL here; the runtime refuses it at start).
    #[cfg(debug_assertions)]
    if let Ok(Some(host)) = crate::testcfg::wsl_direct_host(&|n| std::env::var_os(n)) {
        return host;
    }
    #[cfg(debug_assertions)]
    let helper = std::env::var_os(crate::testcfg::WSL_HELPER_ENV).map(std::path::PathBuf::from);
    #[cfg(not(debug_assertions))]
    let helper = None;
    heimdall_wsl::WslHost::platform(helper)
}

fn wsl_failure(code: Code, why: &str, message: &str) -> crate::setup_cmd::Outcome {
    crate::setup_cmd::Outcome::of(crate::setup_cmd::failure(code, message, Some(why)))
}

/// The registered distribution named `name` (identity is its GUID; a name two
/// registrations share is refused rather than guessed).
fn select(
    host: &heimdall_wsl::WslHost,
    name: &str,
) -> Result<heimdall_app::ports::DiscoveredDistribution, crate::setup_cmd::Outcome> {
    use heimdall_app::ports::DistributionHost as _;
    use heimdall_contract::envelope::reason;
    let listed = host.discover().map_err(|_| {
        wsl_failure(
            Code::CapabilityUnavailable,
            reason::WSL_UNAVAILABLE,
            "WSL is not available on this host",
        )
    })?;
    let mut found = listed.into_iter().filter(|d| d.name == name);
    match (found.next(), found.next()) {
        (Some(d), None) => Ok(d),
        (Some(_), Some(_)) => Err(crate::setup_cmd::usage(
            "two registered distributions have this name; rename one first",
        )),
        (None, _) => Err(wsl_failure(
            Code::NotFound,
            reason::WSL_DISTRIBUTION_UNKNOWN,
            "no registered WSL distribution has this name",
        )),
    }
}

/// The distribution's default Linux account, read by running `id -un` inside it (an
/// explicit `wsl enable`, which may start it). `None` when it cannot be read: the owner then
/// names it with `--account`.
fn default_account(name: &str) -> Option<String> {
    if !heimdall_wsl::spawn::is_plain_argument(name) {
        return None;
    }
    let system_root = std::env::var("SystemRoot").ok();
    let exe = heimdall_wsl::spawn::wsl_exe_path(system_root.as_deref());
    let cmd = heimdall_wsl::spawn::wsl_command(
        &exe,
        &["-d", name, "--exec", "/usr/bin/id", "-un"],
        &|k| std::env::var_os(k),
    );
    let out = heimdall_wsl::spawn::run_bounded(&cmd, std::time::Duration::from_secs(60)).ok()?;
    if out.status != 0 {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let account = text.trim();
    heimdall_app::operations::wsl_m04::account_ok(account).then(|| account.to_owned())
}

fn distribution_intent(
    guid: &heimdall_contract::environment::DistributionGuid,
    rollback: bool,
) -> heimdall_contract::setup::PreviewIntent {
    use heimdall_contract::setup::{PreviewIntent, ProjectionItem};
    let items = std::iter::once(ProjectionItem::DistributionGit).collect();
    if rollback {
        PreviewIntent::Rollback {
            keep_key_files: false,
            items,
            distribution: Some(guid.clone()),
        }
    } else {
        PreviewIntent::Apply {
            include_git: false,
            items,
            distribution: Some(guid.clone()),
        }
    }
}

async fn wsl_session(ctx: &Ctx) -> Result<crate::client::Client, crate::setup_cmd::Outcome> {
    use heimdall_contract::ipc::capability::{ENVIRONMENTS_V1, SETUP_V1};
    crate::client::connect_requiring(ctx, true, &[SETUP_V1, ENVIRONMENTS_V1])
        .await
        .map_err(|e| crate::setup_cmd::Outcome::of(output::error_value(*e)))
}

/// `heimdall wsl enable <distribution> [--account <name>] --mode-a|--mode-b`: record the
/// distribution with the runtime (`wsl_enable`), then, for Mode A, preview, confirm and
/// apply its Git item through the M02 setup flow (ADR-0010 §2 item 2: setup-confirmed, no
/// decision record). `--mode-b` is decision-recorded instead ([`enable_mode_b`]); clap
/// refuses the two flags together.
pub(crate) fn enable(ctx: &Ctx, args: crate::cli::WslEnableArgs) -> ExitCode {
    crate::setup_cmd::block(ctx, async move {
        use heimdall_contract::environment::EnvironmentRequest;
        use heimdall_contract::request::Request;
        if !args.mode_a && !args.mode_b {
            return crate::setup_cmd::usage("name a mode: --mode-a or --mode-b");
        }
        let host = wsl_host();
        let d = match select(&host, &args.distribution) {
            Ok(d) => d,
            Err(o) => return o,
        };
        let Some(account) = args.account.clone().or_else(|| default_account(&d.name)) else {
            return crate::setup_cmd::usage(
                "the distribution's default account could not be read: name it with --account",
            );
        };
        let mut client = match wsl_session(ctx).await {
            Ok(c) => c,
            Err(o) => return o,
        };
        if args.mode_b {
            return enable_mode_b(
                &mut client,
                &mut crate::cli::TerminalPrompt,
                ctx,
                &d.guid,
                account,
            )
            .await;
        }
        let env = client
            .request(Request::Environment(EnvironmentRequest::WslEnable {
                distribution_guid: d.guid.clone(),
                account,
                mode_a: args.mode_a,
                mode_b: args.mode_b,
            }))
            .await;
        if !env.code.is_success() || !args.mode_a {
            return crate::setup_cmd::result_outcome(env);
        }
        let rid = match crate::setup_cmd::request_id(None) {
            Ok(r) => r,
            Err(o) => return o,
        };
        crate::setup_cmd::setup_flow(
            &mut client,
            &mut crate::cli::TerminalPrompt,
            ctx,
            &distribution_intent(&d.guid, false),
            rid,
        )
        .await
    })
}

/// The preface of the Mode B `AddEnvironment` confirmation (ADR-0010 §3 "Non-claims", item 14).
const MODE_B_PREFACE: &str = "Enable WSL Mode B for this distribution (ADR-0010 §3). Heimdall will run a helper inside the distribution that exposes one binding's signing endpoint and public files at a socket only the distribution account can use; the private key stays in Windows. WSL is not a boundary from your Windows user: any process of your Windows user, and the distribution's root, can use the endpoint (wsl.exe -d), and a Linux user who can use interop can become the account that owns it (wsl.exe -u). An active binding keeps the distribution running.";

/// `wsl enable --mode-b`: the runtime answers the request with an `AddEnvironment`
/// decision (host, account and registration rules first, nothing written when they refuse).
/// On an interactive terminal the session is attended first, the exact recorded decision is
/// shown, a typed `yes` is required and only then is `Decide approve` sent; the answer is the
/// environment's view. Otherwise nothing more is sent and the command exits 3 with
/// `next.decision_ref`. An already enabled distribution answers `OK` at once.
async fn enable_mode_b<S: crate::cli::Session, P: crate::cli::Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    guid: &heimdall_contract::environment::DistributionGuid,
    account: String,
) -> crate::setup_cmd::Outcome {
    use heimdall_contract::environment::EnvironmentRequest;
    use heimdall_contract::request::Request;
    if let Err(refused) = crate::setup_cmd::attend_first(s, ctx).await {
        return crate::setup_cmd::Outcome::of(refused);
    }
    let request = Request::Environment(EnvironmentRequest::WslEnable {
        distribution_guid: guid.clone(),
        account,
        mode_a: false,
        mode_b: true,
    });
    let env = s.request(request.clone()).await;
    let decided = crate::setup_cmd::approve_request(
        s,
        p,
        ctx,
        &request,
        env,
        |_| Ok(MODE_B_PREFACE.to_owned()),
        None,
    )
    .await
    .unwrap_or_else(|env| env);
    crate::setup_cmd::Outcome::of(decided)
}

/// `heimdall wsl disable <distribution> [--start]` (ADR-0010 §3 item 13, §9 item 2): ask the
/// runtime to end Mode A. While its Git item is still applied and the distribution runs (or
/// `--start` authorizes starting it), the runtime asks for the rollback first: preview,
/// confirm and apply it, then disable. A stopped distribution without `--start` is never
/// started: its rollback stays a retained, reported obligation (`cleanup_pending`).
pub(crate) fn disable(ctx: &Ctx, args: crate::cli::WslDisableArgs) -> ExitCode {
    crate::setup_cmd::block(ctx, async move {
        use heimdall_contract::environment::EnvironmentRequest;
        use heimdall_contract::request::Request;
        let host = wsl_host();
        let d = match select(&host, &args.distribution) {
            Ok(d) => d,
            Err(o) => return o,
        };
        let mut client = match wsl_session(ctx).await {
            Ok(c) => c,
            Err(o) => return o,
        };
        let request = Request::Environment(EnvironmentRequest::WslDisable {
            distribution_guid: d.guid.clone(),
            start: args.start,
        });
        let env = client.request(request.clone()).await;
        if env.code != Code::ConfigConflict {
            return crate::setup_cmd::result_outcome(env);
        }
        // The item is still applied and reachable: roll it back through the setup flow.
        let rid = match crate::setup_cmd::request_id(None) {
            Ok(r) => r,
            Err(o) => return o,
        };
        let rolled = crate::setup_cmd::setup_flow(
            &mut client,
            &mut crate::cli::TerminalPrompt,
            ctx,
            &distribution_intent(&d.guid, true),
            rid,
        )
        .await;
        if !rolled.env.code.is_success() {
            return rolled;
        }
        crate::setup_cmd::result_outcome(client.request(request).await)
    })
}

/// `heimdall wsl status` (read-only): the registered distributions (Lxss, read without
/// changes), whether each runs (`wsl.exe --list --running --quiet`, which starts nothing),
/// and which ones the runtime serves (`inspect environments`, when a runtime runs; this
/// command never starts one).
pub(crate) fn status(ctx: &Ctx) -> ExitCode {
    crate::setup_cmd::block(ctx, async move {
        use heimdall_app::ports::{DistributionHost as _, RunningState};
        use heimdall_contract::envelope::reason;
        use heimdall_contract::request::{InspectRequest, InspectSubject, Request};
        let host = wsl_host();
        let Ok(listed) = host.discover() else {
            return wsl_failure(
                Code::CapabilityUnavailable,
                reason::WSL_UNAVAILABLE,
                "WSL is not available on this host",
            );
        };
        let served: Vec<serde_json::Value> = match crate::client::connect_requiring(
            ctx,
            false,
            &[heimdall_contract::ipc::capability::ENVIRONMENTS_V1],
        )
        .await
        {
            Ok(mut c) => {
                let env = c
                    .request(Request::Inspect(InspectRequest {
                        subject: InspectSubject::Environments,
                        preview: None,
                        cwd: None,
                        redact: false,
                        select: None,
                        page: None,
                    }))
                    .await;
                env.data["items"].as_array().cloned().unwrap_or_default()
            }
            Err(_) => Vec::new(),
        };
        let rows: Vec<serde_json::Value> = listed
            .iter()
            .map(|d| {
                let running = match host.running(&d.guid) {
                    RunningState::Running => "running",
                    RunningState::NotRunning => "stopped",
                    RunningState::Unknown => "unknown",
                };
                let mine: Vec<&serde_json::Value> = served
                    .iter()
                    .filter(|v| v["realization"]["guid"] == serde_json::json!(d.guid))
                    .collect();
                serde_json::json!({
                    "guid": d.guid,
                    "name": d.name,
                    "version": d.version,
                    "running": running,
                    "served": mine,
                })
            })
            .collect();
        let human = rows
            .iter()
            .map(|r| {
                format!(
                    "{} ({}, {}){}",
                    r["name"].as_str().unwrap_or(""),
                    r["guid"].as_str().unwrap_or(""),
                    r["running"].as_str().unwrap_or(""),
                    if r["served"].as_array().is_some_and(|a| !a.is_empty()) {
                        ": served by Heimdall"
                    } else {
                        ""
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        crate::setup_cmd::Outcome::of(Envelope::ok(serde_json::json!({ "distributions": rows })))
            .with_human(human)
    })
}

/// ⟨M04 U3b⟩ Uninstall's WSL step: for each distribution the runtime serves in Mode A
/// (`inspect environments`), end Mode A as `wsl disable` does on `s`, never starting a
/// distribution. One report row each: `outcome` `disabled`, `retained` (stopped: its
/// rollback is a kept obligation) or `failed` (with the envelope's code and reason).
pub(crate) async fn uninstall_distributions<S: crate::cli::Session, P: crate::cli::Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
) -> Vec<serde_json::Value> {
    use heimdall_contract::environment::{DistributionGuid, EnvironmentRequest};
    use heimdall_contract::request::{InspectRequest, InspectSubject, Request};
    let listed = s
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Environments,
            preview: None,
            cwd: None,
            redact: false,
            select: None,
            page: None,
        }))
        .await;
    let rows: Vec<serde_json::Value> = listed.data["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        // ⟨M04 W2⟩ Mode A and Mode B alike: `wsl disable` rolls Mode A back and retires a
        // Mode B environment (its endpoints withdraw; a stopped distribution's leftovers are
        // a retained obligation, as Mode A's rollback is).
        .filter(|v| {
            v["kind"] == "wsl_distribution" && v["state"] != "removed" && v["state"] != "gone"
        })
        .collect();
    let mut out = Vec::new();
    for row in rows {
        let Ok(guid) =
            serde_json::from_value::<DistributionGuid>(row["realization"]["guid"].clone())
        else {
            continue;
        };
        let name = row["realization"]["name"].clone();
        let request = Request::Environment(EnvironmentRequest::WslDisable {
            distribution_guid: guid.clone(),
            start: false,
        });
        let mut env = s.request(request.clone()).await;
        if env.code == Code::ConfigConflict {
            // Still applied and reachable: the rollback, through the setup flow.
            let rolled = match crate::setup_cmd::request_id(None) {
                Ok(rid) => {
                    crate::setup_cmd::setup_flow(s, p, ctx, &distribution_intent(&guid, true), rid)
                        .await
                        .env
                }
                Err(o) => o.env,
            };
            env = if rolled.code.is_success() {
                s.request(request).await
            } else {
                rolled
            };
        }
        let outcome = if !env.code.is_success() {
            "failed"
        } else if env.data["cleanup_pending"] == true {
            "retained"
        } else {
            "disabled"
        };
        let reason = env.data["error"]["reason"].clone();
        out.push(serde_json::json!({
            "guid": guid,
            "name": name,
            "outcome": outcome,
            "code": env.code,
            "reason": reason,
            "next": (outcome == "retained").then(|| format!(
                "heimdall wsl disable {} --start",
                name.as_str().unwrap_or("<distribution>")
            )),
        }));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// `internal wsl-helper` run by a person: the terminal and the non-Linux refusals are
    /// `USAGE_ERROR` envelopes that name the cause (the helper's stdout is otherwise protocol
    /// frames only), like `internal issuer`'s.
    #[test]
    fn internal_wsl_helper_refuses_a_terminal_and_a_foreign_host() {
        let message = |tty| {
            serde_json::to_value(internal_helper_envelope(tty)).unwrap()["data"]["error"]["message"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert!(message(true).contains("refuses a terminal on stdin"));
        assert!(message(false).contains("inside a WSL distribution"));
        assert_ne!(message(true), message(false));
        assert_ne!(message(false), refusal_message());
    }

    /// ⟨M04 W2⟩ Uninstall's distribution step: every active WSL distribution row, Mode A or
    /// Mode B alike, gets `wsl disable` without `start`; a removed or gone environment and a
    /// container are left alone; a disable that kept a cleanup (a stopped distribution) is
    /// `retained`, with the owner's explicit start as its next step.
    #[tokio::test]
    async fn uninstall_disables_mode_a_and_mode_b_distributions_never_starting_one() {
        use heimdall_contract::Code;
        use heimdall_contract::envelope::Envelope;
        use heimdall_contract::request::Request;

        const A: &str = "0b1c2d3e-1111-4222-8333-abcdef01234a";
        const B: &str = "0b1c2d3e-1111-4222-8333-abcdef01234b";
        const GONE: &str = "0b1c2d3e-1111-4222-8333-abcdef01234c";
        struct Fake {
            disabled: Vec<(String, bool)>,
        }
        impl crate::cli::Session for Fake {
            async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
                match request {
                    Request::Inspect(_) => {
                        let wsl = |guid: &str, state: &str, modes: &[&str]| {
                            serde_json::json!({"kind": "wsl_distribution", "state": state,
                                "realization": {"guid": guid, "name": guid, "modes": modes}})
                        };
                        Envelope::ok(serde_json::json!({"items": [
                            wsl(A, "active", &["a"]),
                            wsl(B, "not_running", &["b"]),
                            wsl(GONE, "removed", &["b"]),
                            {"kind": "container", "state": "active", "realization": {}},
                        ]}))
                    }
                    Request::Environment(
                        heimdall_contract::environment::EnvironmentRequest::WslDisable {
                            distribution_guid,
                            start,
                        },
                    ) => {
                        let guid = serde_json::to_value(&distribution_guid).unwrap();
                        let guid = guid.as_str().unwrap().to_owned();
                        let pending = guid == B;
                        self.disabled.push((guid, start));
                        Envelope::ok(serde_json::json!({"cleanup_pending": pending}))
                    }
                    other => panic!("unexpected request {}", other.kind()),
                }
            }
            async fn attend(&mut self) -> Envelope<serde_json::Value> {
                panic!("uninstall's distribution step never asks for attendance")
            }
        }
        struct NoPrompt;
        impl crate::cli::Prompter for NoPrompt {
            async fn ask(&mut self, text: &str) -> crate::prompt::Answer {
                panic!("unexpected prompt: {text}")
            }
        }
        let ctx = Ctx {
            json: true,
            non_interactive: true,
            home: None,
            stdin_tty: false,
            request_epoch: None,
        };
        let mut s = Fake {
            disabled: Vec::new(),
        };
        let out = uninstall_distributions(&mut s, &mut NoPrompt, &ctx).await;
        assert_eq!(
            s.disabled,
            vec![(A.to_owned(), false), (B.to_owned(), false)],
            "each active distribution, never started"
        );
        let outcome = |guid: &str| {
            out.iter()
                .find(|r| r["guid"] == guid)
                .map(|r| (r["outcome"].clone(), r["next"].clone(), r["code"].clone()))
                .unwrap()
        };
        assert_eq!(outcome(A).0, "disabled");
        assert_eq!(outcome(B).0, "retained");
        assert_eq!(
            outcome(B).1,
            format!("heimdall wsl disable {B} --start").as_str()
        );
        assert_eq!(outcome(A).2, serde_json::to_value(Code::Ok).unwrap());
        assert_eq!(out.len(), 2);
    }
}
