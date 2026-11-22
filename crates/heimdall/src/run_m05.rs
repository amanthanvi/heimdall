//! ⟨M05⟩ U9a: `run` without `--profile` (ADR-0011 §3.1–§3.2, §5.3; the orchestrator's
//! re-issue reading I-9; m05-plan U4's client half, U9).
//!
//! `run` without `--profile` sends `ensure` with `context {cwd}` (the working directory the
//! program will run in) and no profile: the runtime discovers and observes the workspace,
//! reads its manifest itself, and resolves the request in its context — a trusted
//! workspace's policy, else the personal policy for the manifest's profile or the
//! environment's default profile (ADR-0011 §3.1). The CLI never reads the manifest.
//!
//! * **A decision before admission** (`workspace_untrusted`, `workspace_ambiguous`): on a
//!   terminal the decision's record is shown (the first-trust or reconcile text,
//!   `m05_cmd::recorded_preview`), a typed `yes` sends `Decide`, and the **same request**
//!   (same request ID) is sent again: the runtime admitted nothing for it, so the re-issue
//!   resolves in the trusted context the approval wrote and activates with no further
//!   decision (ADR-0011 §3.4). A waiting extension (`WidenPolicy{extend_scope}`) and a
//!   one-off `ApproveAuthority` take the same path, as for `access ensure`. At most
//!   [`MAX_DECISIONS`] decisions are taken per request; a `decision_cooldown` answer is
//!   never prompted (`cli::pending_decision`).
//! * **Mechanism groups** (`mixed_mechanisms` with `next.groups`; ADR-0011 §5.3, Q7): each
//!   group is requested in turn with the group's pairs as its `scope`, under the **same
//!   work ID** and its own request ID (`<request ID>.g<i>`), so the runtime caps every later
//!   group at the earliest group's deadline (`work_deadline`). `run_cmd` binds every group
//!   and launches once with their merged integration ([`merge_consumers`]).

use heimdall_contract::Code;
use heimdall_contract::envelope::{Envelope, reason};
use heimdall_contract::ids::RequestId;
use heimdall_contract::request::{ConsumerIntegration, EnsureRequest, Request, Verdict};

use crate::cli::{Prompter, Session};
use crate::client::Ctx;

/// The most owner decisions one `run` request takes (a trust, then the review of what it
/// still lacks).
pub(crate) const MAX_DECISIONS: usize = 2;

/// One activated group: the ready `ensure` answer and the request ID its `bind` reuses.
#[derive(Debug)]
pub(crate) struct Ensured {
    pub(crate) env: Envelope<serde_json::Value>,
    pub(crate) request_id: RequestId,
}

/// The request ID of group `i` of a request.
fn group_request_id(base: &RequestId, i: usize) -> Option<RequestId> {
    RequestId::parse(&format!("{base}.g{i}")).ok()
}

/// One `ensure` with the owner-present flow (module docs).
async fn decided_ensure<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    request: &EnsureRequest,
) -> Envelope<serde_json::Value> {
    if let Err(refused) = crate::cli::attend_first(s, ctx).await {
        return refused.env;
    }
    let mut env = s.request(Request::Ensure(request.clone())).await;
    for _ in 0..MAX_DECISIONS {
        let Some(decision) = crate::cli::pending_decision(&env) else {
            break;
        };
        if !ctx.interactive() {
            break;
        }
        let decided = crate::cli::confirm_and_decide(
            s,
            p,
            ctx,
            &decision,
            Verdict::Approve,
            env.operation_id.clone(),
            Some(&env.code),
        )
        .await;
        if decided.code != Code::Ok {
            return decided;
        }
        env = s.request(Request::Ensure(request.clone())).await;
    }
    env
}

/// `ensure` by context, split into its mechanism groups when the runtime asks for that
/// (module docs). `Err`: the answer that stops the run.
pub(crate) async fn ensure_by_context<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    request: &EnsureRequest,
) -> Result<Vec<Ensured>, Envelope<serde_json::Value>> {
    let first = decided_ensure(s, p, ctx, request).await;
    if first.code == Code::AccessReady {
        return Ok(vec![Ensured {
            env: first,
            request_id: request.request_id.clone(),
        }]);
    }
    let groups: Vec<_> = if first.data["error"]["reason"].as_str() == Some(reason::MIXED_MECHANISMS)
    {
        first
            .next
            .as_ref()
            .map(|n| n.groups.clone())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if groups.len() < 2 {
        return Err(first);
    }
    let mut out = Vec::new();
    for (i, group) in groups.into_iter().enumerate() {
        let Some(request_id) = group_request_id(&request.request_id, i) else {
            return Err(crate::output::error_value(crate::client::error(
                Code::UsageError,
                "the request ID is too long to name each mechanism group",
            )));
        };
        let one = EnsureRequest {
            scope: group.pairs.into_iter().collect(),
            request_id: request_id.clone(),
            ..request.clone()
        };
        let env = decided_ensure(s, p, ctx, &one).await;
        if env.code != Code::AccessReady {
            return Err(env);
        }
        out.push(Ensured { env, request_id });
    }
    Ok(out)
}

/// The integration a launch over several groups' bindings uses: every group's pairs, its
/// environment entries and its overrides. One agent locator is set only when every pair
/// names the same endpoint (`EnvDelta::from_integration`'s own rule), so groups served by
/// different endpoints never get one forced on them. A single group's integration is
/// returned unchanged.
#[must_use]
pub(crate) fn merge_consumers<'a>(
    mut all: impl Iterator<Item = &'a ConsumerIntegration>,
) -> ConsumerIntegration {
    let Some(first) = all.next() else {
        return ConsumerIntegration::default();
    };
    let mut merged = first.clone();
    for c in all {
        merged.pairs.extend(c.pairs.iter().cloned());
        for e in &c.environment {
            if !merged.environment.contains(e) {
                merged.environment.push(e.clone());
            }
        }
        for o in &c.overrides {
            if !merged.overrides.contains(o) {
                merged.overrides.push(o.clone());
            }
        }
        for x in &c.executables {
            if !merged.executables.contains(x) {
                merged.executables.push(x.clone());
            }
        }
        if merged.signing_endpoint != c.signing_endpoint {
            merged.signing_endpoint = None;
        }
        if merged.ssh_config_include != c.ssh_config_include {
            merged.ssh_config_include = None;
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use heimdall_contract::envelope::{MechanismGroup, NextAction};
    use heimdall_contract::ids::{AccountName, DestinationId, WorkId};
    use heimdall_contract::request::{
        AccessPairRef, InteractionMode, RequiredCapabilities, WaitMode,
    };
    use heimdall_contract::trust::WorkContext;

    use crate::prompt::Answer;

    struct Recorder {
        sent: Vec<String>,
        answers: Vec<Envelope<serde_json::Value>>,
    }

    impl Session for Recorder {
        async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            match &request {
                Request::Ensure(e) => self.sent.push(format!(
                    "ensure {} {} {}",
                    e.request_id,
                    e.work_id,
                    e.scope.len()
                )),
                other => self.sent.push(other.kind().to_owned()),
            }
            if matches!(request, Request::Ensure(_)) && !self.answers.is_empty() {
                self.answers.remove(0)
            } else if let Request::Inspect(_) = request {
                Envelope::ok(serde_json::json!({"decisions": [{
                    "decision_id": DEC, "kind": "trust_workspace", "expires_at": "x",
                    "request": {"kind": "trust_workspace", "action": {"action": "trust_workspace",
                        "cwd": "/w", "access_digest": "", "proposal": {"profile": "dev"}}}}]}))
            } else {
                Envelope::ok(serde_json::json!({}))
            }
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            self.sent.push("attend".into());
            Envelope::ok(serde_json::json!({}))
        }
    }

    struct Script(Vec<Answer>, Vec<String>);

    impl Prompter for Script {
        async fn ask(&mut self, text: &str) -> Answer {
            self.1.push(text.to_owned());
            self.0.remove(0)
        }
    }

    const DEC: &str = "dec_00112233445566778899aabbccddeeff";

    fn request() -> EnsureRequest {
        EnsureRequest {
            profile: None,
            profile_revision: None,
            scope: Default::default(),
            environment: None,
            work_id: WorkId::parse("w").unwrap_or_else(|_| unreachable!()),
            until: None,
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse("r").unwrap_or_else(|_| unreachable!()),
            interaction: InteractionMode::Interactive,
            wait: WaitMode::default(),
            connection: None,
            context: Some(WorkContext { cwd: "/w".into() }),
            covered_only: false,
            pair_issuers: Vec::new(),
        }
    }

    fn refusal(code: Code, why: &str, decision: bool) -> Envelope<serde_json::Value> {
        let mut e = heimdall_app::OpError::new(code, "x".to_owned()).with_reason(why);
        if decision {
            e = e.with_decision(DEC.to_owned());
        }
        crate::output::error_value(e.into_envelope())
    }

    fn ready() -> Envelope<serde_json::Value> {
        Envelope {
            code: Code::AccessReady,
            ..Envelope::ok(serde_json::json!({}))
        }
    }

    fn tty() -> Ctx {
        Ctx {
            json: true,
            non_interactive: false,
            home: None,
            stdin_tty: true,
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| unreachable!())
            .block_on(f)
    }

    /// I-9: a trust decision raised before admission is shown with the first-trust text,
    /// decided on a typed `yes`, and the **same** request (same request ID and work ID) is
    /// sent again; a `no` sends nothing more; a cooldown is never prompted.
    #[test]
    fn a_trust_decision_is_shown_decided_and_the_same_request_reissued() {
        let mut s = Recorder {
            sent: Vec::new(),
            answers: vec![
                refusal(Code::ApprovalRequired, reason::WORKSPACE_UNTRUSTED, true),
                ready(),
            ],
        };
        let mut p = Script(vec![Answer::Yes], Vec::new());
        let r = block_on(ensure_by_context(&mut s, &mut p, &tty(), &request()));
        assert!(r.is_ok());
        assert_eq!(
            s.sent,
            [
                "attend",
                "ensure r w 0",
                "inspect",
                "decide",
                "ensure r w 0"
            ]
        );
        assert!(
            p.1[0].contains("Use dev access automatically for this project?"),
            "{}",
            p.1[0]
        );
        let mut s = Recorder {
            sent: Vec::new(),
            answers: vec![refusal(
                Code::ApprovalRequired,
                reason::WORKSPACE_UNTRUSTED,
                true,
            )],
        };
        let mut p = Script(vec![Answer::No], Vec::new());
        let r = block_on(ensure_by_context(&mut s, &mut p, &tty(), &request()));
        let Err(e) = r else {
            panic!("refused");
        };
        assert_eq!(e.code, Code::InteractionRequired);
        assert_eq!(s.sent, ["attend", "ensure r w 0", "inspect"]);
        let mut s = Recorder {
            sent: Vec::new(),
            answers: vec![refusal(
                Code::ApprovalRequired,
                reason::DECISION_COOLDOWN,
                true,
            )],
        };
        let mut p = Script(Vec::new(), Vec::new());
        let r = block_on(ensure_by_context(&mut s, &mut p, &tty(), &request()));
        let Err(e) = r else {
            panic!("refused");
        };
        assert_eq!(e.code, Code::ApprovalRequired);
        assert_eq!(s.sent, ["attend", "ensure r w 0"]);
    }

    /// ADR-0011 §5.3: each `next.groups` group is requested with its pairs, under the same
    /// work ID, each with its own request ID.
    #[test]
    fn mixed_mechanisms_are_requested_group_by_group_under_one_work_id() {
        let pair = |d: &str| AccessPairRef {
            destination: DestinationId::parse(d).unwrap_or_else(|_| unreachable!()),
            account: AccountName::parse("deploy").unwrap_or_else(|_| unreachable!()),
        };
        let mut mixed = refusal(Code::ConfigConflict, reason::MIXED_MECHANISMS, false);
        mixed.next = Some(NextAction {
            action: "fix_request".into(),
            groups: vec![
                MechanismGroup {
                    mechanism: "managed_certificate".into(),
                    pairs: vec![pair("h1")],
                },
                MechanismGroup {
                    mechanism: "native_agent".into(),
                    pairs: vec![pair("h2"), pair("h3")],
                },
            ],
            ..NextAction::default()
        });
        let mut s = Recorder {
            sent: Vec::new(),
            answers: vec![mixed, ready(), ready()],
        };
        let mut p = Script(Vec::new(), Vec::new());
        let r = block_on(ensure_by_context(&mut s, &mut p, &tty(), &request()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].request_id.as_str(), "r.g1");
        assert_eq!(
            s.sent,
            [
                "attend",
                "ensure r w 0",
                "attend",
                "ensure r.g0 w 1",
                "attend",
                "ensure r.g1 w 2"
            ]
        );
    }
}
