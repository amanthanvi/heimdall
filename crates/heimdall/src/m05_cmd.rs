//! ⟨M05⟩ U9a: the M05 command line (ADR-0011 §2–§7, §10 items 3 and 9; ADR-0006 §17.6
//! item 14 and §17.9; m05-plan U9). `activate_cmd` answers `activate` and `shell init`,
//! `portable_cmd` `export` and `import`, `run_m05` `run` without `--profile`.
//!
//! **Final syntax** (ADR-0006 §17.6 item 14 left `access allow` and `access stop` to M05):
//!
//! | Command | Request | Owner decision |
//! |---|---|---|
//! | `project status [--cwd P]` | `inspect workspace` (read-only; never starts the runtime) | no |
//! | `project trust [--cwd P] [--profile X]` | `policy trust_workspace {cwd, access_digest, proposal}` | yes: the spec §5.2 first-trust text and the proposal, then `Decide` |
//! | `project untrust [--cwd P]` | `policy remove` of the workspace's policy (narrowing) | no |
//! | `project reconcile [--cwd P]` | `policy reconcile_workspace {workspace, cwd}` | yes |
//! | `access allow --policy P` | `policy extend_scope` of P to its profile's current definition | yes |
//! | `access allow --profile X` | `extend_scope` of each policy of X; `create` (personal) when X has none | yes |
//! | `access allow --profile X --environment E` | ⟨M06 W5⟩ `create` (personal) naming the paired runner E only: this controller's authorization to issue for the grants E admits for X; nothing local | yes |
//! | `access allow --workspace [--cwd P]` | an untrusted workspace's `trust_workspace`; an ambiguous one's `reconcile_workspace`; a trusted one's `extend_scope` to its manifest's request | yes |
//! | `access stop --work W [--request-id R]` | `revoke {target: work}` | no |
//! | `access stop --policy P \| --profile X \| --workspace [--cwd P] \| --all` | `policy stop {target}` | no |
//! | `access pause\|resume\|cutoff --profile X \| --workspace [--cwd P] \| --all` | the action with its `target` | `resume`, a later `cutoff`, `--clear` |
//! | `access default-profile [X \| --clear]` | `catalog set_default_profile`; with neither, `inspect policies` | no |
//!
//! **Owner-present flow** ([`owner_request`]). A widening request attends first (an
//! interactive terminal only; ADR-0006 §13.6 item 7), then is sent. When the runtime answers
//! with a pending decision, the decision's own record is shown (`cli::confirm_and_decide`,
//! with [`recorded_preview`]'s first-trust, reconcile or review text), a typed `yes` sends
//! `Decide`, and the same request is sent again so its applied result is reported. A
//! narrowing never attends. `access allow` is an owner-initiated review: its `policy`
//! request always creates (or shares) its own record and never consults a requester cooldown
//! (ADR-0011 §4.3). A `decision_cooldown` answer names the denied record, which is never
//! shown as pending (`cli::pending_decision`).
//!
//! **The proposal a trust request names.** ADR-0011 I5: the runtime compares a
//! `trust_workspace` request's proposal and access digest with its own observation and
//! computation, refuses any difference with nothing written, and its record shows its own
//! proposal. ADR-0011 §2.2: the runtime reads the manifest and the client never does. The
//! CLI therefore takes the proposal and the access digest from the runtime's `inspect
//! workspace` answer (`WorkspaceView.proposal`, ADR-0006 §17.10 item 21: the manifest's
//! request ∩ the profile's latest snapshot, built by the code `trust_workspace` compares
//! with) and sends them back unchanged; it runs no observer and reads no manifest
//! ([`workspace_request`]). A manifest-less root keeps the owner's own profile choice
//! (`--profile`, else this environment's default). What the owner approves is always the
//! record the runtime wrote, shown from `inspect decisions`; the project label is shown
//! only from that record, as quoted data.
//!
//! Every human string passes through `output::sanitize_for_terminal`; IDs, paths and labels
//! from the runtime are data, never part of a command the CLI runs. A path or a label is
//! shown as one quoted field (`output::quoted_field`: line breaks escaped, bidirectional and
//! invisible formatting characters removed; review M05-W3-R03), so it can neither add a
//! line nor reorder the text around it. A `create` review shows the scope the runtime
//! recorded for its decision (ADR-0006 §17.10 item 22; review M05-W3-R01), and its approval
//! is refused when there is none ([`approve_block`]).

use std::collections::BTreeSet;
use std::path::Path;

use heimdall_contract::catalog::CatalogRequest;
use heimdall_contract::envelope::{Envelope, reason};
use heimdall_contract::ids::{EnvironmentId, PolicyId, ProfileId, WorkId};
use heimdall_contract::ipc::capability;
use heimdall_contract::request::{
    AccessPairRef, Capability, InspectRequest, InspectSubject, PolicyAction, Request,
    RevokeRequest, Verdict,
};
use heimdall_contract::trust::{
    PoliciesView, PolicyTarget, PolicyTargetResult, RevokeTarget, TrustProposal, WorkContext,
    WorkspaceMatchView, WorkspaceView,
};
use heimdall_contract::{Code, ExitCode, Timestamp};

use crate::cli::{
    AccessAllowArgs, AccessCommand, AccessDefaultProfileArgs, AccessStopArgs, AccessTarget,
    ProjectCommand, ProjectTrustArgs, Prompter, Session, TerminalPrompt,
};
use crate::client::{Client, Ctx};
use crate::output;
use crate::setup_cmd::{Outcome, block, failure, request_id, usage};

// ---------------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------------

/// A control session that requires `trusted-work/1` in its hello, so a runtime without
/// it refuses the hello (`SCHEMA_UNSUPPORTED`) instead of a later request.
pub(crate) async fn session(ctx: &Ctx, allow_start: bool) -> Result<Client, Outcome> {
    crate::client::connect_requiring(ctx, allow_start, &[capability::TRUSTED_WORK_V1])
        .await
        .map_err(|e| Outcome::of(output::error_value(*e)))
}

/// The working directory a command names: `given` made absolute against the current
/// directory (never canonicalized here: the runtime canonicalizes what it observes), as
/// a [`WorkContext`] accepts it (absolute, 1 to 4096 bytes of Unicode, no NUL).
pub(crate) fn cwd_of(given: Option<&Path>) -> Result<String, Outcome> {
    let base = || {
        std::env::current_dir().map_err(|e| {
            usage(&format!(
                "the working directory cannot be read: {}",
                e.kind()
            ))
        })
    };
    let path = match given {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => base()?.join(p),
        None => base()?,
    };
    let Some(text) = path.to_str() else {
        return Err(usage("the directory's path is not valid Unicode"));
    };
    let cwd = text.to_owned();
    if (WorkContext { cwd: cwd.clone() }).validate().is_err() {
        return Err(usage(
            "the directory is an absolute path of 1 to 4096 bytes without NUL",
        ));
    }
    Ok(cwd)
}

/// One `inspect` request's data, or its refusal.
async fn read<S: Session>(
    s: &mut S,
    request: InspectRequest,
) -> Result<serde_json::Value, Outcome> {
    let env = s.request(Request::Inspect(request)).await;
    if env.code.is_success() {
        Ok(env.data)
    } else {
        Err(Outcome::of(env))
    }
}

fn unreadable(what: &str) -> Outcome {
    Outcome::of(failure(
        Code::InternalError,
        &format!("the runtime's {what} cannot be read"),
        None,
    ))
}

/// `inspect workspace` of `cwd`.
pub(crate) async fn workspace<S: Session>(s: &mut S, cwd: &str) -> Result<WorkspaceView, Outcome> {
    let data = read(
        s,
        InspectRequest {
            subject: InspectSubject::Workspace,
            preview: None,
            cwd: Some(cwd.to_owned()),
            redact: false,
        },
    )
    .await?;
    serde_json::from_value(data).map_err(|_| unreadable("workspace view"))
}

async fn policies<S: Session>(s: &mut S) -> Result<PoliciesView, Outcome> {
    let data = read(
        s,
        InspectRequest {
            subject: InspectSubject::Policies,
            preview: None,
            cwd: None,
            redact: false,
        },
    )
    .await?;
    serde_json::from_value(data).map_err(|_| unreadable("policies"))
}

/// A profile as `inspect profiles` answers it (the latest definition).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub(crate) struct ProfileDef {
    pub(crate) profile_id: ProfileId,
    #[serde(default)]
    pub(crate) pairs: BTreeSet<AccessPairRef>,
    #[serde(default)]
    pub(crate) capabilities: BTreeSet<Capability>,
}

async fn profile_def<S: Session>(s: &mut S, id: &ProfileId) -> Result<Option<ProfileDef>, Outcome> {
    let data = read(
        s,
        InspectRequest {
            subject: InspectSubject::Profiles,
            preview: None,
            cwd: None,
            redact: false,
        },
    )
    .await?;
    let items: Vec<ProfileDef> = data
        .get("items")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| unreadable("profiles"))?
        .unwrap_or_default();
    Ok(items.into_iter().find(|p| &p.profile_id == id))
}

/// What the personal policy for `profile` leaves uncovered of the profile's latest
/// definition, as the runtime's own dry-run resolution answers it (`inspect profiles
/// --preview`: no effect, no record): `Some` empty when it covers everything, the added
/// pairs and capabilities when it needs approval, `None` when it cannot tell (no personal
/// policy, a pause or cutoff, another refusal).
async fn personal_delta<S: Session>(
    s: &mut S,
    profile: &ProfileId,
) -> Result<Option<(BTreeSet<AccessPairRef>, BTreeSet<Capability>)>, Outcome> {
    let data = read(
        s,
        InspectRequest {
            subject: InspectSubject::Profiles,
            preview: Some(heimdall_contract::request::EnsurePreview {
                profile: profile.clone(),
                environment: None,
                until: None,
                required_capabilities: heimdall_contract::request::RequiredCapabilities::default(),
            }),
            cwd: None,
            redact: false,
        },
    )
    .await?;
    let preview = &data["preview"];
    Ok(match preview["outcome"].as_str() {
        Some("allowed") => Some((BTreeSet::new(), BTreeSet::new())),
        Some("approval_required") => {
            let added = &preview["delta"]["added_scope"];
            let pairs = serde_json::from_value(added["pairs"].clone()).unwrap_or_default();
            let caps = serde_json::from_value(added["capabilities"].clone()).unwrap_or_default();
            Some((pairs, caps))
        }
        _ => None,
    })
}

/// The pending `extend_scope` record a requester raised for `policy` (ADR-0011 §4.1–§4.2:
/// it lists exactly the added authority), if there is one.
async fn pending_extension<S: Session>(
    s: &mut S,
    policy: &PolicyId,
) -> Result<Option<String>, Outcome> {
    let data = read(
        s,
        InspectRequest {
            subject: InspectSubject::Decisions,
            preview: None,
            cwd: None,
            redact: false,
        },
    )
    .await?;
    Ok(data["decisions"].as_array().and_then(|list| {
        list.iter()
            .find(|d| {
                d["kind"] == "widen_policy"
                    && d["request"]["action"]["action"] == "extend_scope"
                    && d["request"]["action"]["policy_id"] == policy.as_str()
                    && d["expired"] != true
            })
            .and_then(|d| d["decision_id"].as_str())
            .map(str::to_owned)
    }))
}

/// An owner request on a connected session (module docs, "Owner-present flow"):
/// `widening` attends first and, on a pending decision on a terminal, shows the record,
/// asks for a typed `yes`, sends `Decide` and sends `request` again, so the caller sees the
/// applied state. A narrowing is sent once and never attends. Two requests are not sent
/// again, because their approval makes the same request mean something else: `create`
/// (a second personal policy for the profile is refused) and `reconcile_workspace` (the
/// approval retires the record it names); their answer is the `Decide` result.
pub(crate) async fn owner_request<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    request: Request,
    widening: bool,
) -> Envelope<serde_json::Value> {
    if widening && let Err(refused) = crate::cli::attend_first(s, ctx).await {
        return refused.env;
    }
    let env = s.request(request.clone()).await;
    if !widening {
        return env;
    }
    let decided = match crate::cli::approve_request(s, p, ctx, &request, env, &mut 2).await {
        Ok(decided) => decided,
        Err(env) => return env,
    };
    if matches!(
        request,
        Request::Policy(PolicyAction::Create { .. } | PolicyAction::ReconcileWorkspace { .. })
    ) {
        return decided;
    }
    let again = s.request(request.clone()).await;
    // ⟨M06 W5 `w5m` L4⟩ An approved targeted `resume` or `clear_cutoff` that only lifted a
    // delivered effect on a runner holding no policy in the scope: the request again names
    // no standing policy (`policy_target_empty`), which would report the lift the owner
    // just approved as a failure. Its answer is then the approved target with no policy.
    if again.code == Code::NotFound
        && again.data["error"]["reason"] == reason::POLICY_TARGET_EMPTY
        && let Some(result) = lift_only_result(&request)
    {
        return Envelope::ok(result);
    }
    again
}

/// The result of an approved targeted `resume` or `clear_cutoff` whose target holds no
/// standing policy ([`owner_request`]): the target, changed, no policy. `None` for any
/// other request.
fn lift_only_result(request: &Request) -> Option<serde_json::Value> {
    let Request::Policy(
        PolicyAction::Resume {
            target: Some(target),
            ..
        }
        | PolicyAction::ClearCutoff {
            target: Some(target),
            ..
        },
    ) = request
    else {
        return None;
    };
    serde_json::to_value(heimdall_contract::trust::PolicyTargetResult {
        target: target.clone(),
        changed: true,
        policies: Vec::new(),
        revoked: None,
    })
    .ok()
}

/// One connected owner request, rendered with `render`.
async fn send(
    ctx: &Ctx,
    request: Request,
    widening: bool,
    render: fn(&serde_json::Value) -> String,
) -> Outcome {
    let mut s = match session(ctx, true).await {
        Ok(s) => s,
        Err(o) => return o,
    };
    let env = owner_request(&mut s, &mut TerminalPrompt, ctx, request, widening).await;
    rendered(env, render)
}

fn rendered(env: Envelope<serde_json::Value>, render: fn(&serde_json::Value) -> String) -> Outcome {
    let human = if env.code.is_success() {
        render(&env.data)
    } else {
        String::new()
    };
    Outcome::of(env).with_human(human)
}

fn pretty(v: &serde_json::Value) -> String {
    // ⟨M05⟩ Review M05-W3-RC01: human JSON is inert.
    crate::output::human_json(v)
}

fn s<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v.get(k).and_then(serde_json::Value::as_str).unwrap_or("")
}

// ---------------------------------------------------------------------------------
// What a decision shows (spec §5.2; ADR-0011 §2.1, §3.3, §4.2, I5)
// ---------------------------------------------------------------------------------

/// Whether a recorded `trust_workspace` request's approval also acknowledges the M03 lock
/// disclosure (its `lock_disclosure`), so the prompt needs the runtime's conditional lock
/// text (ADR-0008 §17.27 item 4).
#[must_use]
pub(crate) fn acknowledges_lock(recorded: &serde_json::Value) -> bool {
    recorded
        .get("lock_disclosure")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
}

fn pair_list(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|p| format!("{}:{}", s(p, "destination"), s(p, "account")))
                .collect()
        })
        .unwrap_or_default()
}

fn word_list(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn or_all(list: Vec<String>, all: &str) -> String {
    if list.is_empty() {
        all.to_owned()
    } else {
        list.join(", ")
    }
}

/// The spec §5.2 first-trust message's words, with the ADR-0011 §3.3 re-entry sentence.
fn first_trust_text(profile: &str, background_work: bool) -> String {
    let lock = if background_work {
        "Work can continue while your desktop and password manager are locked, using your saved session limits."
    } else {
        "A session lock ends this access (the workspace asked for no background work); it works within your saved session limits."
    };
    format!(
        "Use {profile} access automatically for this project? {lock} Access starts again automatically when you next use it, within your saved limits; pause or set a stop time to end it. You can pause or remove access at any time.\n"
    )
}

/// ⟨M05⟩ The human form of a pending M05 decision (one `inspect decisions` entry: its
/// `kind`, its recorded `request` and, for a targeted widening, its `policies`), shown
/// before the generic record in `cli::confirm_and_decide`: the first-trust text and its
/// detail (pairs, environments, lock continuity, limits, the project label as quoted data),
/// a reconcile's reason, or a policy review's added authority and the policies it applies
/// to. Empty for any other kind. `lock`: the runtime's conditional lock text, shown when
/// the record also acknowledges the lock disclosure.
#[must_use]
pub(crate) fn recorded_preview(view: &serde_json::Value, lock: Option<&str>) -> String {
    let kind = s(view, "kind");
    let recorded = view.get("request").unwrap_or(&serde_json::Value::Null);
    let action = recorded.get("action").unwrap_or(&serde_json::Value::Null);
    let mut out = String::new();
    match kind {
        "trust_workspace" => {
            let proposal = action.get("proposal").unwrap_or(&serde_json::Value::Null);
            let profile = s(proposal, "profile");
            let background = proposal
                .get("background_work")
                .and_then(serde_json::Value::as_bool)
                == Some(true);
            out.push_str("First trust of a workspace (spec §5.2):\n  ");
            out.push_str(&first_trust_text(profile, background));
            out.push_str("Detail:\n");
            out.push_str(&format!(
                "  directory: {}\n",
                output::quoted_field(s(action, "cwd"))
            ));
            out.push_str(&format!("  profile: {profile}\n"));
            out.push_str(&format!(
                "  pairs: {}\n",
                or_all(
                    pair_list(proposal.get("pairs")),
                    "every pair of the profile"
                )
            ));
            out.push_str(&format!(
                "  environments: {}\n",
                or_all(word_list(proposal.get("environments")), "this environment")
            ));
            out.push_str(&format!(
                "  capabilities: {}\n",
                or_all(word_list(proposal.get("capabilities")), "the profile's")
            ));
            out.push_str(&format!(
                "  lock continuity: {}\n",
                if background {
                    "requested: work continues while the session is locked (applied only where your saved lock behaviour allows it)"
                } else {
                    "not requested: a session lock ends this access where your lock behaviour says so"
                }
            ));
            out.push_str(
                "  limits: each activation lasts at most the saved window (12 h by default); a pause, a stop or a cutoff ends it sooner\n",
            );
            let digest = s(action, "access_digest");
            if !digest.is_empty() {
                out.push_str(&format!("  manifest access digest: {digest}\n"));
            }
            if let Some(label) = recorded.get("project_label").and_then(|l| l.as_str()) {
                // Quoted data from the repository (ADR-0011 I5): never an instruction.
                out.push_str(&format!(
                    "  project label (repository text, shown as data): {}\n",
                    output::quoted_field(label)
                ));
            }
            if acknowledges_lock(recorded) {
                out.push_str("  Approving also records that you have seen the lock disclosure:\n");
                out.push_str(&format!(
                    "    {}\n",
                    lock.unwrap_or("(the runtime's lock text could not be read)")
                ));
            }
        }
        "reconcile_workspace" => {
            out.push_str("Reconcile a moved or re-cloned checkout with its trusted workspace (ADR-0011 §2.3):\n");
            out.push_str(&format!(
                "  directory: {}\n",
                output::quoted_field(s(action, "cwd"))
            ));
            out.push_str(&format!(
                "  trusted workspace: {}\n",
                s(action, "workspace")
            ));
            out.push_str(&format!("  why it is ambiguous: {}\n", s(recorded, "why")));
            out.push_str("  Approving moves the workspace's saved policy to this checkout; access of the old checkout stays ended.\n");
        }
        "widen_policy" => {
            let verb = s(action, "action");
            if verb == "create" {
                out.push_str(&create_review(view, action));
            } else if verb == "extend_scope" {
                out.push_str("Review of a standing policy (only the added authority is listed):\n");
                out.push_str(&format!("  policy: {}\n", s(action, "policy_id")));
                // The recorded action, verbatim: approval adds what the policy lacks of it.
                let pairs = pair_list(action.get("pairs"));
                if !pairs.is_empty() {
                    out.push_str(&format!("  pairs to add: {}\n", pairs.join(", ")));
                }
                let caps = word_list(action.get("capabilities"));
                if !caps.is_empty() {
                    out.push_str(&format!("  capabilities to add: {}\n", caps.join(", ")));
                }
                let envs = word_list(action.get("environments"));
                if !envs.is_empty() {
                    out.push_str(&format!("  environments to add: {}\n", envs.join(", ")));
                }
                if action
                    .get("background_work")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                {
                    out.push_str("  lock behaviour: work continues while the session is locked\n");
                }
            }
            // ⟨M06 W5 `w5m` L2; rev 6.5⟩ A lift names each delivered effect it lifts: its
            // scope, the controller that delivered it and when.
            if let Some(list) = view.get("lifted_effects").and_then(|p| p.as_array())
                && !list.is_empty()
            {
                out.push_str(
                    "  Approving also LIFTS these effects a controller delivered to this runner:\n",
                );
                for e in list {
                    out.push_str(&format!(
                        "    a {} of scope {}, delivered by controller {} at {}\n",
                        output::quoted_field(s(e, "kind")),
                        output::quoted_field(s(e, "scope_key")),
                        output::quoted_field(s(e, "controller")),
                        output::quoted_field(s(e, "delivered_at")),
                    ));
                }
                out.push_str(
                    "    (the delivering controller resumes issuance only after its own owner acknowledges the lift: `heimdall environment resume-issuance`)\n",
                );
            }
            // ⟨rev5.1⟩ C1: a targeted widening lists exactly the policies it applies to.
            if let Some(list) = view.get("policies").and_then(|p| p.as_array()) {
                out.push_str("  policies this applies to:\n");
                for p in list {
                    out.push_str(&format!(
                        "    {} (at revision {})\n",
                        s(p, "policy_id"),
                        p.get("revision")
                            .map_or_else(String::new, ToString::to_string)
                    ));
                }
            }
        }
        _ => {}
    }
    out
}

/// ⟨M05⟩ The review of a `create` record (`access allow --profile` for a profile with no
/// policy; the setup offer's record too, through `heimdall decide`): the scope the runtime
/// recorded for the record (`scope`, ADR-0006 §17.10 item 22; review M05-W3-R01), which is
/// exactly what approval gives the new policy: the pinned profile revision's pairs and
/// capabilities, its environments and its lock behaviour. Never the client's own read of
/// the profile, which a catalog edit can outrun. Without a recorded scope it says so, and
/// [`approve_block`] refuses the approval.
fn create_review(view: &serde_json::Value, action: &serde_json::Value) -> String {
    let mut out = String::from(
        "Review of a new personal standing policy (the scope the runtime recorded for this decision; approval applies exactly this):\n",
    );
    let Some(scope) = crate::setup_cmd::recorded_scope(view) else {
        out.push_str(&format!(
            "  profile: {}\n  {}: approval is refused here\n",
            s(action, "profile"),
            crate::setup_cmd::SCOPE_NOT_RECORDED
        ));
        return out;
    };
    let none = |l: Vec<String>| {
        if l.is_empty() {
            "none".to_owned()
        } else {
            l.join(", ")
        }
    };
    let words = |v: serde_json::Value| word_list(Some(&v));
    out.push_str(&format!(
        "  profile: {} at revision {}\n",
        scope.profile_id, scope.profile_revision
    ));
    out.push_str(&format!(
        "  pairs: {}\n",
        none(pair_list(Some(&serde_json::json!(scope.pairs))))
    ));
    out.push_str(&format!(
        "  capabilities: {}\n",
        none(words(serde_json::json!(scope.capabilities)))
    ));
    out.push_str(&format!(
        "  environments: {}\n",
        none(words(serde_json::json!(scope.environments)))
    ));
    out.push_str(&format!(
        "  lock behaviour: {}\n",
        match scope.lock_behavior {
            heimdall_contract::managed::LockBehavior::Continue => {
                "work continues while the session is locked"
            }
            _ => "a session lock ends this access",
        }
    ));
    if action.get("default").and_then(serde_json::Value::as_bool) == Some(true) {
        out.push_str(
            "  default: it also covers ordinary ssh to your managed aliases in those environments\n",
        );
    }
    out
}

/// ⟨M05⟩ Review M05-W3-R01: why an approval of this `inspect decisions` entry is refused
/// before anything is asked (`cli::confirm_and_decide`): a `widen_policy` `create` without a
/// well-formed recorded `scope` (ADR-0006 §17.10 item 22), whose destinations cannot be
/// shown. `None` for every other entry.
#[must_use]
pub(crate) fn approve_block(view: &serde_json::Value) -> Option<&'static str> {
    (s(view, "kind") == "widen_policy"
        && view["request"]["action"]["action"] == "create"
        && crate::setup_cmd::recorded_scope(view).is_none())
    .then_some(crate::setup_cmd::SCOPE_NOT_RECORDED)
}

// ---------------------------------------------------------------------------------
// The trust proposal (module docs, "The proposal a trust request names")
// ---------------------------------------------------------------------------------

fn manifest_invalid(message: &str) -> Outcome {
    Outcome::of(failure(
        Code::UsageError,
        message,
        Some(reason::MANIFEST_INVALID),
    ))
}

/// What a workspace asks for: `(access digest, proposal)`, from the runtime's own
/// `inspect workspace` answer `view` (ADR-0006 §17.10 item 21; the client never reads the
/// manifest). A manifest root's proposal is the runtime's: the one `trust_workspace` is
/// compared with. When the runtime has a manifest but no proposal for it (an unknown
/// profile, a request that does not resolve), the request carries an empty proposal for
/// `profile` (or this environment's default profile) and the digest, and the runtime's
/// comparison refuses it with the stable reason. A manifest-less root's names `profile`
/// (or the default profile) and its whole scope, which the trust record then supplies
/// (ADR-0011 §2.2 "Discovery").
async fn workspace_request<S: Session>(
    s: &mut S,
    own: &EnvironmentId,
    view: &WorkspaceView,
    profile: Option<&ProfileId>,
) -> Result<(String, TrustProposal), Outcome> {
    if let Some(proposal) = &view.proposal {
        if profile.is_some_and(|p| *p != proposal.profile) {
            return Err(usage(
                "--profile names another profile than the workspace's .heimdall.toml",
            ));
        }
        return Ok((
            view.access_digest.clone().unwrap_or_default(),
            proposal.clone(),
        ));
    }
    let profile = match profile {
        Some(p) => p.clone(),
        None => match default_of(&policies(s).await?, own) {
            Some(p) => p,
            None if view.access_digest.is_some() => {
                return Err(manifest_invalid(
                    "the workspace's .heimdall.toml does not name a request this catalog can resolve: check its profile, pairs, environments and capabilities (or name the profile with --profile)",
                ));
            }
            None => {
                return Err(usage(
                    "this workspace has no .heimdall.toml and this environment has no default profile: name the profile with --profile",
                ));
            }
        },
    };
    Ok((
        view.access_digest.clone().unwrap_or_default(),
        TrustProposal {
            profile,
            pairs: BTreeSet::new(),
            environments: BTreeSet::new(),
            capabilities: BTreeSet::new(),
            background_work: false,
        },
    ))
}

fn default_of(view: &PoliciesView, own: &EnvironmentId) -> Option<ProfileId> {
    view.default_profiles
        .iter()
        .find(|d| &d.environment_id == own)
        .map(|d| d.profile_id.clone())
}

// ---------------------------------------------------------------------------------
// `project trust|status|untrust|reconcile`
// ---------------------------------------------------------------------------------

/// Handle `project …`.
pub(crate) fn project(ctx: &Ctx, command: ProjectCommand) -> ExitCode {
    block(ctx, async move {
        match command {
            ProjectCommand::Status(a) => project_status(ctx, a.cwd.as_deref()).await,
            ProjectCommand::Trust(a) => project_trust(ctx, &a).await,
            ProjectCommand::Untrust(a) => project_untrust(ctx, a.cwd.as_deref()).await,
            ProjectCommand::Reconcile(a) => project_reconcile(ctx, a.cwd.as_deref()).await,
        }
    })
}

/// The human form of a [`WorkspaceView`].
fn render_workspace(v: &serde_json::Value) -> String {
    let matched = s(v, "match");
    let state = match matched {
        "trusted" => "trusted",
        "member" => "trusted (a linked worktree of a trusted checkout)",
        "untrusted" => "not trusted",
        "ambiguous" => "ambiguous: moved or re-cloned; review it with `heimdall project reconcile`",
        "none" => "no workspace (personal context)",
        _ => "unknown",
    };
    // Review M05-W3-R03: the paths are repository and file-system text, shown as quoted
    // data (line breaks escaped, invisible formatting characters removed).
    let mut out = format!("directory: {}\n", output::quoted_field(s(v, "cwd")));
    if let Some(root) = v.get("root").and_then(|r| r.as_str()) {
        out.push_str(&format!("workspace root: {}\n", output::quoted_field(root)));
    }
    out.push_str(&format!("state: {state}\n"));
    if let Some(w) = v.get("workspace_id").and_then(|r| r.as_str()) {
        out.push_str(&format!("workspace: {w}\n"));
    }
    if let Some(p) = v.get("policy_id").and_then(|r| r.as_str()) {
        out.push_str(&format!("policy: {p}\n"));
    }
    if let Some(d) = v.get("access_digest").and_then(|r| r.as_str()) {
        out.push_str(&format!("manifest access digest: {d}\n"));
    }
    out.push_str(
        "provenance: the working directory is a claim any program of this user can make\n",
    );
    out
}

async fn project_status(ctx: &Ctx, cwd: Option<&Path>) -> Outcome {
    let cwd = match cwd_of(cwd) {
        Ok(c) => c,
        Err(o) => return o,
    };
    let mut s = match session(ctx, false).await {
        Ok(s) => s,
        Err(o) => return o,
    };
    match workspace(&mut s, &cwd).await {
        Ok(v) => {
            let data = serde_json::to_value(&v).unwrap_or_default();
            let human = render_workspace(&data);
            Outcome::of(Envelope::ok(data)).with_human(human)
        }
        Err(o) => o,
    }
}

async fn project_trust(ctx: &Ctx, a: &ProjectTrustArgs) -> Outcome {
    let cwd = match cwd_of(a.cwd.as_deref()) {
        Ok(c) => c,
        Err(o) => return o,
    };
    let profile = match a.profile.as_deref().map(ProfileId::parse).transpose() {
        Ok(p) => p,
        Err(_) => return usage("invalid profile"),
    };
    let mut s = match session(ctx, true).await {
        Ok(s) => s,
        Err(o) => return o,
    };
    let own = s.server().environment_id.clone();
    trust_flow(
        &mut s,
        &mut TerminalPrompt,
        ctx,
        &own,
        &cwd,
        profile.as_ref(),
    )
    .await
}

/// `project trust` on a connected session (also `access allow --workspace` for an
/// untrusted workspace).
pub(crate) async fn trust_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    own: &EnvironmentId,
    cwd: &str,
    profile: Option<&ProfileId>,
) -> Outcome {
    let view = match workspace(s, cwd).await {
        Ok(v) => v,
        Err(o) => return o,
    };
    match view.matched {
        WorkspaceMatchView::None => {
            return usage(
                "there is no workspace here: trust needs a directory at or below one holding .heimdall.toml or .git",
            );
        }
        WorkspaceMatchView::Ambiguous => {
            return Outcome::of(failure(
                Code::UsageError,
                "this checkout partly matches a trusted workspace (moved or re-cloned): review it with `heimdall project reconcile`",
                None,
            ));
        }
        WorkspaceMatchView::Trusted | WorkspaceMatchView::Member if view.policy_id.is_some() => {
            let data = serde_json::to_value(&view).unwrap_or_default();
            let human = format!(
                "This workspace is already trusted; nothing was asked.\n{}",
                render_workspace(&data)
            );
            return Outcome::of(Envelope::ok(data)).with_human(human);
        }
        _ => {}
    }
    let (access_digest, proposal) = match workspace_request(s, own, &view, profile).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    let request = Request::Policy(PolicyAction::TrustWorkspace {
        cwd: cwd.to_owned(),
        access_digest,
        proposal,
    });
    let env = owner_request(s, p, ctx, request, true).await;
    rendered(env, render_trusted)
}

/// The human form of an applied trust or reconcile (the workspace's policy).
fn render_trusted(v: &serde_json::Value) -> String {
    format!(
        "This workspace is trusted under policy {}: covered work here activates without asking again, within the saved limits.\n{}",
        s(v, "policy_id"),
        pretty(v)
    )
}

/// The human form of a single-policy result.
fn render_policy(v: &serde_json::Value) -> String {
    let mut out = String::new();
    if let Some(id) = v.get("policy_id").and_then(|r| r.as_str()) {
        out.push_str(&format!("policy: {id}\n"));
    }
    if let Some(changed) = v.get("changed").and_then(serde_json::Value::as_bool) {
        out.push_str(if changed { "changed\n" } else { "unchanged\n" });
    }
    if out.is_empty() {
        pretty(v)
    } else {
        format!("{out}{}", pretty(v))
    }
}

async fn project_untrust(ctx: &Ctx, cwd: Option<&Path>) -> Outcome {
    let cwd = match cwd_of(cwd) {
        Ok(c) => c,
        Err(o) => return o,
    };
    let mut s = match session(ctx, true).await {
        Ok(s) => s,
        Err(o) => return o,
    };
    let view = match workspace(&mut s, &cwd).await {
        Ok(v) => v,
        Err(o) => return o,
    };
    let Some(policy_id) = view.policy_id.clone().filter(|_| {
        matches!(
            view.matched,
            WorkspaceMatchView::Trusted | WorkspaceMatchView::Member
        )
    }) else {
        return Outcome::of(failure(
            Code::NotFound,
            "this directory is not in a trusted workspace with a saved policy; nothing was changed",
            None,
        ));
    };
    let env = owner_request(
        &mut s,
        &mut TerminalPrompt,
        ctx,
        Request::Policy(PolicyAction::Remove { policy_id }),
        false,
    )
    .await;
    rendered(env, |v| {
        format!(
            "The workspace's saved policy was removed; its live access ended.\n{}",
            render_policy(v)
        )
    })
}

async fn project_reconcile(ctx: &Ctx, cwd: Option<&Path>) -> Outcome {
    let cwd = match cwd_of(cwd) {
        Ok(c) => c,
        Err(o) => return o,
    };
    let mut s = match session(ctx, true).await {
        Ok(s) => s,
        Err(o) => return o,
    };
    reconcile_flow(&mut s, &mut TerminalPrompt, ctx, &cwd).await
}

async fn reconcile_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    cwd: &str,
) -> Outcome {
    let view = match workspace(s, cwd).await {
        Ok(v) => v,
        Err(o) => return o,
    };
    let workspace = match (&view.matched, &view.workspace_id) {
        (WorkspaceMatchView::Ambiguous, Some(w)) => w.clone(),
        (WorkspaceMatchView::Trusted | WorkspaceMatchView::Member, _) => {
            let data = serde_json::to_value(&view).unwrap_or_default();
            let human = format!(
                "This workspace is trusted as it is; there is nothing to reconcile.\n{}",
                render_workspace(&data)
            );
            return Outcome::of(Envelope::ok(data)).with_human(human);
        }
        _ => {
            return usage(
                "this directory does not partly match a trusted workspace; there is nothing to reconcile (trust it with `heimdall project trust`)",
            );
        }
    };
    let request = Request::Policy(PolicyAction::ReconcileWorkspace {
        workspace,
        cwd: cwd.to_owned(),
    });
    let env = owner_request(s, p, ctx, request, true).await;
    if env.code != Code::Ok {
        return Outcome::of(env);
    }
    // The approval wrote a new workspace record for this checkout: report it.
    match self::workspace(s, cwd).await {
        Ok(v) => {
            let data = serde_json::to_value(&v).unwrap_or_default();
            let human = format!(
                "This checkout is reconciled with its trusted workspace.\n{}",
                render_workspace(&data)
            );
            Outcome::of(Envelope::ok(data)).with_human(human)
        }
        Err(o) => o,
    }
}

// ---------------------------------------------------------------------------------
// `access allow` (ADR-0011 §4.3: owner-initiated, never stopped by a cooldown)
// ---------------------------------------------------------------------------------

/// Handle `access allow`.
pub(crate) fn allow(ctx: &Ctx, a: &AccessAllowArgs) -> ExitCode {
    block(ctx, allow_flow(ctx, a))
}

async fn allow_flow(ctx: &Ctx, a: &AccessAllowArgs) -> Outcome {
    let cwd = if a.workspace {
        match cwd_of(a.cwd.as_deref()) {
            Ok(c) => Some(c),
            Err(o) => return o,
        }
    } else {
        None
    };
    let policy = match a.policy.as_deref().map(PolicyId::parse).transpose() {
        Ok(p) => p,
        Err(_) => return usage("invalid policy ID"),
    };
    let profile = match a.profile.as_deref().map(ProfileId::parse).transpose() {
        Ok(p) => p,
        Err(_) => return usage("invalid profile"),
    };
    let runner = match a
        .environment
        .as_deref()
        .map(EnvironmentId::parse)
        .transpose()
    {
        Ok(e) => e,
        Err(_) => return usage("invalid environment"),
    };
    let mut s = match session(ctx, true).await {
        Ok(s) => s,
        Err(o) => return o,
    };
    let own = s.server().environment_id.clone();
    let mut prompt = TerminalPrompt;
    if let Some(cwd) = cwd {
        return allow_workspace(&mut s, &mut prompt, ctx, &own, &cwd).await;
    }
    // ⟨M06 W5; record source (b)⟩ `--profile P --environment <runner>`: the review of a
    // new personal policy that names that runner only. The runtime decides whether the
    // environment may be named (a recorded runner on which this controller's role may
    // issue) and whether such a policy already exists.
    if let (Some(profile), Some(environment)) = (&profile, &runner) {
        // Only a paired runner this controller records is named this way; an environment
        // of this device's own set keeps its existing reviews.
        if !recorded_runners(ctx).contains(environment) {
            return Outcome::of(failure(
                Code::NotFound,
                "this controller holds no record of that runner environment",
                None,
            ));
        }
        let request = Request::Policy(PolicyAction::Create {
            profile: profile.clone(),
            environments: [environment.clone()].into_iter().collect(),
            max_window: None,
            default: false,
        });
        if ctx.interactive() {
            output::prompt(&output::sanitize_for_terminal(&format!(
                "This policy names the paired runner {}. It activates nothing on this device: it only lets this controller's issuer sign certificates for the grants that runner admits for the profile, inside the scope shown next.\n",
                environment.as_str()
            )));
        }
        return rendered(
            owner_request(&mut s, &mut prompt, ctx, request, true).await,
            render_policy,
        );
    }
    let view = match policies(&mut s).await {
        Ok(v) => v,
        Err(o) => return o,
    };
    // A policy that names only recorded runners applies nothing here: `--profile` reviews
    // the policies that do (naming such a policy with `--policy` still reviews it).
    let runners = recorded_runners(ctx);
    let runner_only = |i: &heimdall_contract::trust::PolicyView| {
        !i.environments.is_empty() && i.environments.iter().all(|e| runners.contains(e))
    };
    let targets: Vec<(PolicyId, ProfileId)> = view
        .items
        .iter()
        .filter(|i| policy.as_ref().is_none_or(|p| *p == i.policy_id))
        .filter(|i| profile.as_ref().is_none_or(|p| *p == i.profile))
        .filter(|i| policy.is_some() || !runner_only(i))
        .map(|i| (i.policy_id.clone(), i.profile.clone()))
        .collect();
    if targets.is_empty() {
        return match (policy, profile) {
            (Some(_), _) => Outcome::of(failure(Code::NotFound, "unknown policy", None)),
            (None, Some(profile)) => {
                // No policy for the profile: the review is a new personal policy here.
                let request = Request::Policy(PolicyAction::Create {
                    profile,
                    environments: [own].into_iter().collect(),
                    max_window: None,
                    default: false,
                });
                rendered(
                    owner_request(&mut s, &mut prompt, ctx, request, true).await,
                    render_policy,
                )
            }
            (None, None) => usage("access allow names --policy, --profile or --workspace"),
        };
    }
    // The dry-run delta is this environment's: a runner's policy is reviewed against the
    // profile's definition instead.
    let personal: BTreeSet<PolicyId> = view
        .items
        .iter()
        .filter(|i| i.workspace_id.is_none() && !runner_only(i))
        .map(|i| i.policy_id.clone())
        .collect();
    let mut results = Vec::new();
    for (policy_id, profile) in targets {
        // Only the added authority is asked for (spec §12.3): what the personal policy
        // leaves uncovered, as the runtime's dry-run resolution answers it; otherwise (a
        // workspace policy, a paused one) the profile's definition, of which approval
        // adds only what the policy lacks.
        let delta = if personal.contains(&policy_id) {
            match personal_delta(&mut s, &profile).await {
                Ok(d) => d,
                Err(o) => return o,
            }
        } else {
            None
        };
        let (pairs, capabilities) = match delta {
            Some((pairs, caps)) if pairs.is_empty() && caps.is_empty() => {
                results.push(serde_json::json!({
                    "policy_id": policy_id,
                    "changed": false,
                    "covers_the_profile": true,
                }));
                continue;
            }
            Some(d) => d,
            None => match profile_def(&mut s, &profile).await {
                Ok(Some(def)) => (def.pairs, def.capabilities),
                Ok(None) => {
                    return Outcome::of(failure(
                        Code::NotFound,
                        "the policy's profile is not in this catalog",
                        None,
                    ));
                }
                Err(o) => return o,
            },
        };
        let request = Request::Policy(PolicyAction::ExtendScope {
            policy_id,
            pairs,
            capabilities,
            environments: BTreeSet::new(),
            background_work: None,
        });
        let env = owner_request(&mut s, &mut prompt, ctx, request, true).await;
        if !env.code.is_success() {
            return rendered(env, render_policy);
        }
        results.push(env.data);
    }
    let data = serde_json::json!({ "policies": results });
    let human = format!("Reviewed every policy named.\n{}", pretty(&data));
    Outcome::of(Envelope::ok(data)).with_human(human)
}

/// ⟨M06 W5⟩ The runner environments this controller records, read from its state store
/// read-only (as `environment status` reads them). Empty when there is no state or it
/// cannot be read: then no policy is taken for a runner's.
fn recorded_runners(ctx: &Ctx) -> BTreeSet<EnvironmentId> {
    let Ok(paths) = ctx.paths() else {
        return BTreeSet::new();
    };
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    if !db.exists() {
        return BTreeSet::new();
    }
    heimdall_store::Store::open_read_only(&db, std::sync::Arc::new(heimdall_store::NoFaults))
        .and_then(|state| state.transaction(heimdall_app::remote_status_driver::pins))
        .map(|pins| pins.into_iter().map(|p| p.environment).collect())
        .unwrap_or_default()
}

/// `access allow --workspace`: the review the workspace's state calls for.
async fn allow_workspace<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    own: &EnvironmentId,
    cwd: &str,
) -> Outcome {
    let view = match workspace(s, cwd).await {
        Ok(v) => v,
        Err(o) => return o,
    };
    let policy_id = match (&view.matched, &view.policy_id) {
        (WorkspaceMatchView::Ambiguous, _) => return reconcile_flow(s, p, ctx, cwd).await,
        (WorkspaceMatchView::Trusted | WorkspaceMatchView::Member, Some(policy)) => policy.clone(),
        (WorkspaceMatchView::None, _) => {
            return usage("there is no workspace here; review a profile or a policy instead");
        }
        _ => return trust_flow(s, p, ctx, own, cwd, None).await,
    };
    // A requester's pending review lists exactly the added authority: decide that one.
    match pending_extension(s, &policy_id).await {
        Ok(Some(decision)) => {
            if let Err(refused) = crate::cli::attend_first(s, ctx).await {
                return Outcome::of(refused.env);
            }
            let env =
                crate::cli::confirm_and_decide(s, p, ctx, &decision, Verdict::Approve, None, None)
                    .await;
            return rendered(env, render_policy);
        }
        Ok(None) => {}
        Err(o) => return o,
    }
    let (_, proposal) = match workspace_request(s, own, &view, None).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    let pairs = if proposal.pairs.is_empty() {
        match profile_def(s, &proposal.profile).await {
            Ok(Some(def)) => def.pairs,
            Ok(None) => {
                return Outcome::of(failure(
                    Code::NotFound,
                    "the workspace's profile is not in this catalog",
                    Some(reason::MANIFEST_PROFILE_UNKNOWN),
                ));
            }
            Err(o) => return o,
        }
    } else {
        proposal.pairs
    };
    // A manifest that asks for less never narrows the policy (ADR-0011 §4.2): only a
    // request for background work is carried, never its absence.
    let request = Request::Policy(PolicyAction::ExtendScope {
        policy_id,
        pairs,
        capabilities: proposal.capabilities,
        environments: proposal.environments,
        background_work: proposal.background_work.then_some(true),
    });
    rendered(owner_request(s, p, ctx, request, true).await, render_policy)
}

// ---------------------------------------------------------------------------------
// `access stop` and the targets of `access pause|resume|cutoff` (ADR-0011 §7)
// ---------------------------------------------------------------------------------

/// The human form of a [`PolicyTargetResult`] (revision 5.1 C2), or of any other result.
pub(crate) fn render_target_result(v: &serde_json::Value) -> String {
    let Ok(r) = serde_json::from_value::<PolicyTargetResult>(v.clone()) else {
        return render_policy(v);
    };
    let target = match &r.target {
        PolicyTarget::Policy { policy_id } => format!("policy {policy_id}"),
        PolicyTarget::Profile { profile } => format!("every policy of profile {profile}"),
        PolicyTarget::Workspace { workspace } => format!("the policies of workspace {workspace}"),
        PolicyTarget::All => "every policy".to_owned(),
        _ => "?".to_owned(),
    };
    let mut out = format!(
        "target: {target}: {}\n",
        if r.changed { "changed" } else { "unchanged" }
    );
    for p in &r.policies {
        let mut line = format!("  {} revision {}", p.policy_id, p.revision);
        line.push_str(if p.paused { ", paused" } else { ", active" });
        if let Some(at) = &p.cutoff_at {
            line.push_str(&format!(", cutoff at {at}"));
        }
        line.push_str(if p.changed { " (changed)" } else { "" });
        out.push_str(&line);
        out.push('\n');
    }
    if let Some(revoked) = &r.revoked {
        out.push_str(&format!("revoked now: {} grant(s)", revoked.len()));
        for g in revoked {
            out.push_str(&format!(" {g}"));
        }
        out.push('\n');
    }
    // ⟨M06 W3 host⟩ A cutoff of every policy also went to every runner this controller owns.
    for (key, line) in [
        ("delivered", "delivered to runner"),
        ("pending", "pending on runner"),
    ] {
        for runner in v
            .get("runners")
            .and_then(|r| r.get(key))
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(environment) = runner.get("environment").and_then(|e| e.as_str()) {
                out.push_str(&format!(
                    "{line} {}\n",
                    crate::output::sanitize_for_terminal(environment)
                ));
            }
        }
    }
    out
}

/// A policy target from `--policy`, `--profile`, `--workspace` (with `cwd`) or `--all`.
async fn target_of<S: Session>(
    s: &mut S,
    policy: Option<&str>,
    profile: Option<&str>,
    workspace_cwd: Option<&str>,
    all: bool,
) -> Result<PolicyTarget, Outcome> {
    if let Some(p) = policy {
        let policy_id = PolicyId::parse(p).map_err(|_| usage("invalid policy ID"))?;
        return Ok(PolicyTarget::Policy { policy_id });
    }
    if let Some(p) = profile {
        let profile = ProfileId::parse(p).map_err(|_| usage("invalid profile"))?;
        return Ok(PolicyTarget::Profile { profile });
    }
    if let Some(cwd) = workspace_cwd {
        let view = workspace(s, cwd).await?;
        return match view.workspace_id {
            Some(workspace) => Ok(PolicyTarget::Workspace { workspace }),
            None => Err(Outcome::of(failure(
                Code::NotFound,
                "this directory is not in a trusted workspace; nothing was changed",
                Some(reason::POLICY_TARGET_EMPTY),
            ))),
        };
    }
    if all {
        return Ok(PolicyTarget::All);
    }
    Err(usage("name exactly one target"))
}

/// Handle `access stop`.
pub(crate) fn stop(ctx: &Ctx, a: &AccessStopArgs) -> ExitCode {
    block(ctx, stop_flow(ctx, a))
}

async fn stop_flow(ctx: &Ctx, a: &AccessStopArgs) -> Outcome {
    if let Some(work) = &a.work {
        let Ok(work_id) = WorkId::parse(work) else {
            return usage("invalid work ID");
        };
        let request_id = match request_id(a.request_id.as_deref()) {
            Ok(r) => r,
            Err(o) => return o,
        };
        let request = Request::Revoke(RevokeRequest {
            grant_id: None,
            request_id,
            target: Some(RevokeTarget::Work {
                environment: None,
                work_id,
            }),
        });
        return send(ctx, request, false, |v| {
            format!(
                "This work is stopped: its grants are revoked and its work ID never activates again; other work is unaffected.\n{}",
                pretty(v)
            )
        })
        .await;
    }
    let cwd = if a.workspace {
        match cwd_of(a.cwd.as_deref()) {
            Ok(c) => Some(c),
            Err(o) => return o,
        }
    } else {
        None
    };
    let mut s = match session(ctx, true).await {
        Ok(s) => s,
        Err(o) => return o,
    };
    let target = match target_of(
        &mut s,
        a.policy.as_deref(),
        a.profile.as_deref(),
        cwd.as_deref(),
        a.all,
    )
    .await
    {
        Ok(t) => t,
        Err(o) => return o,
    };
    let env = owner_request(
        &mut s,
        &mut TerminalPrompt,
        ctx,
        Request::Policy(PolicyAction::Stop { target }),
        false,
    )
    .await;
    rendered(env, |v| {
        format!(
            "Stopped: paused, and the access resting on these policies ended now. An attended `heimdall access resume` lifts the pause; ended access stays ended.\n{}",
            render_target_result(v)
        )
    })
}

/// Whether an `access pause|resume|cutoff` names an M05 target instead of a policy ID.
#[must_use]
pub(crate) fn is_targeted(command: &AccessCommand) -> bool {
    match command {
        AccessCommand::Pause { target }
        | AccessCommand::Resume { target }
        | AccessCommand::Cutoff { target, .. } => target.policy_id().is_none(),
        _ => false,
    }
}

/// Handle `access pause|resume|cutoff --profile|--workspace|--all`.
pub(crate) fn targeted(ctx: &Ctx, command: AccessCommand) -> ExitCode {
    block(ctx, targeted_flow(ctx, command))
}

async fn targeted_flow(ctx: &Ctx, command: AccessCommand) -> Outcome {
    enum Kind {
        Pause,
        Resume,
        Cutoff(Timestamp),
        Clear,
    }
    let (target, kind): (AccessTarget, Kind) = match command {
        AccessCommand::Pause { target } => (target, Kind::Pause),
        AccessCommand::Resume { target } => (target, Kind::Resume),
        AccessCommand::Cutoff {
            target,
            clear: true,
            ..
        } => (target, Kind::Clear),
        AccessCommand::Cutoff { target, at, .. } => {
            let Ok(at) = at.unwrap_or_default().parse::<Timestamp>() else {
                return usage("--at must be an RFC 3339 instant with an explicit offset");
            };
            (target, Kind::Cutoff(at))
        }
        _ => return usage("unsupported command"),
    };
    let cwd = if target.workspace {
        match cwd_of(target.cwd.as_deref()) {
            Ok(c) => Some(c),
            Err(o) => return o,
        }
    } else {
        None
    };
    let mut s = match session(ctx, true).await {
        Ok(s) => s,
        Err(o) => return o,
    };
    let t = match target_of(
        &mut s,
        None,
        target.profile.as_deref(),
        cwd.as_deref(),
        target.all,
    )
    .await
    {
        Ok(t) => Some(t),
        Err(o) => return o,
    };
    // `pause` narrows and never attends; `resume`, `--clear` and a cutoff (a later one
    // widens) are owner-present, as for one policy (ADR-0006 §13.6 items 6–7).
    let (action, widening) = match kind {
        Kind::Pause => (
            PolicyAction::Pause {
                policy_id: None,
                target: t,
            },
            false,
        ),
        Kind::Resume => (
            PolicyAction::Resume {
                policy_id: None,
                target: t,
            },
            true,
        ),
        Kind::Clear => (
            PolicyAction::ClearCutoff {
                policy_id: None,
                target: t,
            },
            true,
        ),
        Kind::Cutoff(at) => (
            PolicyAction::Cutoff {
                policy_id: None,
                at,
                target: t,
            },
            true,
        ),
    };
    let env = owner_request(
        &mut s,
        &mut TerminalPrompt,
        ctx,
        Request::Policy(action),
        widening,
    )
    .await;
    rendered(env, render_target_result)
}

// ---------------------------------------------------------------------------------
// `access default-profile` (revision 5.1 `set_default_profile`; ADR-0011 §5.1)
// ---------------------------------------------------------------------------------

/// Handle `access default-profile`.
pub(crate) fn default_profile(ctx: &Ctx, a: &AccessDefaultProfileArgs) -> ExitCode {
    block(ctx, default_profile_flow(ctx, a))
}

async fn default_profile_flow(ctx: &Ctx, a: &AccessDefaultProfileArgs) -> Outcome {
    if a.profile.is_none() && !a.clear {
        // Show: a read, which never starts the runtime.
        let mut s = match session(ctx, false).await {
            Ok(s) => s,
            Err(o) => return o,
        };
        let own = s.server().environment_id.clone();
        let view = match policies(&mut s).await {
            Ok(v) => v,
            Err(o) => return o,
        };
        let current = default_of(&view, &own);
        let human = match &current {
            Some(p) => format!("default profile: {p}\n"),
            None => "no default profile is set\n".to_owned(),
        };
        let data = serde_json::json!({ "environment_id": own, "profile_id": current });
        return Outcome::of(Envelope::ok(data)).with_human(human);
    }
    let profile = match a.profile.as_deref().map(ProfileId::parse).transpose() {
        Ok(p) => p,
        Err(_) => return usage("invalid profile"),
    };
    let request_id = match request_id(a.request_id.as_deref()) {
        Ok(r) => r,
        Err(o) => return o,
    };
    let request = Request::Catalog(CatalogRequest::SetDefaultProfile {
        environment: None,
        profile,
        request_id,
    });
    send(ctx, request, false, |v| {
        match v.get("profile_id").and_then(|p| p.as_str()) {
            Some(p) => format!(
                "default profile: {p} (a preference: only new requests that name no profile read it)\n"
            ),
            None => "the default profile is cleared\n".to_owned(),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first-trust preview shows the spec §5.2 text, every detail, and the project
    /// label only as quoted data (JSON-escaped, so a newline or a command substitution in
    /// it is shown, never acted on); a reconcile and a targeted review show what they apply.
    #[test]
    fn recorded_previews_show_the_scope_and_quote_the_label() {
        let recorded = serde_json::json!({
            "kind": "trust_workspace",
            "action": {"action": "trust_workspace", "cwd": "/w", "access_digest": "ab",
                "proposal": {"profile": "dev", "pairs": [{"destination": "h1", "account": "deploy"}],
                    "background_work": true}},
            "project_label": "x\n$(touch y)",
            "lock_disclosure": true,
        });
        let view = |kind: &str, request: &serde_json::Value| serde_json::json!({"kind": kind, "request": request});
        let text = recorded_preview(&view("trust_workspace", &recorded), Some("LOCK TEXT"));
        assert!(
            text.contains("Use dev access automatically for this project?"),
            "{text}"
        );
        assert!(text.contains("pairs: h1:deploy"), "{text}");
        assert!(text.contains("environments: this environment"), "{text}");
        assert!(text.contains("lock continuity: requested"), "{text}");
        assert!(text.contains("limits:"), "{text}");
        assert!(text.contains(r#""x\n$(touch y)""#), "{text}");
        assert!(text.contains("LOCK TEXT"), "{text}");
        assert!(acknowledges_lock(&recorded));
        let reconcile = serde_json::json!({
            "kind": "reconcile_workspace",
            "action": {"action": "reconcile_workspace", "workspace": "ws_1", "cwd": "/w2"},
            "why": "moved",
        });
        let text = recorded_preview(&view("reconcile_workspace", &reconcile), None);
        assert!(text.contains("/w2") && text.contains("moved"), "{text}");
        let targeted = serde_json::json!({
            "kind": "widen_policy",
            "request": {"action": {"action": "resume", "target": {"kind": "all"}}},
            "policies": [{"policy_id": "pol", "revision": 3}],
        });
        let text = recorded_preview(&targeted, None);
        assert!(text.contains("pol (at revision 3)"), "{text}");
        assert!(!text.contains("LIFTS"), "{text}");
        // ⟨M06 W5 `w5m` L2⟩ A lift names the delivered effect: scope, controller, when
        // (each as quoted data), also when the record lists no policy.
        let lift = serde_json::json!({
            "kind": "widen_policy",
            "request": {"action": {"action": "clear_cutoff", "target": {"kind": "all"}}},
            "policies": [],
            "lifted_effects": [{
                "scope": {"kind": "all"}, "scope_key": "all", "kind": "cutoff",
                "controller": "cl_00112233445566778899aabbccddeeff", "revision": 1,
                "effect": "eff_00112233445566778899aabbccddeeff",
                "delivered_at": "2026-11-22T10:00:00Z",
            }],
        });
        let text = recorded_preview(&lift, None);
        assert!(
            text.contains("Approving also LIFTS these effects")
                && text.contains("\"cutoff\" of scope \"all\"")
                && text.contains("delivered by controller \"cl_00112233445566778899aabbccddeeff\"")
                && text.contains("at \"2026-11-22T10:00:00Z\"")
                && text.contains("resume-issuance"),
            "{text}"
        );
        let other = serde_json::json!({"kind": "approve_authority", "request": {}});
        assert!(recorded_preview(&other, None).is_empty());
    }

    const ENV: &str = "env_00112233445566778899aabbccddeeff";
    const DEC: &str = "dec_00112233445566778899aabbccddeeff";

    fn create_entry(scope: Option<serde_json::Value>) -> serde_json::Value {
        let mut d = serde_json::json!({
            "decision_id": DEC, "kind": "widen_policy", "state": "pending",
            "expires_at": "2026-11-18T00:15:00Z",
            "request": {"action": {"action": "create", "profile": "dev",
                "environments": [ENV], "default": false}},
        });
        if let Some(scope) = scope {
            d["scope"] = scope;
        }
        d
    }

    fn scope_of(pairs: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "profile_id": "dev", "profile_revision": 3,
            "pairs": pairs.iter().map(|d| serde_json::json!({"destination": d, "account": "deploy"}))
                .collect::<Vec<_>>(),
            "environments": [ENV], "capabilities": ["ssh-authentication"],
            "lock_behavior": "continue",
        })
    }

    /// A scripted owner session: `inspect` answers the decision listing, a `create` answers
    /// that it waits on [`DEC`], `decide` succeeds; every request kind is recorded.
    struct Owner {
        listing: serde_json::Value,
        sent: Vec<String>,
    }

    impl Session for Owner {
        async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            self.sent.push(request.kind().to_owned());
            match request {
                Request::Inspect(_) => Envelope::ok(self.listing.clone()),
                Request::Policy(_) => output::error_value(
                    heimdall_app::OpError::new(Code::ApprovalRequired, "owner approval required")
                        .with_decision(DEC.to_owned())
                        .into_envelope(),
                ),
                _ => Envelope::ok(serde_json::json!({"decided": true})),
            }
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            self.sent.push("attend".to_owned());
            Envelope::ok(serde_json::json!({"attended": true}))
        }
    }

    struct Yes(Vec<String>);

    impl Prompter for Yes {
        async fn ask(&mut self, text: &str) -> crate::prompt::Answer {
            self.0.push(text.to_owned());
            crate::prompt::Answer::Yes
        }
    }

    /// ⟨M05⟩ Review M05-W3-R01 (ADR-0006 §17.10 item 22): `access allow --profile` for a
    /// profile with no policy (`create`) shows the scope the runtime recorded for its
    /// decision (every pair of the pinned revision, its capabilities, environments and lock
    /// behaviour) before the typed `yes`; a record without a well-formed `scope` is refused
    /// before anything is asked, and no `Decide` is sent. Another kind is never blocked.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_create_review_shows_the_recorded_scope_or_refuses() {
        let ctx = Ctx {
            json: false,
            non_interactive: false,
            home: None,
            stdin_tty: true,
        };
        let create = Request::Policy(PolicyAction::Create {
            profile: ProfileId::parse("dev").unwrap(),
            environments: [EnvironmentId::parse(ENV).unwrap()].into_iter().collect(),
            max_window: None,
            default: false,
        });
        let run = |entry: serde_json::Value| {
            let mut s = Owner {
                listing: serde_json::json!({ "decisions": [entry] }),
                sent: Vec::new(),
            };
            let mut p = Yes(Vec::new());
            let env = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(owner_request(&mut s, &mut p, &ctx, create.clone(), true));
            (env, s.sent, p.0)
        };
        let (env, sent, shown) = run(create_entry(Some(scope_of(&["h1", "h3"]))));
        assert_eq!(env.code, Code::Ok, "{env:?}");
        assert_eq!(sent, ["attend", "policy", "inspect", "decide"]);
        let [shown] = shown.as_slice() else {
            panic!("one prompt: {shown:?}")
        };
        for needle in [
            "profile: dev at revision 3",
            "pairs: h1:deploy, h3:deploy\n",
            "capabilities: ssh-authentication\n",
            &format!("environments: {ENV}\n"),
            "lock behaviour: work continues while the session is locked",
        ] {
            assert!(shown.contains(needle), "missing {needle:?}: {shown}");
        }
        assert_eq!(approve_block(&create_entry(Some(scope_of(&[])))), None);
        let malformed = serde_json::json!({"profile_id": "dev", "pairs": []});
        for entry in [create_entry(None), create_entry(Some(malformed))] {
            let text = recorded_preview(&entry, None);
            assert!(
                text.contains(crate::setup_cmd::SCOPE_NOT_RECORDED),
                "{text}"
            );
            assert!(!text.contains("pairs:"), "no pair is guessed: {text}");
            assert!(approve_block(&entry).is_some());
            let (env, sent, shown) = run(entry);
            assert_eq!(env.code, Code::InteractionRequired, "{env:?}");
            assert_eq!(sent, ["attend", "policy", "inspect"], "no decide");
            assert!(shown.is_empty(), "nothing is asked: {shown:?}");
        }
        let extension = serde_json::json!({
            "kind": "widen_policy",
            "request": {"action": {"action": "extend_scope", "policy_id": "pol",
                "pairs": [{"destination": "h3", "account": "deploy"}]}},
        });
        assert_eq!(approve_block(&extension), None);
    }

    /// ⟨M05⟩ Review M05-W3-R03: a directory name with a line break and a bidirectional
    /// override, in `project status`, the first-trust view and the reconcile view, is one
    /// quoted field: no line of its own, no override, the line break escaped.
    #[test]
    fn workspace_paths_render_as_quoted_data() {
        let hostile = "/w/r\nOWNER-LINE\u{202e}cba";
        let status = render_workspace(&serde_json::json!({
            "cwd": hostile, "root": hostile, "match": "untrusted",
        }));
        let trust = recorded_preview(
            &serde_json::json!({"kind": "trust_workspace", "request": {
                "action": {"action": "trust_workspace", "cwd": hostile, "access_digest": "ab",
                    "proposal": {"profile": "dev"}}}}),
            None,
        );
        let reconcile = recorded_preview(
            &serde_json::json!({"kind": "reconcile_workspace", "request": {
                "action": {"action": "reconcile_workspace", "workspace": "ws_1", "cwd": hostile},
                "why": "same_identity_other_path"}}),
            None,
        );
        let quoted = r#""/w/r\nOWNER-LINEcba" (invisible formatting characters removed)"#;
        for text in [&status, &trust, &reconcile] {
            assert!(!text.lines().any(|l| l.starts_with("OWNER-LINE")), "{text}");
            assert!(!text.contains('\u{202e}'), "{text}");
            assert!(text.contains(&format!("directory: {quoted}\n")), "{text}");
        }
        assert!(
            status.contains(&format!("workspace root: {quoted}\n")),
            "{status}"
        );
    }

    /// The typed result of a targeted action renders every policy and, for `stop`, the
    /// revoked grants; anything else falls back to its JSON.
    #[test]
    fn a_targeted_result_renders_each_policy() {
        let v = serde_json::json!({
            "target": {"kind": "profile", "profile": "dev"},
            "changed": true,
            "policies": [{"policy_id": "pol", "revision": 2, "paused": true,
                "cutoff_at": null, "changed": true}],
            "revoked": ["grant_00112233445566778899aabbccddeeff"],
        });
        let text = render_target_result(&v);
        assert!(
            text.contains("every policy of profile dev: changed"),
            "{text}"
        );
        assert!(text.contains("pol revision 2, paused (changed)"), "{text}");
        assert!(text.contains("revoked now: 1 grant(s)"), "{text}");
        assert!(render_target_result(&serde_json::json!({"policy_id": "p"})).contains("policy: p"));
    }
}
