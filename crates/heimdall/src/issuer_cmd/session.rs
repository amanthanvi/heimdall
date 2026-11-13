//! The owner-present ceremonies of `issuer` (ADR-0008 D4 items 1–4): `init` (with
//! `--replace-orphan`), `rotate begin`, `restore` and `unlock`, run by
//! `heimdall_issuer::ceremony` on the controlling terminal, over [`WireSession`]: the
//! ceremony's [`OwnerSession`] on the control endpoint (`Attend`, `Request::Issuer`,
//! `inspect decisions`, `Decide`), one `block_on` per call on this command's own
//! current-thread executor.
//!
//! **Order of refusals.** `--non-interactive`, an unreadable `--bundle`, a missing
//! `--not-stolen` and a process without a controlling terminal are refused before the
//! runtime is contacted (none starts) and before the store is opened.
//!
//! **What is reported.** On success, the issuer status after the ceremony. On a refusal
//! by the runtime, the runtime's own envelope (code, reason, decision reference). A
//! typed answer other than the confirmation word ends exit 3 `INTERACTION_REQUIRED`,
//! naming the pending decision, which then expires; nothing more is sent.

use std::io::Read as _;
use std::path::Path;

use heimdall_contract::Code;
use heimdall_contract::enrollment::DisclosureKind;
use heimdall_contract::envelope::{Envelope, reason};
use heimdall_contract::ids::{CaFingerprint, DecisionId};
use heimdall_contract::issuer::{
    IssuerRequest, IssuerStatus, RECOVERY_BUNDLE_SCHEMA, RecoveryBundle,
};
use heimdall_contract::request::{
    DecideRequest, InspectRequest, InspectSubject, InteractionMode, Request, Verdict,
};
use heimdall_issuer::ceremony::{
    self, CeremonyError, ControllingTerminal, InitOptions, OwnerSession, RegisterDecision,
    RegisterRequest, ReplaceOrphanOptions, RestoreOptions, Restored, SessionError, Tty,
};
use heimdall_issuer::store::SecretStore;

use super::{delete_exact, displaced_of, open_store, render, shown, status_of, test_config};
use crate::cli::{IssuerCommand, IssuerRotateCommand};
use crate::client::{Client, Ctx};
use crate::output;
use crate::setup_cmd::{self, Outcome, failure};

/// The largest recovery bundle read for `--replace-orphan --bundle`.
const BUNDLE_MAX_BYTES: u64 = 16 << 20;

/// What a ceremony command asks for, its arguments checked.
enum Plan {
    Init {
        backup_out: std::path::PathBuf,
        orphan: Option<(CaFingerprint, Option<RecoveryBundle>)>,
    },
    Rotate {
        backup_out: std::path::PathBuf,
    },
    Restore {
        backup: std::path::PathBuf,
    },
    Unlock,
}

/// The owner session over the control endpoint (module docs).
pub(super) struct WireSession<'r> {
    rt: &'r tokio::runtime::Runtime,
    client: Client,
    /// The runtime's (or this module's) last refusal: the command's answer.
    refused: Option<Envelope<serde_json::Value>>,
    /// The last registration decision the runtime named.
    decision: Option<String>,
}

impl WireSession<'_> {
    fn send(&mut self, request: Request) -> Envelope<serde_json::Value> {
        self.rt.block_on(self.client.request(request))
    }

    /// Keep `env` as the command's answer; the ceremony sees its code and reason.
    fn refuse(&mut self, env: Envelope<serde_json::Value>) -> SessionError {
        let reason = env
            .data
            .get("error")
            .and_then(|e| e.get("reason"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let code = env.code.clone();
        self.refused = Some(env);
        SessionError::Refused { code, reason }
    }

    fn status_reply(
        &mut self,
        env: Envelope<serde_json::Value>,
    ) -> Result<IssuerStatus, SessionError> {
        match status_of(&env) {
            Some(st) => Ok(st),
            None if env.code.is_success() => Err(self.refuse(failure(
                Code::InternalError,
                "the runtime's issuer status could not be read",
                None,
            ))),
            None => Err(self.refuse(env)),
        }
    }

    /// `issuer.retire {ca, deleted_locator}` (attended), after this process deleted it.
    fn confirm_deleted(
        &mut self,
        ca: &CaFingerprint,
        locator: &str,
    ) -> Result<IssuerStatus, Envelope<serde_json::Value>> {
        let env = self.send(Request::Issuer(IssuerRequest::Retire {
            ca_fingerprint: ca.clone(),
            deleted_locator: Some(locator.to_owned()),
        }));
        status_of(&env).ok_or(env)
    }
}

/// The `request` of the pending decision `id` in an `inspect decisions` listing.
fn recorded_request(listing: &serde_json::Value, id: &str) -> Option<serde_json::Value> {
    listing
        .get("decisions")?
        .as_array()?
        .iter()
        .find(|d| d.get("decision_id").and_then(|v| v.as_str()) == Some(id))?
        .get("request")
        .cloned()
}

impl OwnerSession for WireSession<'_> {
    fn attend(&mut self) -> Result<(), SessionError> {
        let env = self.rt.block_on(self.client.attend());
        if env.code.is_success() {
            Ok(())
        } else {
            Err(self.refuse(env))
        }
    }

    fn status(&mut self) -> Result<IssuerStatus, SessionError> {
        let env = self.send(Request::Issuer(IssuerRequest::Status));
        self.status_reply(env)
    }

    fn register(&mut self, request: &RegisterRequest) -> Result<RegisterDecision, SessionError> {
        let wire = match request.to_issuer_request() {
            Ok(w) => w,
            Err(e) => {
                // A test-configuration store kind is never on the wire (U10B-Q5; ADR-0008
                // §17.25 item 7: the product-file test store is registrable).
                return Err(self.refuse(failure(
                    e.code(),
                    "the CA key store is a test-configuration store, which cannot be registered (a test kind is never on the wire; a test registers on the product-file test store): nothing was registered or written",
                    e.reason().as_deref(),
                )));
            }
        };
        let env = self.send(Request::Issuer(wire));
        let decision = (env.code == Code::ApprovalRequired)
            .then(|| setup_cmd::pending_decision(&env))
            .flatten();
        let Some(decision) = decision else {
            return Err(self.refuse(env));
        };
        self.decision = Some(decision.clone());
        let listing = self.send(Request::Inspect(InspectRequest {
            subject: InspectSubject::Decisions,
            preview: None,
        }));
        if !listing.code.is_success() {
            return Err(self.refuse(listing));
        }
        let stale = || {
            failure(
                Code::DecisionStale,
                "the registration's decision is not pending in this runtime: nothing more was sent",
                None,
            )
        };
        let Some(recorded) = recorded_request(&listing.data, &decision)
            .filter(|r| r.get("kind").and_then(|k| k.as_str()) == Some("register_issuer"))
        else {
            return Err(self.refuse(stale()));
        };
        let field = |k: &str| recorded.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let (Ok(decision_id), Ok(ca_fingerprint)) = (
            DecisionId::parse(&decision),
            CaFingerprint::parse(field("ca_fingerprint")),
        ) else {
            return Err(self.refuse(stale()));
        };
        let disclosures: Vec<DisclosureKind> = recorded
            .get("disclosures")
            .cloned()
            .and_then(|d| serde_json::from_value(d).ok())
            .unwrap_or_default();
        Ok(RegisterDecision {
            decision_id,
            ca_fingerprint,
            backup_sha256: field("backup_sha256").to_owned(),
            disclosures,
        })
    }

    fn approve(&mut self, decision: &DecisionId) -> Result<(), SessionError> {
        let env = self.send(Request::Decide(DecideRequest {
            decision_id: decision.clone(),
            verdict: Verdict::Approve,
        }));
        if env.code == Code::Ok {
            Ok(())
        } else {
            Err(self.refuse(env))
        }
    }

    fn unlock(&mut self) -> Result<IssuerStatus, SessionError> {
        let env = self.send(Request::Issuer(IssuerRequest::Unlock));
        self.status_reply(env)
    }
}

/// `CeremonyError` as the command's answer (module docs).
fn ceremony_failure(
    e: &CeremonyError,
    refused: Option<Envelope<serde_json::Value>>,
    decision: Option<&str>,
) -> Outcome {
    if let (CeremonyError::Session(_), Some(env)) = (e, refused) {
        return Outcome::of(env);
    }
    let env = match e {
        CeremonyError::NotConfirmed => {
            setup_cmd::not_confirmed(decision, None, "the confirmation word was not typed")
        }
        CeremonyError::StoreUnavailable(a) => failure(
            Code::CapabilityUnavailable,
            a.refusal_reason()
                .and_then(heimdall_app::issuer::unlock_guidance)
                .unwrap_or("the CA key store is unavailable: nothing was written"),
            a.refusal_reason(),
        ),
        other => failure(other.code(), &other.to_string(), other.reason().as_deref()),
    };
    Outcome::of(env)
}

fn backup_out_of(command: &IssuerCommand) -> Option<&Path> {
    match command {
        IssuerCommand::Init { backup_out, .. }
        | IssuerCommand::Rotate(IssuerRotateCommand::Begin { backup_out }) => Some(backup_out),
        _ => None,
    }
}

/// Read and check `--bundle` (a recovery bundle of this schema, public metadata).
fn read_bundle(path: &Path) -> Result<RecoveryBundle, Outcome> {
    let unreadable = |why: &str| {
        setup_cmd::usage(&format!(
            "the recovery bundle {} cannot be used: {why}",
            shown(path)
        ))
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(BUNDLE_MAX_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| unreadable(&format!("{:?}", e.kind())))?;
    if bytes.len() as u64 > BUNDLE_MAX_BYTES {
        return Err(unreadable("it is larger than any recovery bundle"));
    }
    let bundle: RecoveryBundle =
        serde_json::from_slice(&bytes).map_err(|_| unreadable("it is not a recovery bundle"))?;
    if bundle.schema != RECOVERY_BUNDLE_SCHEMA {
        return Err(unreadable("its schema is not heimdall-recovery-bundle/1"));
    }
    Ok(bundle)
}

fn plan_of(command: IssuerCommand) -> Result<Plan, Outcome> {
    match command {
        IssuerCommand::Init {
            backup_out,
            replace_orphan,
            bundle,
            no_bundle_available,
        } => {
            let orphan = match replace_orphan {
                None => None,
                Some(fp) => {
                    let fp = CaFingerprint::parse(&fp).map_err(|_| {
                        setup_cmd::usage(
                            "invalid --replace-orphan fingerprint (expected SHA256:<43 base64 characters>)",
                        )
                    })?;
                    let bundle = match bundle {
                        Some(path) => Some(read_bundle(&path)?),
                        None if no_bundle_available => None,
                        None => {
                            return Err(Outcome::of(failure(
                                CeremonyError::BundleOrFlagRequired.code(),
                                &CeremonyError::BundleOrFlagRequired.to_string(),
                                None,
                            )));
                        }
                    };
                    Some((fp, bundle))
                }
            };
            Ok(Plan::Init { backup_out, orphan })
        }
        IssuerCommand::Rotate(IssuerRotateCommand::Begin { backup_out }) => {
            Ok(Plan::Rotate { backup_out })
        }
        IssuerCommand::Restore { backup, not_stolen } => {
            if !not_stolen {
                return Err(setup_cmd::usage(
                    "restore needs --not-stolen. Restore only if the backup and this device are not believed stolen; if they may be, do not restore: rotate the CA instead (`heimdall issuer rotate begin --backup-out <path>`)",
                ));
            }
            Ok(Plan::Restore { backup })
        }
        IssuerCommand::Unlock => Ok(Plan::Unlock),
        IssuerCommand::Status | IssuerCommand::Retire { .. } | IssuerCommand::Bundle { .. } => {
            Err(setup_cmd::usage("not a ceremony"))
        }
    }
}

/// Run one ceremony command (module docs).
pub(super) fn ceremony(ctx: &Ctx, command: IssuerCommand) -> Outcome {
    if ctx.non_interactive {
        return ceremony_failure(&CeremonyError::NonInteractive, None, None);
    }
    let backup_shown = backup_out_of(&command).map(shown);
    let plan = match plan_of(command) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let test = match test_config(ctx) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let mut tty = match ControllingTerminal::open() {
        Ok(t) => t,
        Err(e) => return ceremony_failure(&e, None, None),
    };
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(env) => return Outcome::of(output::error_value(env)),
    };
    // The ceremony holds the controlling terminal: the owner can interact, whatever
    // stdin is. Attendance is still sent by the ceremony itself, first.
    let client = match rt.block_on(crate::client::connect_as(
        ctx,
        true,
        &[],
        InteractionMode::Interactive,
    )) {
        Ok(c) => c,
        Err(e) => return Outcome::of(output::error_value(*e)),
    };
    let mut s = WireSession {
        rt: &rt,
        client,
        refused: None,
        decision: None,
    };
    let store = match open_store(ctx, &test) {
        Ok(store) => store,
        Err(o) => return o,
    };
    let done = run_plan(
        &mut tty,
        &mut s,
        store.as_ref(),
        &plan,
        backup_shown.as_deref(),
    );
    match done {
        Ok(human) => {
            let env = s.send(Request::Issuer(IssuerRequest::Status));
            match status_of(&env) {
                Some(st) => {
                    let mut text = human;
                    text.push_str(&render::status(&st, &[]));
                    Outcome::of(env).with_human(text)
                }
                None => Outcome::of(env),
            }
        }
        Err(Done::Ceremony(e)) => {
            let decision = s.decision.clone();
            ceremony_failure(&e, s.refused.take(), decision.as_deref())
        }
        Err(Done::Answer(env)) => Outcome::of(*env),
    }
}

/// How a plan stopped.
enum Done {
    /// The ceremony's own error.
    Ceremony(CeremonyError),
    /// An envelope that is the command's answer.
    Answer(Box<Envelope<serde_json::Value>>),
}

impl From<CeremonyError> for Done {
    fn from(e: CeremonyError) -> Self {
        Done::Ceremony(e)
    }
}

impl From<SessionError> for Done {
    fn from(e: SessionError) -> Self {
        Done::Ceremony(CeremonyError::Session(e))
    }
}

fn run_plan(
    tty: &mut ControllingTerminal,
    s: &mut WireSession<'_>,
    store: &dyn SecretStore,
    plan: &Plan,
    backup_shown: Option<&str>,
) -> Result<String, Done> {
    match plan {
        Plan::Init { backup_out, orphan } => {
            let mut text = String::new();
            if let Some((fp, bundle)) = orphan {
                if let Some(b) = bundle
                    && !b.cas.iter().any(|c| c.fingerprint == *fp)
                {
                    let _ = tty.write_text(
                        "Note: the bundle does not list this CA, so it cannot show which accounts trust it.\n",
                    );
                }
                let deleted = ceremony::replace_orphan(
                    tty,
                    s,
                    store,
                    &ReplaceOrphanOptions {
                        fingerprint: fp,
                        bundle: bundle.as_ref(),
                        no_bundle_available: bundle.is_none(),
                        non_interactive: false,
                    },
                )?;
                text.push_str(&format!(
                    "Deleted the orphan CA key {} from the store.\n",
                    deleted.fingerprint
                ));
            }
            let registered = ceremony::init(
                tty,
                s,
                store,
                &InitOptions {
                    backup_out,
                    non_interactive: false,
                },
            )?;
            text.push_str(&render::registered(&registered, backup_shown));
            Ok(text)
        }
        Plan::Rotate { backup_out } => {
            let registered = ceremony::rotate_begin(
                tty,
                s,
                store,
                &InitOptions {
                    backup_out,
                    non_interactive: false,
                },
            )?;
            Ok(render::registered(&registered, backup_shown))
        }
        Plan::Restore { backup } => {
            let restored = ceremony::restore(
                tty,
                s,
                store,
                &RestoreOptions {
                    backup,
                    not_stolen: true,
                    non_interactive: false,
                },
            )?;
            match restored {
                Restored::StoreItemRewritten { fingerprint, .. } => {
                    let resolved = resolve_displaced(tty, s, store, &fingerprint)?;
                    Ok(format!(
                        "CA {fingerprint} restored to the store and reloaded.\n{resolved}"
                    ))
                }
                Restored::RegisteredWithoutLog(r) => Ok(format!(
                    "CA {} registered from its backup without its issuance log: every residual under it is unknown. Rotate it soon (`heimdall issuer rotate begin --backup-out <path>`).\n",
                    r.fingerprint
                )),
                _ => Ok(String::new()),
            }
        }
        Plan::Unlock => {
            ceremony::unlock(tty, s, store, false).map_err(|e| match e {
                CeremonyError::StoreUnavailable(a) => Done::Answer(Box::new(failure(
                    Code::CapabilityUnavailable,
                    a.refusal_reason()
                        .and_then(heimdall_app::issuer::unlock_guidance)
                        .unwrap_or("the CA key store is unavailable: Heimdall never shows a store prompt; unlock the store, then run `heimdall issuer unlock` again"),
                    Some(a.refusal_reason().unwrap_or(reason::ISSUER_STORE_UNAVAILABLE)),
                ))),
                other => Done::Ceremony(other),
            })?;
            Ok("The issuer reloaded its CA keys.\n".to_owned())
        }
    }
}

/// ⟨§17.22 item 12⟩ After a log-intact restore that recorded a new store item: delete
/// each item it displaced by exact identity, and confirm each on the attended session
/// (the item holds the same CA key as the new one, or is already gone).
fn resolve_displaced(
    tty: &mut ControllingTerminal,
    s: &mut WireSession<'_>,
    store: &dyn SecretStore,
    ca: &CaFingerprint,
) -> Result<String, Done> {
    let st = OwnerSession::status(s)?;
    let displaced: Vec<_> = displaced_of(&st, ca).cloned().collect();
    let mut text = String::new();
    for item in displaced {
        let Some(locator) = item.locator else {
            continue;
        };
        delete_exact(store, ca, item.store, &locator).map_err(|e| Done::Answer(Box::new(e)))?;
        s.confirm_deleted(ca, &locator)
            .map_err(|e| Done::Answer(Box::new(e)))?;
        let line = format!("Deleted the store item the restore displaced ({locator}).\n");
        let _ = tty.write_text(&line);
        text.push_str(&line);
    }
    Ok(text)
}
