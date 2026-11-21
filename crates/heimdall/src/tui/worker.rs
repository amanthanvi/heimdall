//! The TUI's worker thread (m02-plan U10; overview §3): IPC with the runtime on a
//! current-thread tokio runtime, and the local doctor work on its blocking pool.
//!
//! The main thread owns the terminal and never waits on the runtime: it sends
//! [`Command`]s and receives [`Event`]s. The worker:
//! * connects to the control endpoint as an **interactive** client and never starts
//!   the runtime unless the owner asks ([`Command::StartRuntime`]);
//! * reads the listings with `inspect` (read-only; spec §10.2);
//! * runs the passive doctor (the `static` level: configuration and `.pub` files,
//!   agent sockets by `stat`, local queries that read no SSH configuration) only at
//!   start, on an explicit refresh, after an action, or when the catalog's aliases
//!   change; never on a search or a periodic tick;
//! * runs an explicit probe level only on its labelled action, with the owner's typed
//!   authorization for a real-tree level ([`Command::Probe`]);
//! * sends `Attend` before `Decide` and before a held repair, and only for them
//!   (ADR-0006 §3.1, §13.6 item 7);
//! * on Unix, forwards SIGHUP, SIGTERM and SIGINT (and SIGWINCH as a resize) to the main
//!   loop, which restores the terminal before it exits. Its handlers stay registered
//!   for the life of the process (tokio never unregisters one), which the connect
//!   handoff relies on anyway (ADR-0007 §8).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use heimdall_contract::doctor::{DoctorReport, Finding, FindingSeverity};
use heimdall_contract::envelope::{Envelope, NextAction, ResourceRef};
use heimdall_contract::event::{Cursor, EventFilter};
use heimdall_contract::ids::{DecisionId, OperationId, RequestId};
use heimdall_contract::provider::{InteractionKind, ProbeLevel};
use heimdall_contract::request::{
    CancelRequest, DecideRequest, InspectRequest, InspectSubject, InteractionMode, ObserveRequest,
    Request, Verdict,
};
use heimdall_contract::setup::{
    ConflictKind, PlanDigest, PreviewIntent, RepairResolution, SetupPlan, SetupRequest,
};
use heimdall_contract::trust::WorkContext;
use heimdall_contract::{Code, Timestamp};
use heimdall_localenv::clients::{ClientKind, ClientsConfig, resolve_clients};
use heimdall_localenv::doctor::{CatalogAlias, CatalogIdentity, DoctorRequest, LocalContext};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use serde_json::Value;

use super::data::{
    Catalog, Doctor, EventLine, ListingFailure, MAX_EVENTS, Operation, OperationDetail, Runtime,
};
use super::model::{Command, HeldRepair, Origin, Outcome, RepairPlan, Update};
use crate::client::{Client, Ctx, connect_as};

/// What the worker needs from the invocation.
#[derive(Debug, Clone)]
pub(crate) struct WorkerConfig {
    /// The CLI context (home, flags).
    pub ctx: Ctx,
    /// The SSH locations of the static pass; `None` when the account home cannot be
    /// resolved (the overview then needs attention: nothing was read).
    pub ssh_paths: Option<SshPaths>,
    /// This process's environment snapshot.
    pub env: Env,
    /// Heimdall's configuration directory (P and the key files live there).
    pub config_dir: Option<PathBuf>,
    /// Test configuration only: the isolation arguments a probe's client gets.
    pub isolation: Option<Vec<OsString>>,
}

/// One message to the main loop.
#[derive(Debug)]
pub(crate) enum Event {
    /// A model update.
    Update(Box<Update>),
    /// A termination signal (Unix): SIGHUP, SIGTERM or SIGINT.
    #[cfg_attr(windows, allow(dead_code))]
    Signal(i32),
    /// The terminal was resized (Unix SIGWINCH).
    #[cfg_attr(windows, allow(dead_code))]
    Resize,
}

/// The handle the main loop keeps.
pub(crate) struct Worker {
    commands: tokio::sync::mpsc::Sender<Command>,
    /// Events from the worker.
    pub events: std::sync::mpsc::Receiver<Event>,
}

/// Bound of the command queue (overview §4: every queue is bounded).
const COMMAND_QUEUE: usize = 64;

impl Worker {
    /// Queue a command; `false` when the queue is full or the worker is gone.
    pub(crate) fn send(&self, command: Command) -> bool {
        self.commands.try_send(command).is_ok()
    }
}

/// Start the worker thread.
///
/// # Errors
/// The thread cannot be spawned.
pub(crate) fn spawn(config: WorkerConfig) -> std::io::Result<Worker> {
    let (commands, rx) = tokio::sync::mpsc::channel(COMMAND_QUEUE);
    let (tx, events) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("heimdall-tui-ipc".into())
        .spawn(move || run(config, rx, tx))?;
    Ok(Worker { commands, events })
}

fn run(
    config: WorkerConfig,
    mut rx: tokio::sync::mpsc::Receiver<Command>,
    tx: std::sync::mpsc::Sender<Event>,
) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        let _ = tx.send(Event::Update(Box::new(Update::Runtime(Runtime::Failed(
            "the TUI's IPC worker could not start".to_owned(),
        )))));
        return;
    };
    rt.block_on(async move {
        #[cfg(unix)]
        forward_signals(&tx);
        let mut state = State::new(config, tx);
        while let Some(first) = rx.recv().await {
            let mut batch = vec![first];
            while let Ok(more) = rx.try_recv() {
                batch.push(more);
            }
            for command in coalesce(batch) {
                state.handle(command).await;
            }
        }
    });
    rt.shutdown_background();
}

/// Merge repeated refreshes (one, re-running the doctor if any asked) and repeated
/// reads of the same operation; keep everything else in order.
fn coalesce(batch: Vec<Command>) -> Vec<Command> {
    let mut out: Vec<Command> = Vec::new();
    for c in batch {
        match &c {
            Command::Refresh { doctor } => {
                if let Some(Command::Refresh { doctor: d }) = out
                    .iter_mut()
                    .find(|o| matches!(o, Command::Refresh { .. }))
                {
                    *d |= *doctor;
                    continue;
                }
            }
            Command::Operation { id }
                if out
                    .iter()
                    .any(|o| matches!(o, Command::Operation { id: other } if other == id)) =>
            {
                continue;
            }
            _ => {}
        }
        out.push(c);
    }
    out
}

#[cfg(unix)]
fn forward_signals(tx: &std::sync::mpsc::Sender<Event>) {
    use tokio::signal::unix::{SignalKind, signal};
    for (kind, number) in [
        (SignalKind::hangup(), 1),
        (SignalKind::terminate(), 15),
        (SignalKind::interrupt(), 2),
        (SignalKind::window_change(), 28),
    ] {
        let Ok(mut stream) = signal(kind) else {
            continue;
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            while stream.recv().await.is_some() {
                let event = if number == 28 {
                    Event::Resize
                } else {
                    Event::Signal(number)
                };
                if tx.send(event).is_err() {
                    break;
                }
            }
        });
    }
}

/// The events read so far for the open operation.
struct OpEvents {
    id: String,
    cursor: Option<Cursor>,
    events: Vec<EventLine>,
}

struct State {
    config: WorkerConfig,
    tx: std::sync::mpsc::Sender<Event>,
    client: Option<Client>,
    allow_start: bool,
    runtime: Option<Runtime>,
    catalog: Catalog,
    /// ⟨M07⟩ Per [`REFRESH_SUBJECTS`] entry, the data of its last good read and when it
    /// was read; a failed read keeps it (Q4: a failed listing is never shown as empty).
    last_good: Vec<(Value, Option<Timestamp>)>,
    /// ⟨M07⟩ The same for `inspect policies` and `inspect workspace` ([`M05_SUBJECTS`]).
    m05_good: [(Value, Option<Timestamp>); 2],
    /// ⟨M07⟩ The subjects whose last read failed (into [`Catalog::failures`]).
    failures: BTreeMap<String, ListingFailure>,
    doctored_aliases: Option<BTreeSet<String>>,
    doctor_running: Arc<AtomicBool>,
    op: Option<OpEvents>,
    /// ⟨M05⟩ The working directory the workspace status is read for (a same-user claim,
    /// ADR-0011 R2; `inspect` is read-only).
    cwd: Option<String>,
    /// ⟨M05⟩ The runtime answered an M05 `inspect` as unsupported on this connection: it does
    /// not offer `trusted-work/1`, so it is not asked again until the next connection.
    m05_unavailable: bool,
}

/// What one refresh reads, in order: only `inspect` subjects (read-only, passive;
/// spec §10.2). ⟨M03⟩ U12 adds the enrollments, the owned connections and the
/// capabilities. ⟨M07⟩ U1 adds the environments (the Environments view, the overview's own
/// environment). Never `issuer`: the TUI's listings never reach the issuer, and nothing
/// here reaches a remote host.
pub(crate) const REFRESH_SUBJECTS: [InspectSubject; 10] = [
    InspectSubject::Destinations,
    InspectSubject::Profiles,
    InspectSubject::Identities,
    InspectSubject::Operations,
    InspectSubject::Decisions,
    InspectSubject::Projections,
    InspectSubject::Enrollments,
    InspectSubject::Connections,
    InspectSubject::Capabilities,
    InspectSubject::Environments,
];

fn inspect(subject: InspectSubject) -> Request {
    Request::Inspect(InspectRequest {
        subject,
        preview: None,
        cwd: None,
        redact: false,
    })
}

/// ⟨M07⟩ The wire name of `subject` (`destinations`, ...).
fn subject_name(subject: InspectSubject) -> String {
    serde_json::to_value(subject)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{subject:?}"))
}

/// ⟨M07⟩ Fold one listing's answer in (Q4): a good answer replaces the subject's data
/// and clears its failure; a failed one keeps the last good data (now stale) and records
/// the failure, keeping its first time while the code and message repeat.
fn record_answer(
    last_good: &mut (Value, Option<Timestamp>),
    failures: &mut BTreeMap<String, ListingFailure>,
    subject: String,
    answer: Result<Value, (String, String)>,
    now: Timestamp,
) {
    match answer {
        Ok(data) => {
            *last_good = (data, Some(now));
            failures.remove(&subject);
        }
        Err((code, message)) => {
            let message = super::data::clean(&message);
            let since = failures
                .get(&subject)
                .filter(|f| f.code == code && f.message == message)
                .map_or(now, |f| f.since);
            failures.insert(
                subject,
                ListingFailure {
                    code,
                    message,
                    since,
                    stale_from: last_good.1,
                },
            );
        }
    }
}

/// ⟨M07⟩ The two trusted-work listings' names in the failure cache, in [`State::m05_good`]
/// order.
const M05_SUBJECTS: [&str; 2] = [
    super::data::subject::POLICIES,
    super::data::subject::WORKSPACE,
];

/// ⟨M07⟩ One listing's answer in a refresh round, for [`record_answer`] (M07-W0-R03). A
/// good answer is its data (its warnings are collected). A failed one is its code and
/// message. A transport failure (`SERVICE_UNAVAILABLE`, which drops the session, or a
/// request that could not be sent) is also kept in `lost`: the round asks nothing more,
/// and every listing it did not read fails the same way.
fn round_answer(
    lost: &mut Option<(String, String)>,
    env: Option<Envelope<Value>>,
    warnings: &mut Vec<heimdall_contract::envelope::Warning>,
) -> Result<Value, (String, String)> {
    match env {
        Some(env) if env.code.is_success() => {
            warnings.extend(env.warnings);
            Ok(env.data)
        }
        Some(env) => {
            let failure = (env.code.to_string(), message_of(&env));
            if env.code == Code::ServiceUnavailable {
                *lost = Some(failure.clone());
            }
            Err(failure)
        }
        None => {
            let failure = (
                Code::ServiceUnavailable.to_string(),
                "the runtime is not connected".to_owned(),
            );
            *lost = Some(failure.clone());
            Err(failure)
        }
    }
}

fn message_of(env: &Envelope<Value>) -> String {
    env.data
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .map_or_else(|| env.code.to_string(), super::data::clean)
}

fn outcome(env: &Envelope<Value>) -> Outcome {
    Outcome {
        ok: env.code.is_success(),
        code: env.code.to_string(),
        message: message_of(env),
        decision_ref: env
            .next
            .as_ref()
            .and_then(|n: &NextAction| n.decision_ref.clone()),
    }
}

/// The catalog as the doctor reads it: each destination's alias and definition, and
/// the adopted identity a managed one renders (an observed alias is evaluated with a
/// placeholder identity, so every entry of its own selection is reported).
fn catalog_aliases(catalog: &Catalog, config_dir: Option<&std::path::Path>) -> Vec<CatalogAlias> {
    use heimdall_contract::doctor::AliasDefinition;
    catalog
        .destinations
        .iter()
        .map(|d| {
            let identity = if d.is_managed() {
                d.identity_id
                    .as_deref()
                    .and_then(|id| catalog.identity(id))
                    .map(|i| CatalogIdentity {
                        public_key_path: config_dir.map_or_else(PathBuf::new, |c| {
                            c.join(heimdall_localenv::materialize::key_file_path(
                                &i.fingerprint,
                            ))
                        }),
                        fingerprint: Some(i.fingerprint.clone()),
                        interaction: serde_json::from_value::<InteractionKind>(Value::String(
                            i.interaction.clone(),
                        ))
                        .unwrap_or(InteractionKind::Unknown),
                        endpoint: i.endpoint.as_deref().and_then(|e| {
                            heimdall_localenv::agents::locator_for(e, Platform::current())
                        }),
                    })
            } else {
                Some(CatalogIdentity {
                    public_key_path: PathBuf::new(),
                    fingerprint: None,
                    interaction: InteractionKind::Unknown,
                    endpoint: None,
                })
            };
            CatalogAlias {
                alias: d.alias.clone(),
                definition: if d.is_managed() {
                    AliasDefinition::Managed
                } else {
                    AliasDefinition::Observed
                },
                identity,
            }
        })
        .collect()
}

/// The report when the static pass cannot run at all: one problem, so the overview
/// needs attention instead of reading as Ready over nothing (fail closed).
fn unavailable_report() -> DoctorReport {
    DoctorReport {
        levels_performed: BTreeSet::new(),
        levels_declined: BTreeSet::new(),
        clients: Vec::new(),
        config_files: Vec::new(),
        aliases: Vec::new(),
        providers: Vec::new(),
        projection: None,
        git: None,
        findings: vec![Finding {
            code: "static_pass_unavailable".to_owned(),
            severity: FindingSeverity::Problem,
            subject: ResourceRef {
                kind: "configuration".to_owned(),
                id: None,
            },
            level: ProbeLevel::Static,
            provenance: None,
            message: "the account home cannot be resolved, so your SSH configuration was not read"
                .to_owned(),
            next: NextAction::for_code(Code::UsageError),
            reason: None,
        }],
        probes: Vec::new(),
    }
}

impl State {
    fn new(config: WorkerConfig, tx: std::sync::mpsc::Sender<Event>) -> Self {
        Self {
            config,
            tx,
            client: None,
            allow_start: false,
            runtime: None,
            catalog: Catalog::default(),
            last_good: vec![(Value::Null, None); REFRESH_SUBJECTS.len()],
            m05_good: [(Value::Null, None), (Value::Null, None)],
            failures: BTreeMap::new(),
            doctored_aliases: None,
            doctor_running: Arc::new(AtomicBool::new(false)),
            op: None,
            cwd: std::env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
                .filter(|c| WorkContext { cwd: c.clone() }.validate().is_ok()),
            m05_unavailable: false,
        }
    }

    fn send(&self, update: Update) {
        let _ = self.tx.send(Event::Update(Box::new(update)));
    }

    fn set_runtime(&mut self, r: Runtime) {
        if self.runtime.as_ref() != Some(&r) {
            self.runtime = Some(r.clone());
            self.send(Update::Runtime(r));
        }
    }

    async fn session(&mut self) -> Option<&mut Client> {
        if self.client.is_none() {
            match connect_as(
                &self.config.ctx,
                self.allow_start,
                &[],
                InteractionMode::Interactive,
            )
            .await
            {
                Ok(c) => {
                    self.client = Some(c);
                    self.m05_unavailable = false;
                    self.set_runtime(Runtime::Connected);
                }
                Err(env) => {
                    let message = env.data.error.message.clone();
                    let r = if message.starts_with("no runtime is running") {
                        Runtime::NotRunning
                    } else {
                        Runtime::Failed(message)
                    };
                    self.set_runtime(r);
                    return None;
                }
            }
        }
        self.client.as_mut()
    }

    /// Send `request`; a transport failure drops the session (the next refresh
    /// reconnects).
    async fn request(&mut self, request: Request) -> Option<Envelope<Value>> {
        let env = self.session().await?.request(request).await;
        if env.code == Code::ServiceUnavailable {
            self.client = None;
            self.set_runtime(Runtime::Failed(message_of(&env)));
        }
        Some(env)
    }

    /// `Attend` first; `Err` carries the refusal.
    async fn attend(&mut self) -> Result<(), Outcome> {
        let Some(client) = self.session().await else {
            return Err(Outcome {
                ok: false,
                code: Code::ServiceUnavailable.to_string(),
                message: "the runtime is not connected; nothing was sent".to_owned(),
                decision_ref: None,
            });
        };
        let env = client.attend().await;
        if env.code.is_success() {
            Ok(())
        } else {
            Err(outcome(&env))
        }
    }

    async fn handle(&mut self, command: Command) {
        match command {
            Command::Refresh { doctor } => self.refresh(doctor).await,
            Command::StartRuntime => {
                self.allow_start = true;
                self.client = None;
                self.refresh(true).await;
                self.allow_start = false;
            }
            Command::Operation { id } => self.operation(id).await,
            Command::Decide { id, verdict } => {
                let Some(request) = decide_request(&id, verdict) else {
                    self.send(Update::Decided {
                        id,
                        outcome: invalid_id(),
                    });
                    return;
                };
                let result = match self.attend().await {
                    Err(o) => o,
                    Ok(()) => match self.request(request).await {
                        Some(env) => outcome(&env),
                        None => not_sent(),
                    },
                };
                // ⟨M07⟩ M07-W0-R07: with the decision's ID, so a stale answer is matched
                // with its own modal and its own originating request.
                self.send(Update::Decided {
                    id,
                    outcome: result,
                });
            }
            Command::Cancel { id } => {
                let Some(request) = cancel_request(&id) else {
                    self.send(Update::Done {
                        what: format!("cancel {id}"),
                        outcome: invalid_id(),
                    });
                    return;
                };
                let result = match self.request(request).await {
                    Some(env) => outcome(&env),
                    None => not_sent(),
                };
                self.send(Update::Done {
                    what: format!("cancel {id}"),
                    outcome: result,
                });
            }
            // ⟨M05⟩ One narrowing action of the stop menu as the CLI sends it; a cutoff
            // attends first (it may become a widening record), `pause`, `stop` and a work
            // stop never do (they create no decision).
            Command::Stop(action) => {
                let (what, attends) = (action.what(), action.attends());
                self.originate(what, attends, |id| action.request(id)).await;
            }
            // ⟨M07⟩ One Settings change as the CLI sends it: a widening attends first (the
            // runtime answers it with a decision, which the decision modal then shows); a
            // narrowing and the default profile never do.
            Command::Setting(action) => {
                let (what, attends) = (action.what(), action.attends());
                self.originate(what, attends, |id| action.request(id)).await;
            }
            // ⟨M07⟩ M07-W0-R07: the same request again, for a decision that went stale.
            Command::Resend { origin, replaces } => {
                let outcome = self.send_origin(&origin).await;
                self.send(Update::Sent {
                    origin,
                    outcome,
                    replaces: Some(replaces),
                });
            }
            Command::PrepareProbe { alias, level } => self.prepare_probe(alias, level),
            Command::Probe {
                alias,
                level,
                allow_config_commands,
            } => self.probe(alias, level, allow_config_commands),
            Command::PreviewRepair { operation, repair } => {
                let plan = self.preview_repair(&operation, repair).await;
                self.send(Update::RepairPlan {
                    operation,
                    repair,
                    plan,
                });
            }
            Command::SubmitRepair {
                operation,
                repair,
                plan_digest,
            } => {
                let what = format!("{} {operation}", repair.name());
                let Ok(plan_digest) = PlanDigest::parse(&plan_digest) else {
                    self.send(Update::Done {
                        what,
                        outcome: not_sent(),
                    });
                    return;
                };
                self.originate(what, true, |id| submit_repair_request(plan_digest, id))
                    .await;
            }
        }
    }

    async fn refresh(&mut self, doctor: bool) {
        if self.session().await.is_some() {
            let mut warnings = Vec::new();
            // ⟨M07⟩ M07-W0-R03: a transport failure ends the round's reads. The listings
            // not read keep their last good data and are recorded as failed too, and the
            // round is published either way: the failure is never lost with the session.
            let mut lost: Option<(String, String)> = None;
            for (i, s) in REFRESH_SUBJECTS.into_iter().enumerate() {
                let answer = match lost.clone() {
                    Some(failure) => Err(failure),
                    None => {
                        let env = self.request(inspect(s)).await;
                        round_answer(&mut lost, env, &mut warnings)
                    }
                };
                record_answer(
                    &mut self.last_good[i],
                    &mut self.failures,
                    subject_name(s),
                    answer,
                    Timestamp::now(),
                );
            }
            // ⟨M05⟩ The policies and the working directory's workspace, through the same
            // failure cache.
            let m05 = self.read_m05(&mut lost).await;
            self.publish(m05, &warnings);
        } else {
            // ⟨M07⟩ M07-W0-R03: not connected. What was read before is still shown, so it
            // is published as stale (every listing failed with why the runtime is not
            // reachable); with nothing ever read there is nothing to mark.
            if self.ever_read() {
                let why = (
                    Code::ServiceUnavailable.to_string(),
                    match &self.runtime {
                        Some(Runtime::Failed(m)) => super::data::clean(m),
                        _ => "no runtime is running".to_owned(),
                    },
                );
                let now = Timestamp::now();
                for (i, s) in REFRESH_SUBJECTS.into_iter().enumerate() {
                    record_answer(
                        &mut self.last_good[i],
                        &mut self.failures,
                        subject_name(s),
                        Err(why.clone()),
                        now,
                    );
                }
                for (slot, name) in self.m05_good.iter_mut().zip(M05_SUBJECTS) {
                    if slot.1.is_some() {
                        record_answer(
                            slot,
                            &mut self.failures,
                            name.to_owned(),
                            Err(why.clone()),
                            now,
                        );
                    }
                }
                let m05 = super::m05::Listings::of(&self.m05_good[0].0, &self.m05_good[1].0);
                self.publish(m05, &[]);
            }
            // ⟨M03⟩ F14: with no runtime, the pending chores come from the store, read
            // only (worker U's reader; the runtime is never started).
            let ctx = self.config.ctx.clone();
            if let Ok(lines) = tokio::task::spawn_blocking(move || {
                crate::doctor_cmd::pending_chores(&ctx)
                    .iter()
                    .map(super::m03::chore_line)
                    .collect::<Vec<_>>()
            })
            .await
            {
                self.send(Update::OfflineChores(lines));
            }
        }
        let aliases: BTreeSet<String> = self
            .catalog
            .destinations
            .iter()
            .map(|d| d.alias.clone())
            .collect();
        if doctor || self.doctored_aliases.as_ref() != Some(&aliases) {
            self.doctored_aliases = Some(aliases);
            self.run_doctor();
        }
    }

    /// ⟨M07⟩ Whether any listing has ever been read (so something stale can be on screen).
    fn ever_read(&self) -> bool {
        self.last_good
            .iter()
            .chain(&self.m05_good)
            .any(|(_, at)| at.is_some())
    }

    /// ⟨M07⟩ Build the catalog from each listing's last good data with the recorded
    /// failures, and send it: after every round, whether its reads succeeded or not.
    fn publish(
        &mut self,
        m05: super::m05::Listings,
        warnings: &[heimdall_contract::envelope::Warning],
    ) {
        let answers = &self.last_good;
        self.catalog = Catalog::from_answers(
            &answers[0].0,
            &answers[1].0,
            &answers[2].0,
            &answers[3].0,
            &answers[4].0,
            &answers[5].0,
            Timestamp::now(),
        );
        // ⟨M03⟩ U12: the enrollments, the owned connections, the capabilities' lock
        // report, and the time warning any answer carried.
        self.catalog.m03 =
            super::m03::Listings::of(&answers[6].0, &answers[7].0, &answers[8].0, warnings);
        // ⟨M07⟩ Every environment the runtime knows, its own first.
        self.catalog.environments = super::m07::Environments::of(&answers[9].0);
        self.catalog.m05 = m05;
        self.catalog.failures = self.failures.clone();
        self.send(Update::Catalog(Box::new(self.catalog.clone())));
    }

    /// ⟨M05⟩ `inspect policies` and `inspect workspace` for the working directory. A runtime
    /// that does not offer `trusted-work/1` answers `SCHEMA_UNSUPPORTED` (or
    /// `CAPABILITY_UNAVAILABLE`): that reads as "not available" and is not asked again on this
    /// connection. Both are read-only and contact nothing outside the runtime.
    ///
    /// ⟨M07⟩ M07-W0-R03: any other failed answer goes through the listings' failure cache
    /// ([`record_answer`], under `policies` and `workspace`): the last good answer is kept
    /// and marked stale, and one never read is reported as not read, so Settings never
    /// shows "none set" for a default profile it could not read. `lost` is the round's
    /// transport failure, if the session dropped.
    async fn read_m05(&mut self, lost: &mut Option<(String, String)>) -> super::m05::Listings {
        let not_served = |state: &mut Self| {
            state.m05_unavailable = true;
            state.m05_good = [(Value::Null, None), (Value::Null, None)];
            for name in M05_SUBJECTS {
                state.failures.remove(name);
            }
            super::m05::Listings::default()
        };
        if self.m05_unavailable {
            return not_served(self);
        }
        let unserved = |env: &Envelope<Value>| {
            matches!(
                env.code,
                Code::SchemaUnsupported | Code::CapabilityUnavailable
            )
        };
        let mut requests = vec![(0, inspect(InspectSubject::Policies))];
        if let Some(cwd) = self.cwd.clone() {
            requests.push((
                1,
                Request::Inspect(InspectRequest {
                    subject: InspectSubject::Workspace,
                    preview: None,
                    cwd: Some(cwd),
                    redact: false,
                }),
            ));
        }
        for (i, request) in requests {
            let answer = match lost.clone() {
                Some(failure) => Err(failure),
                None => match self.request(request).await {
                    Some(env) if unserved(&env) => return not_served(self),
                    env => round_answer(lost, env, &mut Vec::new()),
                },
            };
            record_answer(
                &mut self.m05_good[i],
                &mut self.failures,
                M05_SUBJECTS[i].to_owned(),
                answer,
                Timestamp::now(),
            );
        }
        super::m05::Listings::of(&self.m05_good[0].0, &self.m05_good[1].0)
    }

    /// ⟨M07⟩ M07-W0-R07: send one of the TUI's own requests that the runtime may answer
    /// with a decision, and report it with the request itself ([`Update::Sent`]): the
    /// model keeps it while that decision is pending, so a stale decision can be retried
    /// with exactly this request, request ID included.
    async fn originate(
        &mut self,
        what: String,
        attends: bool,
        request: impl FnOnce(RequestId) -> Request,
    ) {
        let Ok(request_id) = crate::cli::fresh_request_id() else {
            self.send(Update::Done {
                what,
                outcome: Outcome {
                    ok: false,
                    code: Code::InternalError.to_string(),
                    message: "randomness unavailable; nothing was sent".to_owned(),
                    decision_ref: None,
                },
            });
            return;
        };
        let origin = Origin {
            what,
            request: Box::new(request(request_id)),
            attends,
        };
        let outcome = self.send_origin(&origin).await;
        self.send(Update::Sent {
            origin,
            outcome,
            replaces: None,
        });
    }

    /// Send `origin`'s request as it is, attending first when it did.
    async fn send_origin(&mut self, origin: &Origin) -> Outcome {
        if origin.attends
            && let Err(refused) = self.attend().await
        {
            return refused;
        }
        match self.request((*origin.request).clone()).await {
            Some(env) => outcome(&env),
            None => not_sent(),
        }
    }

    fn local_context(&self) -> Option<LocalContext> {
        let paths = self.config.ssh_paths.clone()?;
        let mut local = LocalContext::new(
            paths,
            self.config.env.clone(),
            Platform::current(),
            ClientsConfig::default(),
            Default::default(),
        );
        local.managed_file = self
            .config
            .config_dir
            .as_ref()
            .map(|c| c.join("ssh_config"));
        local.client_isolation = self.config.isolation.clone();
        local.catalog = catalog_aliases(&self.catalog, self.config.config_dir.as_deref());
        Some(local)
    }

    fn run_doctor(&self) {
        if self.doctor_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let local = self.local_context();
        let tx = self.tx.clone();
        let running = Arc::clone(&self.doctor_running);
        let ctx = self.config.ctx.clone();
        tokio::task::spawn_blocking(move || {
            // ⟨M03⟩ U12: the managed facts (free slots, managed directories) worker U's
            // doctor reads, so the passive pass reports `slot_free` and
            // `managed_dir_unsafe` as `heimdall doctor` does.
            let local = local.map(|mut l| {
                l.managed = crate::doctor_cmd::managed_facts(&ctx);
                l
            });
            let taken_at = Timestamp::now();
            let report = local.map_or_else(unavailable_report, |l| {
                heimdall_localenv::doctor::run(&l, &DoctorRequest::passive())
            });
            running.store(false, Ordering::SeqCst);
            let _ = tx.send(Event::Update(Box::new(Update::Doctor(Box::new(Doctor {
                report,
                taken_at,
            })))));
        });
    }

    fn prepare_probe(&self, alias: String, level: ProbeLevel) {
        let local = self.local_context();
        let tx = self.tx.clone();
        tokio::task::spawn_blocking(move || {
            let update = match local {
                Some(l) => {
                    let version =
                        resolve_clients(&l.env, &l.paths, &l.clients, LocalQueries::Enabled)
                            .selected(ClientKind::Ssh)
                            .and_then(|c| c.version);
                    let pass = heimdall_localenv::probe::static_pass(&l, &alias, version);
                    Update::ProbePrepared {
                        alias,
                        level,
                        executed: pass
                            .executed
                            .iter()
                            .map(|p| format!("{}:{}", p.path_display, p.line))
                            .collect(),
                        not_fully_readable: pass.not_fully_readable,
                    }
                }
                None => Update::ProbeDone {
                    alias,
                    level,
                    report: Err("the account home cannot be resolved; nothing ran".to_owned()),
                },
            };
            let _ = tx.send(Event::Update(Box::new(update)));
        });
    }

    fn probe(&self, alias: String, level: ProbeLevel, allow_config_commands: bool) {
        let local = self.local_context();
        let tx = self.tx.clone();
        tokio::task::spawn_blocking(move || {
            let report = match local {
                Some(l) => {
                    let request = DoctorRequest {
                        levels: [ProbeLevel::Static, level].into_iter().collect(),
                        allow_config_commands,
                        aliases: Some(vec![alias.clone()]),
                        interactive: true,
                        local_queries: LocalQueries::Enabled,
                        redact: false,
                    };
                    Ok(Box::new(heimdall_localenv::doctor::run(&l, &request)))
                }
                None => Err("the account home cannot be resolved; nothing ran".to_owned()),
            };
            let _ = tx.send(Event::Update(Box::new(Update::ProbeDone {
                alias,
                level,
                report,
            })));
        });
    }

    async fn operation(&mut self, id: String) {
        let Ok(operation_id) = OperationId::parse(&id) else {
            return;
        };
        let mut detail = OperationDetail {
            operation: None,
            events: Vec::new(),
            error: None,
        };
        match self
            .request(Request::Observe(ObserveRequest::Operation {
                operation_id: operation_id.clone(),
                wait_ms: None,
            }))
            .await
        {
            Some(env) if env.code.is_success() => detail.operation = Operation::of(&env.data),
            Some(env) => detail.error = Some(message_of(&env)),
            None => detail.error = Some("the runtime is not connected".to_owned()),
        }
        if self.op.as_ref().is_none_or(|o| o.id != id) {
            self.op = Some(OpEvents {
                id: id.clone(),
                cursor: None,
                events: Vec::new(),
            });
        }
        let cursor = self.op.as_ref().and_then(|o| o.cursor.clone());
        let answer = self
            .request(Request::Observe(ObserveRequest::Events {
                cursor: cursor.clone(),
                filter: EventFilter {
                    operation_id: Some(operation_id),
                    types: Vec::new(),
                },
                limit: Some(64),
            }))
            .await;
        if let (Some(env), Some(op)) = (answer, self.op.as_mut()) {
            if env.code.is_success() {
                let data = &env.data;
                let next = data
                    .get("cursor")
                    .or_else(|| data.get("snapshot").and_then(|s| s.get("cursor")))
                    .cloned()
                    .and_then(|c| serde_json::from_value::<Cursor>(c).ok());
                for e in data
                    .get("events")
                    .and_then(Value::as_array)
                    .map_or(&[][..], Vec::as_slice)
                {
                    op.events.push(EventLine::of(e));
                }
                if op.events.len() > MAX_EVENTS {
                    let drop = op.events.len() - MAX_EVENTS;
                    op.events.drain(..drop);
                }
                if next.is_some() {
                    op.cursor = next;
                }
            } else if let Some(c) = env.next.as_ref().and_then(|n| n.cursor.clone()) {
                // RESYNC_REQUIRED: resume from the boundary it names.
                op.cursor = Some(c);
            }
            detail.events.clone_from(&op.events);
        }
        self.send(Update::Operation { id, detail });
    }

    async fn preview_repair(
        &mut self,
        operation: &str,
        repair: HeldRepair,
    ) -> Result<RepairPlan, String> {
        let operation_id =
            OperationId::parse(operation).map_err(|_| "invalid operation ID".to_owned())?;
        let resolution = match repair {
            HeldRepair::Retry => RepairResolution::RetryHeld,
            HeldRepair::Keep => RepairResolution::KeepHeld,
        };
        let env = self
            .request(preview_repair_request(operation_id, resolution))
            .await
            .ok_or_else(|| "the runtime is not connected; nothing was previewed".to_owned())?;
        if !env.code.is_success() {
            return Err(format!("{}: {}", env.code, message_of(&env)));
        }
        let plan: SetupPlan = serde_json::from_value(env.data)
            .map_err(|_| "the preview could not be read".to_owned())?;
        Ok(RepairPlan {
            digest: plan.plan_digest.as_str().to_owned(),
            lines: plan_lines(&plan, repair),
        })
    }
}

/// ⟨M07⟩ `decide` of a listed decision, as `heimdall decision approve|deny <id>` sends it
/// (`Decide { decision_id, verdict }`); `None` for an ID that does not parse.
pub(crate) fn decide_request(id: &str, verdict: Verdict) -> Option<Request> {
    Some(Request::Decide(DecideRequest {
        decision_id: DecisionId::parse(id).ok()?,
        verdict,
    }))
}

/// ⟨M07⟩ `cancel`, as `heimdall operation cancel <id>` sends it; `None` for an ID that
/// does not parse.
pub(crate) fn cancel_request(id: &str) -> Option<Request> {
    Some(Request::Cancel(CancelRequest {
        operation_id: OperationId::parse(id).ok()?,
    }))
}

/// ⟨M07⟩ A held repair's preview, as `heimdall setup repair --operation <id> retry|keep`
/// previews it (`setup_cmd::repair_intent`).
pub(crate) fn preview_repair_request(
    operation: OperationId,
    resolution: RepairResolution,
) -> Request {
    Request::Setup(SetupRequest::Preview {
        intent: PreviewIntent::Repair {
            conflict: ConflictKind::ProjectionHeld,
            resolution,
            operation: Some(operation),
        },
    })
}

/// ⟨M07⟩ A previewed repair's submission by its plan digest.
pub(crate) fn submit_repair_request(plan_digest: PlanDigest, request_id: RequestId) -> Request {
    Request::Setup(SetupRequest::Repair {
        plan_digest,
        request_id,
    })
}

fn invalid_id() -> Outcome {
    Outcome {
        ok: false,
        code: Code::UsageError.to_string(),
        message: "the listed ID is not valid; nothing was sent".to_owned(),
        decision_ref: None,
    }
}

fn not_sent() -> Outcome {
    Outcome {
        ok: false,
        code: Code::ServiceUnavailable.to_string(),
        message: "nothing was sent".to_owned(),
        decision_ref: None,
    }
}

/// What a held repair's plan says, one line each (paths only, never content).
fn plan_lines(plan: &SetupPlan, repair: HeldRepair) -> Vec<String> {
    let clean = super::data::clean;
    let mut lines = Vec::new();
    if plan.files.is_empty() {
        lines.push(match repair {
            HeldRepair::Keep => "no file changes: every file stays in place as it is".to_owned(),
            HeldRepair::Retry => "no file is written by the plan itself".to_owned(),
        });
    }
    for f in &plan.files {
        let role = serde_json::to_value(f.role)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        lines.push(format!("{role} {}", clean(&f.path_display)));
    }
    for a in &plan.aliases {
        lines.push(format!("alias {}", clean(&a.alias)));
    }
    for f in &plan.findings {
        lines.push(format!("[ !] {}: {}", clean(&f.code), clean(&f.message)));
    }
    lines.push(format!(
        "decision required: {}",
        if plan.consent.decision_required {
            "yes"
        } else {
            "no"
        }
    ));
    lines
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn refreshes_and_operation_reads_coalesce_in_order() {
        let batch = vec![
            Command::Refresh { doctor: false },
            Command::Operation { id: "op_1".into() },
            Command::Cancel { id: "op_1".into() },
            Command::Refresh { doctor: true },
            Command::Operation { id: "op_1".into() },
        ];
        assert_eq!(
            coalesce(batch),
            [
                Command::Refresh { doctor: true },
                Command::Operation { id: "op_1".into() },
                Command::Cancel { id: "op_1".into() },
            ]
        );
    }

    #[test]
    fn a_static_pass_that_cannot_run_needs_attention() {
        let r = unavailable_report();
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].severity, FindingSeverity::Problem);
    }

    /// M07-W0-R03 at the worker's fold: a failed answer is recorded and the round goes on,
    /// but a transport failure (the answer that drops the session, or a request that
    /// could not be sent) ends the round's reads: it is kept, and every listing the round
    /// did not read fails with it and keeps its last good data.
    #[test]
    fn a_transport_failure_fails_the_rest_of_the_round_and_keeps_the_data() {
        use crate::client::error;
        use crate::output::error_value;
        let t = |s: &str| -> Timestamp { s.parse().unwrap() };
        let good = |n: usize| serde_json::json!({"items": [{"alias": format!("a{n}")}]});
        // Every listing was read once.
        let mut slots: Vec<(Value, Option<Timestamp>)> = (0..REFRESH_SUBJECTS.len())
            .map(|n| (good(n), Some(t("2026-11-03T09:00:00Z"))))
            .collect();
        let mut failures = BTreeMap::new();
        // The next round: the first listing answers, the second fails in the runtime, the
        // third answer is the transport failure; nothing more is asked.
        let mut asked = 0;
        let mut lost = None;
        let mut warnings = Vec::new();
        for (i, subject) in REFRESH_SUBJECTS.into_iter().enumerate() {
            let answer = match lost.clone() {
                Some(failure) => Err(failure),
                None => {
                    asked += 1;
                    let env = match i {
                        0 => Envelope::ok(good(100)),
                        1 => error_value(error(Code::InternalError, "the store could not be read")),
                        _ => error_value(error(
                            Code::ServiceUnavailable,
                            "the runtime closed the connection",
                        )),
                    };
                    round_answer(&mut lost, Some(env), &mut warnings)
                }
            };
            record_answer(
                &mut slots[i],
                &mut failures,
                subject_name(subject),
                answer,
                t("2026-11-03T09:00:03Z"),
            );
        }
        assert_eq!(
            asked, 3,
            "a dropped session is not asked again in the round"
        );
        assert_eq!(slots[0].0, good(100), "the listing that answered is new");
        assert_eq!(failures.len(), REFRESH_SUBJECTS.len() - 1);
        for (i, subject) in REFRESH_SUBJECTS.into_iter().enumerate().skip(1) {
            let f = &failures[&subject_name(subject)];
            assert_eq!(
                f.code,
                if i == 1 {
                    "INTERNAL_ERROR"
                } else {
                    "SERVICE_UNAVAILABLE"
                },
                "{subject:?}"
            );
            assert_eq!(f.stale_from, Some(t("2026-11-03T09:00:00Z")), "{subject:?}");
            assert_eq!(slots[i].0, good(i), "{subject:?} keeps its last good data");
        }
        // A request that could not be sent at all is a transport failure too.
        let mut lost = None;
        let answer = round_answer(&mut lost, None, &mut warnings);
        assert_eq!(answer.as_ref().err(), lost.as_ref());
        assert_eq!(lost.unwrap().0, "SERVICE_UNAVAILABLE");
    }

    /// M07-W0-R03 through the worker itself: when the runtime cannot be reached, a
    /// refresh still publishes. What was read before is sent again with every listing
    /// marked failed (so the views show it as stale), after the connection state. Before
    /// this, a refresh without a session published nothing and the old listings stayed on
    /// screen as if current. The home is a scratch directory with no runtime in it.
    #[test]
    fn a_refresh_without_a_runtime_publishes_what_it_has_as_stale() {
        let t = |s: &str| -> Timestamp { s.parse().unwrap() };
        let home = tempfile::tempdir().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut state = State::new(
            WorkerConfig {
                ctx: Ctx {
                    json: false,
                    non_interactive: false,
                    home: Some(home.path().join("hh")),
                    stdin_tty: false,
                },
                ssh_paths: None,
                env: Env::capture(),
                config_dir: None,
                isolation: None,
            },
            tx,
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Nothing was ever read: only the connection state is published.
        rt.block_on(state.refresh(false));
        let updates = |rx: &std::sync::mpsc::Receiver<Event>| -> Vec<Update> {
            rx.try_iter()
                .filter_map(|e| match e {
                    Event::Update(u) => Some(*u),
                    _ => None,
                })
                .collect()
        };
        let first = updates(&rx);
        assert!(
            first.contains(&Update::Runtime(Runtime::NotRunning)),
            "{first:?}"
        );
        assert!(
            !first.iter().any(|u| matches!(u, Update::Catalog(_))),
            "nothing to mark stale: {first:?}"
        );
        // As after a good round: the destinations and the default profile were read.
        let read_at = t("2026-11-03T09:00:00Z");
        for slot in &mut state.last_good {
            *slot = (serde_json::json!({}), Some(read_at));
        }
        state.last_good[0] = (
            serde_json::json!({"items": [
                {"destination_id": "dst-a", "alias": "alpha", "definition": "observed"}
            ]}),
            Some(read_at),
        );
        state.m05_good[0] = (
            serde_json::json!({"items": [], "default_profiles": [
                {"environment_id": "env_1", "profile_id": "dev"}
            ]}),
            Some(read_at),
        );
        rt.block_on(state.refresh(false));
        let second = updates(&rx);
        let catalogs: Vec<&Catalog> = second
            .iter()
            .filter_map(|u| match u {
                Update::Catalog(c) => Some(&**c),
                _ => None,
            })
            .collect();
        let [stale] = catalogs.as_slice() else {
            panic!("one catalog is published: {second:?}");
        };
        assert_eq!(stale.destinations.len(), 1, "the last good data is kept");
        assert_eq!(
            stale.m05.default_profiles,
            [("env_1".to_owned(), "dev".to_owned())]
        );
        let mut expected: Vec<String> = REFRESH_SUBJECTS.into_iter().map(subject_name).collect();
        expected.push(super::super::data::subject::POLICIES.to_owned());
        expected.sort();
        assert_eq!(
            stale.failures.keys().cloned().collect::<Vec<_>>(),
            expected,
            "every listing that was read is marked; the workspace never was"
        );
        for (name, f) in &stale.failures {
            assert_eq!(f.code, "SERVICE_UNAVAILABLE", "{name}");
            assert_eq!(f.stale_from, Some(read_at), "{name}");
            assert_eq!(f.message, "no runtime is running", "{name}");
        }
        // The same state again is the same publication (so it redraws nothing).
        rt.block_on(state.refresh(false));
        let third = updates(&rx);
        let again = third.iter().find_map(|u| match u {
            Update::Catalog(c) => Some(&**c),
            _ => None,
        });
        assert!(again.is_some_and(|c| c.same_listings(stale)), "{third:?}");
    }

    /// ⟨M07⟩ Q4 at the worker: a failed read keeps the last good data and says since
    /// when it is stale; a repeated failure keeps its first time (so it redraws
    /// nothing); a good read clears it.
    #[test]
    fn a_failed_listing_keeps_the_last_good_data() {
        let t = |s: &str| -> Timestamp { s.parse().unwrap() };
        let mut slot = (Value::Null, None);
        let mut failures = BTreeMap::new();
        let name = subject_name(InspectSubject::Destinations);
        assert_eq!(name, super::super::data::subject::DESTINATIONS);
        let fail = || {
            Err((
                "INTERNAL_ERROR".to_owned(),
                "response exceeds the frame limit".to_owned(),
            ))
        };
        // Never read: the failure says so.
        record_answer(
            &mut slot,
            &mut failures,
            name.clone(),
            fail(),
            t("2026-11-03T09:00:00Z"),
        );
        assert_eq!(slot.0, Value::Null);
        assert_eq!(failures[&name].stale_from, None);
        // A good read clears it.
        let good = serde_json::json!({"items": [{"alias": "alpha"}]});
        record_answer(
            &mut slot,
            &mut failures,
            name.clone(),
            Ok(good.clone()),
            t("2026-11-03T09:00:03Z"),
        );
        assert!(failures.is_empty());
        // A failure after it keeps the data, stale from the good read.
        record_answer(
            &mut slot,
            &mut failures,
            name.clone(),
            fail(),
            t("2026-11-03T09:00:06Z"),
        );
        assert_eq!(slot.0, good);
        let first = failures[&name].clone();
        assert_eq!(first.stale_from, Some(t("2026-11-03T09:00:03Z")));
        assert_eq!(first.since, t("2026-11-03T09:00:06Z"));
        assert_eq!(first.code, "INTERNAL_ERROR");
        // The same failure again: unchanged, so the catalog compares equal.
        record_answer(
            &mut slot,
            &mut failures,
            name.clone(),
            fail(),
            t("2026-11-03T09:00:09Z"),
        );
        assert_eq!(failures[&name], first);
    }
}
