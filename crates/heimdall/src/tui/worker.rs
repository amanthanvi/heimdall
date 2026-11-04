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

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use heimdall_contract::doctor::{DoctorReport, Finding, FindingSeverity};
use heimdall_contract::envelope::{Envelope, NextAction, ResourceRef};
use heimdall_contract::event::{Cursor, EventFilter};
use heimdall_contract::ids::{DecisionId, OperationId};
use heimdall_contract::provider::{InteractionKind, ProbeLevel};
use heimdall_contract::request::{
    CancelRequest, DecideRequest, InspectRequest, InspectSubject, InteractionMode, ObserveRequest,
    Request,
};
use heimdall_contract::setup::{
    ConflictKind, PlanDigest, PreviewIntent, RepairResolution, SetupPlan, SetupRequest,
};
use heimdall_contract::{Code, Timestamp};
use heimdall_localenv::clients::{ClientKind, ClientsConfig, resolve_clients};
use heimdall_localenv::doctor::{CatalogAlias, CatalogIdentity, DoctorRequest, LocalContext};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use serde_json::Value;

use super::data::{Catalog, Doctor, EventLine, MAX_EVENTS, Operation, OperationDetail, Runtime};
use super::model::{Command, HeldRepair, Outcome, RepairPlan, Update};
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
    doctored_aliases: Option<BTreeSet<String>>,
    doctor_running: Arc<AtomicBool>,
    op: Option<OpEvents>,
}

fn inspect(subject: InspectSubject) -> Request {
    Request::Inspect(InspectRequest {
        subject,
        preview: None,
    })
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
            doctored_aliases: None,
            doctor_running: Arc::new(AtomicBool::new(false)),
            op: None,
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
                let what = format!("decision {id}");
                let Ok(decision_id) = DecisionId::parse(&id) else {
                    self.send(Update::Done {
                        what,
                        outcome: invalid_id(),
                    });
                    return;
                };
                let result = match self.attend().await {
                    Err(o) => o,
                    Ok(()) => match self
                        .request(Request::Decide(DecideRequest {
                            decision_id,
                            verdict,
                        }))
                        .await
                    {
                        Some(env) => outcome(&env),
                        None => not_sent(),
                    },
                };
                self.send(Update::Done {
                    what,
                    outcome: result,
                });
            }
            Command::Cancel { id } => {
                let Ok(operation_id) = OperationId::parse(&id) else {
                    self.send(Update::Done {
                        what: format!("cancel {id}"),
                        outcome: invalid_id(),
                    });
                    return;
                };
                let result = match self
                    .request(Request::Cancel(CancelRequest { operation_id }))
                    .await
                {
                    Some(env) => outcome(&env),
                    None => not_sent(),
                };
                self.send(Update::Done {
                    what: format!("cancel {id}"),
                    outcome: result,
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
                let result = self.submit_repair(&plan_digest).await;
                self.send(Update::Done {
                    what,
                    outcome: result,
                });
            }
        }
    }

    async fn refresh(&mut self, doctor: bool) {
        if self.session().await.is_some() {
            let subjects = [
                InspectSubject::Destinations,
                InspectSubject::Profiles,
                InspectSubject::Identities,
                InspectSubject::Operations,
                InspectSubject::Decisions,
                InspectSubject::Projections,
            ];
            let mut answers = Vec::with_capacity(subjects.len());
            for s in subjects {
                match self.request(inspect(s)).await {
                    Some(env) if env.code.is_success() => answers.push(env.data),
                    _ => answers.push(Value::Null),
                }
            }
            if self.client.is_some() {
                self.catalog = Catalog::from_answers(
                    &answers[0],
                    &answers[1],
                    &answers[2],
                    &answers[3],
                    &answers[4],
                    &answers[5],
                    Timestamp::now(),
                );
                self.send(Update::Catalog(Box::new(self.catalog.clone())));
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
        tokio::task::spawn_blocking(move || {
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
        let intent = PreviewIntent::Repair {
            conflict: ConflictKind::ProjectionHeld,
            resolution,
            operation: Some(operation_id),
        };
        let env = self
            .request(Request::Setup(SetupRequest::Preview { intent }))
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

    async fn submit_repair(&mut self, digest: &str) -> Outcome {
        let Ok(plan_digest) = PlanDigest::parse(digest) else {
            return not_sent();
        };
        let Some(request_id) = crate::cli::fresh_request_id().ok() else {
            return not_sent();
        };
        if let Err(o) = self.attend().await {
            return o;
        }
        match self
            .request(Request::Setup(SetupRequest::Repair {
                plan_digest,
                request_id,
            }))
            .await
        {
            Some(env) => outcome(&env),
            None => not_sent(),
        }
    }
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
}
