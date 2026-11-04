//! The TUI's state and its keyboard handling (m02-plan U10; spec §12). Pure: no I/O.
//!
//! [`App::key`] turns one key into [`Effect`]s; [`App::apply`] folds one worker
//! [`Update`] in. Neither touches the terminal, the runtime or the filesystem, so every
//! action is testable by key sequence alone (`keyboard_only_navigation_*` below).
//!
//! **Rules this module enforces.**
//! * Search is immediate and never produces an effect: typing filters the list in
//!   memory and nothing is probed, listed or contacted (spec §12.1, A21).
//! * A pending decision is completed only by a typed `y`/`yes` (case-insensitive,
//!   surrounding whitespace ignored), default **No** (ADR-0006 §3.1). The modal shows
//!   the exact recorded request from the runtime's latest listing, which opening it
//!   refreshes; Enter on anything else, Escape and Ctrl-C send nothing.
//! * A probe level that runs the real configuration tree (`evaluate`,
//!   `host_verification`, `authentication`) first shows the authorization text, "runs
//!   your configuration's commands with whatever effects they have", with the file:line
//!   list the static pass found (or "none found now; the configuration can change
//!   before ssh reads it"), and runs only after a typed `yes`, even when the list is
//!   empty (ADR-0007 §6, M2-R06). A tree the static pass could not fully read is
//!   declined without the prompt (`config_not_fully_readable`).
//! * A held setup operation (ADR-0007 §5.7) is **Needs attention** with its two repairs,
//!   `retry_held` and `keep_held`. Each is previewed first, its plan shown, and it is
//!   submitted only after a typed `yes` (QR12: a client-side confirmation, no decision
//!   record). A repair counts as done only when the refreshed listing shows no held
//!   operation (ADR-0007 §12.19 item 7).

use heimdall_contract::Timestamp;
use heimdall_contract::doctor::{DoctorReport, FindingSeverity};
use heimdall_contract::provider::ProbeLevel;
use heimdall_contract::request::Verdict;

use super::data::{Catalog, Doctor, OperationDetail, Runtime};
use super::keys::Key;

/// The top-level views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    /// Ready / Working / Needs attention.
    Overview,
    /// Catalog destinations.
    Destinations,
    /// Catalog profiles.
    Profiles,
    /// Pending decisions and open operations.
    Activity,
}

impl Tab {
    /// Every tab, in key order (`1`–`4`).
    pub(crate) const ALL: [Tab; 4] = [
        Tab::Overview,
        Tab::Destinations,
        Tab::Profiles,
        Tab::Activity,
    ];

    /// Its title.
    #[must_use]
    pub(crate) fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Destinations => "Destinations",
            Tab::Profiles => "Profiles",
            Tab::Activity => "Activity",
        }
    }

    fn index(self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Destinations => 1,
            Tab::Profiles => 2,
            Tab::Activity => 3,
        }
    }
}

/// What fills the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Screen {
    /// A top-level view.
    Tab(Tab),
    /// One destination's detail, by alias.
    Destination(String),
    /// One profile's detail, by ID.
    Profile(String),
    /// One operation's detail, by ID.
    Operation(String),
}

/// The two repairs of a held setup operation (ADR-0007 §5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldRepair {
    /// `retry_held`: re-observe and continue by the recovery table.
    Retry,
    /// `keep_held`: keep the files as they are and close the operation.
    Keep,
}

impl HeldRepair {
    /// The resolution's wire name.
    #[must_use]
    pub(crate) fn name(self) -> &'static str {
        match self {
            HeldRepair::Retry => "retry_held",
            HeldRepair::Keep => "keep_held",
        }
    }

    /// What it does, in one sentence.
    #[must_use]
    pub(crate) fn sentence(self) -> &'static str {
        match self {
            HeldRepair::Retry => {
                "retry: after you put the file back, Heimdall continues the held operation's own recovery under its approval"
            }
            HeldRepair::Keep => {
                "keep: Heimdall moves and deletes nothing, closes the operation and lists what stays in place"
            }
        }
    }
}

/// A request for the IPC worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    /// Re-read the runtime's listings; with `doctor`, re-run the passive static pass.
    Refresh {
        /// Also re-run the passive doctor.
        doctor: bool,
    },
    /// Start the runtime on demand (the TUI never starts it by itself).
    StartRuntime,
    /// Read one operation and its events.
    Operation {
        /// Operation ID.
        id: String,
    },
    /// Attend, then complete a decision with this verdict.
    Decide {
        /// Decision ID.
        id: String,
        /// Verdict.
        verdict: Verdict,
    },
    /// Cancel an operation (narrowing; no confirmation).
    Cancel {
        /// Operation ID.
        id: String,
    },
    /// Run the static pass for `alias` to show the authorization text of a real-tree
    /// level (nothing executes).
    PrepareProbe {
        /// Alias.
        alias: String,
        /// Level.
        level: ProbeLevel,
    },
    /// Run one explicit probe level for `alias`.
    Probe {
        /// Alias.
        alias: String,
        /// Level.
        level: ProbeLevel,
        /// The owner's typed authorization for a real-tree level.
        allow_config_commands: bool,
    },
    /// Preview a held operation's repair.
    PreviewRepair {
        /// The held operation.
        operation: String,
        /// The repair.
        repair: HeldRepair,
    },
    /// Attend, then submit a previewed repair by its plan digest.
    SubmitRepair {
        /// The held operation.
        operation: String,
        /// The repair.
        repair: HeldRepair,
        /// The digest of the plan the owner saw.
        plan_digest: String,
    },
}

/// What a key asks the main loop to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    /// Send to the IPC worker.
    Worker(Command),
    /// Hand the terminal to `ssh <alias>` (`launch::handoff::run_foreground`).
    Connect(String),
    /// Leave the TUI.
    Quit,
}

/// The result of a request the worker sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// Whether the code is a success.
    pub ok: bool,
    /// The code.
    pub code: String,
    /// The message.
    pub message: String,
    /// `next.decision_ref`, when the runtime issued a decision.
    pub decision_ref: Option<String>,
}

/// A held repair's plan, as previewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepairPlan {
    /// Its digest (what is submitted).
    pub digest: String,
    /// What it will do and what stays in place, one line each.
    pub lines: Vec<String>,
}

/// One message from the worker.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Update {
    /// The runtime connection changed.
    Runtime(Runtime),
    /// Fresh listings.
    Catalog(Box<Catalog>),
    /// A fresh passive doctor report.
    Doctor(Box<Doctor>),
    /// An operation and its events.
    Operation {
        /// Operation ID.
        id: String,
        /// What was read.
        detail: OperationDetail,
    },
    /// The static pass for a real-tree level's authorization text.
    ProbePrepared {
        /// Alias.
        alias: String,
        /// Level.
        level: ProbeLevel,
        /// The executing constructs found, as file:line.
        executed: Vec<String>,
        /// The pass met an unreadable include, a bound or an unexpandable path.
        not_fully_readable: bool,
    },
    /// A probe level finished.
    ProbeDone {
        /// Alias.
        alias: String,
        /// Level.
        level: ProbeLevel,
        /// The report, or why none could be made.
        report: Result<Box<DoctorReport>, String>,
    },
    /// A repair preview.
    RepairPlan {
        /// The held operation.
        operation: String,
        /// The repair.
        repair: HeldRepair,
        /// The plan, or the refusal.
        plan: Result<RepairPlan, String>,
    },
    /// A request finished (`what` names it).
    Done {
        /// What was sent.
        what: String,
        /// Its result.
        outcome: Outcome,
    },
}

/// The authorization text of a real-tree level (ADR-0007 §6).
pub(crate) const AUTHORIZATION_TEXT: &str =
    "runs your configuration's commands with whatever effects they have";

/// What the authorization shows when the static pass found no executing construct.
pub(crate) const NONE_FOUND_TEXT: &str =
    "none found now; the configuration can change before ssh reads it";

/// The longest typed confirmation kept.
const MAX_TYPED: usize = 16;

/// A typed `y`/`yes` (case-insensitive, surrounding whitespace ignored); anything else
/// is No (ADR-0006 §3.1).
#[must_use]
pub(crate) fn typed_yes(input: &str) -> bool {
    crate::prompt::classify(Some(input)) == crate::prompt::Answer::Yes
}

/// The probe levels, in ladder order, with the label each action shows.
pub(crate) const PROBE_LEVELS: [(ProbeLevel, &str, &str); 6] = [
    (
        ProbeLevel::Static,
        "static",
        "re-run the passive static pass (nothing executes)",
    ),
    (
        ProbeLevel::Evaluate,
        "evaluate",
        "ssh -G with your configuration (runs its commands)",
    ),
    (
        ProbeLevel::Agent,
        "agent",
        "one identity-listing request to each agent endpoint",
    ),
    (
        ProbeLevel::Network,
        "network",
        "TCP connect to the host and read its SSH banner",
    ),
    (
        ProbeLevel::HostVerification,
        "host_verification",
        "host-key check with nothing to sign (runs your configuration's commands)",
    ),
    (
        ProbeLevel::Authentication,
        "authentication",
        "a real authentication, ssh -T ... exit 0 (runs your configuration's commands)",
    ),
];

/// The name of a probe level.
#[must_use]
pub(crate) fn level_name(level: ProbeLevel) -> &'static str {
    PROBE_LEVELS
        .iter()
        .find(|(l, _, _)| *l == level)
        .map_or("?", |(_, n, _)| n)
}

/// Whether the level runs ssh against the real configuration tree, so it needs the
/// typed authorization (ADR-0007 §6).
#[must_use]
pub(crate) fn runs_real_tree(level: ProbeLevel) -> bool {
    matches!(
        level,
        ProbeLevel::Evaluate | ProbeLevel::HostVerification | ProbeLevel::Authentication
    )
}

/// The decision modal: the exact recorded request and a typed confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecisionPrompt {
    /// Decision ID.
    pub id: String,
    /// The verdict a `yes` sends (Tab toggles).
    pub verdict: Verdict,
    /// What was typed.
    pub input: String,
    /// Scroll offset of the recorded request.
    pub scroll: u16,
}

/// The real-tree authorization modal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthPrompt {
    /// Alias.
    pub alias: String,
    /// Level.
    pub level: ProbeLevel,
    /// The constructs the static pass found (`None` while it runs).
    pub executed: Option<Vec<String>>,
    /// What was typed.
    pub input: String,
}

/// The held-repair confirmation modal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepairPrompt {
    /// The held operation.
    pub operation: String,
    /// The repair.
    pub repair: HeldRepair,
    /// The plan (`None` while it is previewed).
    pub plan: Option<Result<RepairPlan, String>>,
    /// What was typed.
    pub input: String,
}

/// A probe's result view.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProbeView {
    /// Alias.
    pub alias: String,
    /// Level.
    pub level: ProbeLevel,
    /// The report (`None` while it runs).
    pub report: Option<Result<Box<DoctorReport>, String>>,
    /// Scroll offset.
    pub scroll: u16,
}

/// A window over the main screen.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Modal {
    /// Key help.
    Help,
    /// A pending decision.
    Decision(DecisionPrompt),
    /// The labelled probe levels for an alias.
    ProbeMenu {
        /// Alias.
        alias: String,
        /// Selected level index into [`PROBE_LEVELS`].
        selected: usize,
    },
    /// The typed authorization of a real-tree level.
    Authorization(AuthPrompt),
    /// A held repair's plan and confirmation.
    Repair(RepairPrompt),
    /// A probe's result.
    Probe(ProbeView),
}

/// The immediate search of a list view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Search {
    /// Typing goes to the search field.
    pub editing: bool,
    /// The filter text.
    pub text: String,
}

/// Overall state (spec §12.1: "Ready" or "Working", not a list of alarms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Health {
    /// Nothing waits on the owner and nothing runs.
    Ready,
    /// Work is in progress.
    Working,
    /// Something needs the owner.
    Attention,
    /// Not known yet (first read in progress).
    Checking,
}

impl Health {
    /// Its text marker (never color alone, spec §12.2).
    #[must_use]
    pub(crate) fn marker(self) -> &'static str {
        match self {
            Health::Ready => "[OK]",
            Health::Working => "[..]",
            Health::Attention => "[!!]",
            Health::Checking => "[??]",
        }
    }

    /// Its words.
    #[must_use]
    pub(crate) fn words(self) -> &'static str {
        match self {
            Health::Ready => "Ready",
            Health::Working => "Working",
            Health::Attention => "Needs attention",
            Health::Checking => "Checking",
        }
    }
}

/// One line of the overview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Item {
    /// A held setup operation, with its two repairs.
    Held {
        /// Operation ID.
        op: String,
        /// Kind.
        kind: String,
    },
    /// A pending decision.
    Decision {
        /// Decision ID.
        id: String,
        /// Kind.
        kind: String,
    },
    /// An unresolved operation (not held).
    Unresolved {
        /// Operation ID.
        op: String,
        /// Kind.
        kind: String,
    },
    /// A doctor finding of severity `problem`.
    Problem {
        /// Finding code.
        code: String,
        /// The alias it concerns, when it concerns one.
        alias: Option<String>,
        /// Message.
        message: String,
    },
    /// An operation in progress.
    Working {
        /// Operation ID.
        op: String,
        /// Kind.
        kind: String,
        /// State.
        state: String,
    },
    /// A doctor finding of severity `warning`.
    Warning {
        /// Finding code.
        code: String,
        /// The alias it concerns, when it concerns one.
        alias: Option<String>,
        /// Message.
        message: String,
    },
}

impl Item {
    /// Whether it makes the overview **Needs attention**.
    #[must_use]
    pub(crate) fn needs_attention(&self) -> bool {
        matches!(
            self,
            Item::Held { .. }
                | Item::Decision { .. }
                | Item::Unresolved { .. }
                | Item::Problem { .. }
        )
    }
}

/// An Activity row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActivityRow {
    /// A pending decision (ID).
    Decision(String),
    /// An operation (ID).
    Operation(String),
}

/// The whole TUI state.
#[derive(Debug, Clone)]
pub(crate) struct App {
    /// The runtime connection.
    pub runtime: Runtime,
    /// The runtime's latest listings.
    pub catalog: Catalog,
    /// The latest passive doctor report.
    pub doctor: Option<Doctor>,
    /// The open operation detail.
    pub operation: Option<(String, OperationDetail)>,
    /// What fills the screen.
    pub screen: Screen,
    /// The tab a sub-screen returns to.
    pub tab: Tab,
    /// Selected row per tab.
    pub selected: [usize; 4],
    /// Searches of Destinations and Profiles.
    pub searches: [Search; 2],
    /// Scroll offset of a detail screen.
    pub scroll: u16,
    /// The open modal.
    pub modal: Option<Modal>,
    /// The status line.
    pub status: Option<String>,
    /// The clock the screen's ages are computed from.
    pub now: Timestamp,
    /// A decision the runtime just issued, opened once it is listed.
    pub open_when_listed: Option<String>,
    /// Whether the color theme is off (`NO_COLOR`).
    pub no_color: bool,
}

impl App {
    /// A fresh state at `now`.
    #[must_use]
    pub(crate) fn new(now: Timestamp, no_color: bool) -> Self {
        Self {
            runtime: Runtime::Connecting,
            catalog: Catalog::default(),
            doctor: None,
            operation: None,
            screen: Screen::Tab(Tab::Overview),
            tab: Tab::Overview,
            selected: [0; 4],
            searches: [Search::default(), Search::default()],
            scroll: 0,
            modal: None,
            status: None,
            now,
            open_when_listed: None,
            no_color,
        }
    }

    // ---- derived views --------------------------------------------------------------

    /// The overview's lines: what needs attention first, then work in progress, then
    /// warnings.
    #[must_use]
    pub(crate) fn overview_items(&self) -> Vec<Item> {
        let mut attention = Vec::new();
        let mut working = Vec::new();
        let mut warnings = Vec::new();
        for op in &self.catalog.operations {
            if op.is_held() {
                attention.push(Item::Held {
                    op: op.id.clone(),
                    kind: op.kind.clone(),
                });
            } else if op.is_unresolved() {
                attention.push(Item::Unresolved {
                    op: op.id.clone(),
                    kind: op.kind.clone(),
                });
            } else if op.is_active() {
                working.push(Item::Working {
                    op: op.id.clone(),
                    kind: op.kind.clone(),
                    state: op.state.clone(),
                });
            }
        }
        for d in &self.catalog.decisions {
            if !d.expired && d.expires_at.is_none_or(|t| t > self.now) {
                attention.push(Item::Decision {
                    id: d.id.clone(),
                    kind: d.kind.clone(),
                });
            }
        }
        if let Some(doctor) = &self.doctor {
            for f in &doctor.report.findings {
                let alias = (f.subject.kind == "destination" || f.subject.kind == "alias")
                    .then(|| f.subject.id.clone())
                    .flatten()
                    .map(|a| super::data::clean(&a));
                let code = super::data::clean(&f.code);
                let message = super::data::clean(&f.message);
                match f.severity {
                    FindingSeverity::Problem => attention.push(Item::Problem {
                        code,
                        alias,
                        message,
                    }),
                    FindingSeverity::Warning => warnings.push(Item::Warning {
                        code,
                        alias,
                        message,
                    }),
                    _ => {}
                }
            }
        }
        attention.extend(working);
        attention.extend(warnings);
        attention
    }

    /// Ready, Working or Needs attention.
    #[must_use]
    pub(crate) fn health(&self) -> Health {
        let items = self.overview_items();
        if items.iter().any(Item::needs_attention) {
            Health::Attention
        } else if items.iter().any(|i| matches!(i, Item::Working { .. })) {
            Health::Working
        } else if self.runtime == Runtime::Connecting || self.doctor.is_none() {
            Health::Checking
        } else {
            Health::Ready
        }
    }

    /// The destinations the search keeps, in catalog order.
    #[must_use]
    pub(crate) fn visible_destinations(&self) -> Vec<&super::data::Destination> {
        let needle = self.searches[0].text.to_lowercase();
        self.catalog
            .destinations
            .iter()
            .filter(|d| {
                needle.is_empty()
                    || [
                        Some(d.alias.as_str()),
                        d.label.as_deref(),
                        d.hostname.as_deref(),
                        Some(d.definition.as_str()),
                    ]
                    .into_iter()
                    .flatten()
                    .any(|t| t.to_lowercase().contains(&needle))
            })
            .collect()
    }

    /// The profiles the search keeps.
    #[must_use]
    pub(crate) fn visible_profiles(&self) -> Vec<&super::data::Profile> {
        let needle = self.searches[1].text.to_lowercase();
        self.catalog
            .profiles
            .iter()
            .filter(|p| {
                needle.is_empty()
                    || p.id.to_lowercase().contains(&needle)
                    || p.label
                        .as_deref()
                        .is_some_and(|l| l.to_lowercase().contains(&needle))
            })
            .collect()
    }

    /// The Activity rows: pending decisions, then open and unresolved operations.
    #[must_use]
    pub(crate) fn activity_rows(&self) -> Vec<ActivityRow> {
        self.catalog
            .decisions
            .iter()
            .map(|d| ActivityRow::Decision(d.id.clone()))
            .chain(
                self.catalog
                    .operations
                    .iter()
                    .map(|o| ActivityRow::Operation(o.id.clone())),
            )
            .collect()
    }

    fn row_count(&self, tab: Tab) -> usize {
        match tab {
            Tab::Overview => self.overview_items().len(),
            Tab::Destinations => self.visible_destinations().len(),
            Tab::Profiles => self.visible_profiles().len(),
            Tab::Activity => self.activity_rows().len(),
        }
    }

    /// The selected row of `tab`, clamped to its rows.
    #[must_use]
    pub(crate) fn selection(&self, tab: Tab) -> Option<usize> {
        let n = self.row_count(tab);
        (n > 0).then(|| self.selected[tab.index()].min(n - 1))
    }

    /// The search of a list tab.
    #[must_use]
    pub(crate) fn search(&self, tab: Tab) -> Option<&Search> {
        match tab {
            Tab::Destinations => Some(&self.searches[0]),
            Tab::Profiles => Some(&self.searches[1]),
            _ => None,
        }
    }

    fn search_mut(&mut self, tab: Tab) -> Option<&mut Search> {
        match tab {
            Tab::Destinations => Some(&mut self.searches[0]),
            Tab::Profiles => Some(&mut self.searches[1]),
            _ => None,
        }
    }

    // ---- periodic -------------------------------------------------------------------

    /// What the main loop polls while the screen is open: the listings, and the open
    /// operation's events.
    #[must_use]
    pub(crate) fn poll_commands(&self) -> Vec<Command> {
        let mut out = vec![Command::Refresh { doctor: false }];
        if let Screen::Operation(id) = &self.screen {
            out.push(Command::Operation { id: id.clone() });
        }
        out
    }

    // ---- updates --------------------------------------------------------------------

    /// Fold one worker update in; returns what it triggers.
    pub(crate) fn apply(&mut self, update: Update) -> Vec<Effect> {
        let mut effects = Vec::new();
        match update {
            Update::Runtime(r) => {
                if r == Runtime::Connected && self.runtime != Runtime::Connected {
                    effects.push(Effect::Worker(Command::Refresh { doctor: true }));
                }
                self.runtime = r;
            }
            Update::Catalog(c) => {
                self.catalog = *c;
                if let Some(id) = self.open_when_listed.clone()
                    && self.catalog.decisions.iter().any(|d| d.id == id)
                    && self.modal.is_none()
                {
                    self.open_when_listed = None;
                    self.modal = Some(Modal::Decision(DecisionPrompt {
                        id,
                        verdict: Verdict::Approve,
                        input: String::new(),
                        scroll: 0,
                    }));
                }
            }
            Update::Doctor(d) => self.doctor = Some(*d),
            Update::Operation { id, detail } => {
                if matches!(&self.screen, Screen::Operation(open) if *open == id) {
                    self.operation = Some((id, detail));
                }
            }
            Update::ProbePrepared {
                alias,
                level,
                executed,
                not_fully_readable,
            } => {
                let waiting = matches!(&self.modal, Some(Modal::Authorization(p))
                    if p.alias == alias && p.level == level && p.executed.is_none());
                if waiting {
                    if not_fully_readable {
                        // Declined before any prompt: the authorization would not name
                        // what runs. The doctor records the decline; nothing executes.
                        self.modal = Some(Modal::Probe(ProbeView {
                            alias: alias.clone(),
                            level,
                            report: None,
                            scroll: 0,
                        }));
                        self.status = Some(format!(
                            "{}: declined, config_not_fully_readable (the static pass could not read the whole configuration); nothing ran",
                            level_name(level)
                        ));
                        effects.push(Effect::Worker(Command::Probe {
                            alias,
                            level,
                            allow_config_commands: false,
                        }));
                    } else if let Some(Modal::Authorization(p)) = &mut self.modal {
                        p.executed = Some(executed);
                    }
                }
            }
            Update::ProbeDone {
                alias,
                level,
                report,
            } => {
                let open = matches!(&self.modal, Some(Modal::Probe(v)) if v.alias == alias && v.level == level);
                if open {
                    if let Some(Modal::Probe(v)) = &mut self.modal {
                        v.report = Some(report);
                    }
                } else {
                    self.status = Some(format!("{} probe for {alias} finished", level_name(level)));
                }
            }
            Update::RepairPlan {
                operation,
                repair,
                plan,
            } => {
                if let Some(Modal::Repair(p)) = &mut self.modal
                    && p.operation == operation
                    && p.repair == repair
                {
                    p.plan = Some(plan);
                }
            }
            Update::Done { what, outcome } => {
                self.status = Some(if outcome.ok {
                    format!("{what}: {}", outcome.code)
                } else {
                    format!("{what}: {}: {}", outcome.code, outcome.message)
                });
                if let Some(d) = outcome.decision_ref {
                    self.open_when_listed = Some(d);
                }
                effects.push(Effect::Worker(Command::Refresh { doctor: true }));
            }
        }
        effects
    }

    /// The connect handoff ended (`text` describes how).
    pub(crate) fn handoff_ended(&mut self, text: String) -> Vec<Effect> {
        self.status = Some(text);
        vec![Effect::Worker(Command::Refresh { doctor: false })]
    }

    // ---- keys -----------------------------------------------------------------------

    /// Handle one key.
    pub(crate) fn key(&mut self, key: Key) -> Vec<Effect> {
        if self.modal.is_some() {
            return self.modal_key(key);
        }
        if let Screen::Tab(tab) = self.screen.clone()
            && self.search(tab).is_some_and(|s| s.editing)
        {
            return self.search_key(tab, key);
        }
        match key {
            Key::CtrlC => return vec![Effect::Quit],
            Key::Char('?') => {
                self.modal = Some(Modal::Help);
                return Vec::new();
            }
            Key::Char('R') => {
                self.status = Some("refreshing".to_owned());
                return vec![Effect::Worker(Command::Refresh { doctor: true })];
            }
            Key::Char('S') => {
                return if matches!(self.runtime, Runtime::NotRunning | Runtime::Failed(_)) {
                    self.status = Some("starting the runtime".to_owned());
                    vec![Effect::Worker(Command::StartRuntime)]
                } else {
                    self.status = Some("the runtime is already connected".to_owned());
                    Vec::new()
                };
            }
            Key::Char(c @ '1'..='4') => {
                let i = usize::from(u8::try_from(c).unwrap_or(b'1') - b'1');
                self.go_tab(Tab::ALL[i.min(3)]);
                return Vec::new();
            }
            Key::Tab => {
                self.go_tab(Tab::ALL[(self.tab.index() + 1) % 4]);
                return Vec::new();
            }
            Key::BackTab => {
                self.go_tab(Tab::ALL[(self.tab.index() + 3) % 4]);
                return Vec::new();
            }
            _ => {}
        }
        match self.screen.clone() {
            Screen::Tab(tab) => self.tab_key(tab, key),
            Screen::Destination(alias) => self.destination_key(&alias, key),
            Screen::Profile(_) => self.detail_key(key),
            Screen::Operation(id) => self.operation_key(&id, key),
        }
    }

    fn go_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.screen = Screen::Tab(tab);
        self.scroll = 0;
        self.operation = None;
    }

    fn back(&mut self) {
        let tab = self.tab;
        self.go_tab(tab);
    }

    fn move_selection(&mut self, tab: Tab, key: Key) -> bool {
        let n = self.row_count(tab);
        let i = &mut self.selected[tab.index()];
        let last = n.saturating_sub(1);
        *i = (*i).min(last);
        match key {
            Key::Up => *i = i.saturating_sub(1),
            Key::Down => *i = (*i + 1).min(last),
            Key::PageUp => *i = i.saturating_sub(10),
            Key::PageDown => *i = (*i + 10).min(last),
            Key::Home => *i = 0,
            Key::End => *i = last,
            _ => return false,
        }
        true
    }

    fn scroll_key(&mut self, key: Key) -> bool {
        match key {
            Key::Up => self.scroll = self.scroll.saturating_sub(1),
            Key::Down => self.scroll = self.scroll.saturating_add(1),
            Key::PageUp => self.scroll = self.scroll.saturating_sub(10),
            Key::PageDown => self.scroll = self.scroll.saturating_add(10),
            Key::Home => self.scroll = 0,
            _ => return false,
        }
        true
    }

    fn tab_key(&mut self, tab: Tab, key: Key) -> Vec<Effect> {
        if self.move_selection(tab, key) {
            return Vec::new();
        }
        if key == Key::Char('q') {
            return vec![Effect::Quit];
        }
        if key == Key::Char('/')
            && let Some(s) = self.search_mut(tab)
        {
            s.editing = true;
            return Vec::new();
        }
        let sel = self.selection(tab);
        match tab {
            Tab::Overview => {
                let items = self.overview_items();
                let Some(item) = sel.and_then(|i| items.get(i)).cloned() else {
                    return Vec::new();
                };
                match (item, key) {
                    (Item::Held { op, .. }, Key::Char('r')) => self.repair(op, HeldRepair::Retry),
                    (Item::Held { op, .. }, Key::Char('k')) => self.repair(op, HeldRepair::Keep),
                    (
                        Item::Held { op, .. }
                        | Item::Unresolved { op, .. }
                        | Item::Working { op, .. },
                        Key::Enter,
                    ) => self.open_operation(op),
                    (Item::Decision { id, .. }, Key::Enter) => self.open_decision(id),
                    (
                        Item::Problem { alias: Some(a), .. } | Item::Warning { alias: Some(a), .. },
                        Key::Enter,
                    ) if self.catalog.destination(&a).is_some()
                        || self.doctor_alias(&a).is_some() =>
                    {
                        self.open_destination(a);
                        Vec::new()
                    }
                    _ => Vec::new(),
                }
            }
            Tab::Destinations => {
                let alias =
                    sel.and_then(|i| self.visible_destinations().get(i).map(|d| d.alias.clone()));
                let Some(alias) = alias else {
                    return Vec::new();
                };
                match key {
                    Key::Enter => {
                        self.open_destination(alias);
                        Vec::new()
                    }
                    Key::Char('c') => self.connect(alias),
                    Key::Char('p') => {
                        self.modal = Some(Modal::ProbeMenu { alias, selected: 0 });
                        Vec::new()
                    }
                    _ => Vec::new(),
                }
            }
            Tab::Profiles => {
                if key == Key::Enter
                    && let Some(id) =
                        sel.and_then(|i| self.visible_profiles().get(i).map(|p| p.id.clone()))
                {
                    self.screen = Screen::Profile(id);
                    self.scroll = 0;
                }
                Vec::new()
            }
            Tab::Activity => {
                let rows = self.activity_rows();
                match (sel.and_then(|i| rows.get(i)).cloned(), key) {
                    (Some(ActivityRow::Decision(id)), Key::Enter) => self.open_decision(id),
                    (Some(ActivityRow::Operation(id)), Key::Enter) => self.open_operation(id),
                    _ => Vec::new(),
                }
            }
        }
    }

    fn search_key(&mut self, tab: Tab, key: Key) -> Vec<Effect> {
        let i = tab.index();
        let Some(s) = self.search_mut(tab) else {
            return Vec::new();
        };
        match key {
            Key::Char(c) => {
                if s.text.chars().count() < 64 {
                    s.text.push(c);
                }
            }
            Key::Backspace => {
                s.text.pop();
            }
            Key::Enter | Key::Down | Key::Tab => s.editing = false,
            Key::Esc | Key::CtrlC => {
                s.editing = false;
                s.text.clear();
            }
            _ => {}
        }
        self.selected[i] = 0;
        // Search is immediate and in memory: no effect, ever (spec §12.1).
        Vec::new()
    }

    fn open_destination(&mut self, alias: String) {
        self.tab = Tab::Destinations;
        self.screen = Screen::Destination(alias);
        self.scroll = 0;
    }

    fn open_operation(&mut self, id: String) -> Vec<Effect> {
        self.screen = Screen::Operation(id.clone());
        self.scroll = 0;
        self.operation = None;
        vec![Effect::Worker(Command::Operation { id })]
    }

    fn open_decision(&mut self, id: String) -> Vec<Effect> {
        self.modal = Some(Modal::Decision(DecisionPrompt {
            id,
            verdict: Verdict::Approve,
            input: String::new(),
            scroll: 0,
        }));
        // The contract: fetch the exact recorded request before deciding. The modal
        // always shows the record from the latest listing.
        vec![Effect::Worker(Command::Refresh { doctor: false })]
    }

    fn repair(&mut self, operation: String, repair: HeldRepair) -> Vec<Effect> {
        self.modal = Some(Modal::Repair(RepairPrompt {
            operation: operation.clone(),
            repair,
            plan: None,
            input: String::new(),
        }));
        vec![Effect::Worker(Command::PreviewRepair { operation, repair })]
    }

    fn connect(&mut self, alias: String) -> Vec<Effect> {
        if self.runtime != Runtime::Connected {
            self.status = Some(
                "connect needs the runtime's destination list; press S to start the runtime"
                    .to_owned(),
            );
            return Vec::new();
        }
        if self.catalog.destination(&alias).is_none() {
            self.status = Some(format!(
                "{alias}: unknown destination (not a managed or observed catalog destination)"
            ));
            return Vec::new();
        }
        vec![Effect::Connect(alias)]
    }

    /// The doctor's observation of `alias`, if any.
    #[must_use]
    pub(crate) fn doctor_alias(
        &self,
        alias: &str,
    ) -> Option<&heimdall_contract::doctor::AliasObservation> {
        self.doctor
            .as_ref()?
            .report
            .aliases
            .iter()
            .find(|a| a.alias == alias)
    }

    fn destination_key(&mut self, alias: &str, key: Key) -> Vec<Effect> {
        match key {
            Key::Char('c') => self.connect(alias.to_owned()),
            Key::Char('p') => {
                self.modal = Some(Modal::ProbeMenu {
                    alias: alias.to_owned(),
                    selected: 0,
                });
                Vec::new()
            }
            _ => self.detail_key(key),
        }
    }

    fn detail_key(&mut self, key: Key) -> Vec<Effect> {
        if self.scroll_key(key) {
            return Vec::new();
        }
        if matches!(key, Key::Esc | Key::Backspace | Key::Char('q') | Key::Left) {
            self.back();
        }
        Vec::new()
    }

    fn operation_key(&mut self, id: &str, key: Key) -> Vec<Effect> {
        let op = self
            .catalog
            .operations
            .iter()
            .find(|o| o.id == id)
            .cloned()
            .or_else(|| {
                self.operation
                    .as_ref()
                    .and_then(|(_, d)| d.operation.clone())
            });
        match key {
            Key::Char('r') if op.as_ref().is_some_and(super::data::Operation::is_held) => {
                self.repair(id.to_owned(), HeldRepair::Retry)
            }
            Key::Char('k') if op.as_ref().is_some_and(super::data::Operation::is_held) => {
                self.repair(id.to_owned(), HeldRepair::Keep)
            }
            Key::Char('x') if op.as_ref().is_some_and(super::data::Operation::is_active) => {
                self.status = Some(format!("cancelling {id}"));
                vec![Effect::Worker(Command::Cancel { id: id.to_owned() })]
            }
            Key::Char('d') | Key::Enter => {
                let decision = self
                    .catalog
                    .decisions
                    .iter()
                    .find(|d| d.operation().as_deref() == Some(id))
                    .map(|d| d.id.clone());
                match decision {
                    Some(d) => self.open_decision(d),
                    None => Vec::new(),
                }
            }
            _ => self.detail_key(key),
        }
    }

    // ---- modals ---------------------------------------------------------------------

    fn modal_key(&mut self, key: Key) -> Vec<Effect> {
        let Some(modal) = self.modal.take() else {
            return Vec::new();
        };
        let (keep, effects) = match modal {
            Modal::Help => (None, Vec::new()),
            Modal::Decision(p) => self.decision_key(p, key),
            Modal::ProbeMenu { alias, selected } => Self::probe_menu_key(alias, selected, key),
            Modal::Authorization(p) => self.authorization_key(p, key),
            Modal::Repair(p) => self.repair_key(p, key),
            Modal::Probe(mut v) => match key {
                Key::Up => {
                    v.scroll = v.scroll.saturating_sub(1);
                    (Some(Modal::Probe(v)), Vec::new())
                }
                Key::Down => {
                    v.scroll = v.scroll.saturating_add(1);
                    (Some(Modal::Probe(v)), Vec::new())
                }
                Key::PageDown => {
                    v.scroll = v.scroll.saturating_add(10);
                    (Some(Modal::Probe(v)), Vec::new())
                }
                Key::PageUp => {
                    v.scroll = v.scroll.saturating_sub(10);
                    (Some(Modal::Probe(v)), Vec::new())
                }
                Key::Esc | Key::Enter | Key::Char('q') | Key::CtrlC => (None, Vec::new()),
                _ => (Some(Modal::Probe(v)), Vec::new()),
            },
        };
        if self.modal.is_none() {
            self.modal = keep;
        }
        effects
    }

    fn type_into(input: &mut String, key: Key) {
        match key {
            Key::Char(c) if input.chars().count() < MAX_TYPED => input.push(c),
            Key::Backspace => {
                input.pop();
            }
            _ => {}
        }
    }

    fn not_confirmed_reason(input: &str) -> &'static str {
        if input.trim().is_empty() {
            "default No"
        } else {
            "answered no"
        }
    }

    fn decision_key(&mut self, mut p: DecisionPrompt, key: Key) -> (Option<Modal>, Vec<Effect>) {
        match key {
            Key::Esc | Key::CtrlC => {
                self.status = Some(format!(
                    "not confirmed (cancelled): nothing was sent; {} stays pending until it expires",
                    p.id
                ));
                (None, Vec::new())
            }
            Key::Tab | Key::BackTab => {
                p.verdict = match p.verdict {
                    Verdict::Approve => Verdict::Deny,
                    Verdict::Deny => Verdict::Approve,
                };
                p.input.clear();
                (Some(Modal::Decision(p)), Vec::new())
            }
            Key::Up | Key::Down | Key::PageUp | Key::PageDown => {
                p.scroll = match key {
                    Key::Up => p.scroll.saturating_sub(1),
                    Key::Down => p.scroll.saturating_add(1),
                    Key::PageUp => p.scroll.saturating_sub(10),
                    _ => p.scroll.saturating_add(10),
                };
                (Some(Modal::Decision(p)), Vec::new())
            }
            Key::Enter => {
                if !typed_yes(&p.input) {
                    self.status = Some(format!(
                        "not confirmed ({}): nothing was sent; {} stays pending until it expires",
                        Self::not_confirmed_reason(&p.input),
                        p.id
                    ));
                    return (None, Vec::new());
                }
                if !self.catalog.decisions.iter().any(|d| d.id == p.id) {
                    self.status = Some(format!(
                        "{} is not pending in this runtime: nothing was sent",
                        p.id
                    ));
                    return (None, Vec::new());
                }
                let verb = match p.verdict {
                    Verdict::Approve => "approve",
                    Verdict::Deny => "deny",
                };
                self.status = Some(format!("sending {verb} for {}", p.id));
                (
                    None,
                    vec![Effect::Worker(Command::Decide {
                        id: p.id,
                        verdict: p.verdict,
                    })],
                )
            }
            other => {
                Self::type_into(&mut p.input, other);
                (Some(Modal::Decision(p)), Vec::new())
            }
        }
    }

    fn probe_menu_key(alias: String, selected: usize, key: Key) -> (Option<Modal>, Vec<Effect>) {
        let last = PROBE_LEVELS.len() - 1;
        match key {
            Key::Up => (
                Some(Modal::ProbeMenu {
                    alias,
                    selected: selected.saturating_sub(1),
                }),
                Vec::new(),
            ),
            Key::Down => (
                Some(Modal::ProbeMenu {
                    alias,
                    selected: (selected + 1).min(last),
                }),
                Vec::new(),
            ),
            Key::Enter => {
                let level = PROBE_LEVELS[selected.min(last)].0;
                if runs_real_tree(level) {
                    (
                        Some(Modal::Authorization(AuthPrompt {
                            alias: alias.clone(),
                            level,
                            executed: None,
                            input: String::new(),
                        })),
                        vec![Effect::Worker(Command::PrepareProbe { alias, level })],
                    )
                } else {
                    (
                        Some(Modal::Probe(ProbeView {
                            alias: alias.clone(),
                            level,
                            report: None,
                            scroll: 0,
                        })),
                        vec![Effect::Worker(Command::Probe {
                            alias,
                            level,
                            allow_config_commands: false,
                        })],
                    )
                }
            }
            Key::Esc | Key::CtrlC | Key::Char('q') => (None, Vec::new()),
            _ => (Some(Modal::ProbeMenu { alias, selected }), Vec::new()),
        }
    }

    fn authorization_key(&mut self, mut p: AuthPrompt, key: Key) -> (Option<Modal>, Vec<Effect>) {
        match key {
            Key::Esc | Key::CtrlC => {
                self.declined(&p, "cancelled");
                (None, Vec::new())
            }
            Key::Enter => {
                if p.executed.is_none() {
                    // The static pass has not answered: the text is not shown yet, so
                    // nothing can be authorized.
                    return (Some(Modal::Authorization(p)), Vec::new());
                }
                if !typed_yes(&p.input) {
                    self.declined(&p, Self::not_confirmed_reason(&p.input));
                    return (None, Vec::new());
                }
                (
                    Some(Modal::Probe(ProbeView {
                        alias: p.alias.clone(),
                        level: p.level,
                        report: None,
                        scroll: 0,
                    })),
                    vec![Effect::Worker(Command::Probe {
                        alias: p.alias,
                        level: p.level,
                        allow_config_commands: true,
                    })],
                )
            }
            other => {
                Self::type_into(&mut p.input, other);
                (Some(Modal::Authorization(p)), Vec::new())
            }
        }
    }

    fn declined(&mut self, p: &AuthPrompt, why: &str) {
        self.status = Some(format!(
            "{}: not authorized ({why}): declined, config_commands_not_authorized; nothing ran",
            level_name(p.level)
        ));
    }

    fn repair_key(&mut self, mut p: RepairPrompt, key: Key) -> (Option<Modal>, Vec<Effect>) {
        match key {
            Key::Esc | Key::CtrlC => {
                self.status = Some(format!(
                    "{} not confirmed (cancelled): nothing was sent",
                    p.repair.name()
                ));
                (None, Vec::new())
            }
            Key::Enter => {
                let digest = match &p.plan {
                    Some(Ok(plan)) => plan.digest.clone(),
                    Some(Err(_)) => return (None, Vec::new()),
                    None => return (Some(Modal::Repair(p)), Vec::new()),
                };
                if !typed_yes(&p.input) {
                    self.status = Some(format!(
                        "{} not confirmed ({}): nothing was sent",
                        p.repair.name(),
                        Self::not_confirmed_reason(&p.input)
                    ));
                    return (None, Vec::new());
                }
                self.status = Some(format!(
                    "{} submitted for {}; it is done only when no held operation remains",
                    p.repair.name(),
                    p.operation
                ));
                (
                    None,
                    vec![Effect::Worker(Command::SubmitRepair {
                        operation: p.operation,
                        repair: p.repair,
                        plan_digest: digest,
                    })],
                )
            }
            other => {
                Self::type_into(&mut p.input, other);
                (Some(Modal::Repair(p)), Vec::new())
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use crate::tui::data::{Decision, Destination, Identity, Operation, Profile};
    use heimdall_contract::doctor::{
        AliasDefinition, AliasObservation, ConfigFileObservation, ConfigFileRole, ConfigProvenance,
        DirectiveCertainty, DirectiveObservation, Finding, ProjectionObservation, ProjectionState,
    };
    use heimdall_contract::envelope::{NextAction, ResourceRef};
    use heimdall_contract::provider::{
        Certainty, EvidenceBasis, IdentitiesOnly, IdentityBacking, IdentityEntry,
        IdentityEntryKind, IdentityEntrySource, IdentitySelection, IdentitySelectionReport,
        InteractionKind, ProviderAvailability, ProviderKind, ProviderStatus,
    };

    pub(crate) fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    pub(crate) fn now() -> Timestamp {
        t("2026-11-03T09:00:30Z")
    }

    pub(crate) fn destination(alias: &str, managed: bool) -> Destination {
        Destination {
            id: format!("dst-{alias}"),
            alias: alias.to_owned(),
            definition: if managed { "managed" } else { "observed" }.to_owned(),
            label: None,
            revision: Some("2".to_owned()),
            updated_at: Some(t("2026-11-02T08:00:00Z")),
            hostname: managed.then(|| format!("{alias}.example.invalid")),
            port: managed.then(|| "22".to_owned()),
            account: managed.then(|| "fixture".to_owned()),
            identity_id: managed.then(|| "idn_alpha".to_owned()),
        }
    }

    pub(crate) fn held_operation() -> Operation {
        Operation::of(&serde_json::json!({
            "operation_id": "op_held1", "kind": "setup.apply", "state": "outcome_unknown",
            "code": "OUTCOME_UNKNOWN", "effect_status": "unknown",
            "created_at": "2026-11-03T08:59:00Z", "updated_at": "2026-11-03T08:59:10Z",
            "result": {"error": {"reason": "projection_held", "message": "held"}},
        }))
        .unwrap()
    }

    pub(crate) fn apply_decision() -> Decision {
        Decision {
            id: "dec_apply1".to_owned(),
            kind: "apply_projection".to_owned(),
            created_at: Some(t("2026-11-03T09:00:00Z")),
            expires_at: Some(t("2026-11-03T09:15:00Z")),
            expired: false,
            request: serde_json::json!({
                "operation_id": "op_apply1",
                "plan_digest": "a".repeat(64),
                "intent": "apply",
                "added_aliases": 1, "changed_aliases": 0, "removed_aliases": 0,
                "files": 2, "git": false,
                "restore": [{"item": "alias:alpha", "digest": "3f9c2d7e1b4a5c6d8e9f00112233445566778899aabbccddeeff001122334455"}],
                "diff_text": "--- ~/.ssh/config\n+# >>> heimdall managed include\n+Include ~/.config/heimdall/ssh_config\n--- ~/.config/heimdall/ssh_config\n-Host alpha\n-  HostName old.example.invalid\n+Host alpha\n+  HostName alpha.example.invalid\n",
            }),
        }
    }

    pub(crate) fn declare_decision() -> Decision {
        Decision {
            id: "dec_declare1".to_owned(),
            kind: "declare_interaction".to_owned(),
            created_at: Some(t("2026-11-03T09:00:00Z")),
            expires_at: Some(t("2026-11-03T09:15:00Z")),
            expired: false,
            request: serde_json::json!({
                "operation_id": "op_declare1",
                "identity_id": "idn_alpha",
                "fingerprint": "SHA256:fixtureAlphaKey",
                "endpoint": {"kind": "unix_socket", "locator": "/scratch/agent.sock"},
                "interaction": "none",
                "valid_until": "2026-12-03T09:00:00Z",
            }),
        }
    }

    pub(crate) fn finding(code: &str, severity: FindingSeverity, alias: Option<&str>) -> Finding {
        Finding {
            code: code.to_owned(),
            severity,
            subject: ResourceRef {
                kind: "destination".to_owned(),
                id: alias.map(str::to_owned),
            },
            level: ProbeLevel::Static,
            provenance: None,
            message: format!("{code} message"),
            next: NextAction::for_code(heimdall_contract::Code::Ok),
            reason: None,
        }
    }

    pub(crate) fn report() -> DoctorReport {
        DoctorReport {
            levels_performed: [ProbeLevel::Static].into_iter().collect(),
            levels_declined: Default::default(),
            clients: Vec::new(),
            config_files: vec![
                ConfigFileObservation {
                    path_display: "~/.ssh/config".to_owned(),
                    role: ConfigFileRole::User,
                    readable: true,
                    sha256: None,
                    bytes: None,
                },
                ConfigFileObservation {
                    path_display: "~/.config/heimdall/ssh_config".to_owned(),
                    role: ConfigFileRole::Managed,
                    readable: true,
                    sha256: None,
                    bytes: None,
                },
            ],
            aliases: vec![AliasObservation {
                alias: "alpha".to_owned(),
                definition: AliasDefinition::Managed,
                behavior: vec![
                    DirectiveObservation {
                        directive: "HostName".to_owned(),
                        values: vec!["alpha.example.invalid".to_owned()],
                        certainty: DirectiveCertainty::Determined,
                        provenance: vec![ConfigProvenance {
                            path_display: "~/.config/heimdall/ssh_config".to_owned(),
                            line: 3,
                        }],
                    },
                    DirectiveObservation {
                        directive: "User".to_owned(),
                        values: vec!["fixture".to_owned()],
                        certainty: DirectiveCertainty::Determined,
                        provenance: vec![ConfigProvenance {
                            path_display: "~/.ssh/config".to_owned(),
                            line: 9,
                        }],
                    },
                    DirectiveObservation {
                        directive: "ProxyJump".to_owned(),
                        values: vec!["jump1".to_owned(), "jump2".to_owned()],
                        certainty: DirectiveCertainty::Undetermined,
                        provenance: vec![ConfigProvenance {
                            path_display: "~/.ssh/config".to_owned(),
                            line: 14,
                        }],
                    },
                ],
                identity_selection: Some(IdentitySelectionReport {
                    selection: IdentitySelection::Exclusive,
                    entries: vec![IdentityEntry {
                        kind: IdentityEntryKind::IdentityFile,
                        source: IdentityEntrySource::Managed,
                        provenance: Some(ConfigProvenance {
                            path_display: "~/.config/heimdall/ssh_config".to_owned(),
                            line: 5,
                        }),
                        certainty: Certainty::Determined,
                        fingerprint: Some("SHA256:fixtureAlphaKey".to_owned()),
                        backing: IdentityBacking::Agent,
                        cleared: None,
                    }],
                    identities_only: IdentitiesOnly::DeterminedYes,
                }),
            }],
            providers: vec![ProviderStatus {
                provider: ProviderKind::NativeAgent,
                availability: ProviderAvailability::Unknown,
                interaction: InteractionKind::Unknown,
                observed_level: ProbeLevel::Static,
                observed_at: t("2026-11-03T09:00:20Z"),
                basis: EvidenceBasis::Inferred,
            }],
            projection: Some(ProjectionObservation {
                state: ProjectionState::Healthy,
                generation: None,
                conflict: None,
            }),
            git: None,
            findings: vec![finding(
                "identity_selection_not_exclusive",
                FindingSeverity::Warning,
                Some("beta"),
            )],
            probes: Vec::new(),
        }
    }

    /// A populated state: two destinations, a profile, an identity with a declaration,
    /// one running operation, a held setup operation and two pending decisions.
    pub(crate) fn populated() -> App {
        let mut app = App::new(now(), false);
        app.runtime = Runtime::Connected;
        app.catalog = Catalog {
            destinations: vec![destination("alpha", true), destination("beta", false)],
            profiles: vec![Profile {
                id: "dev".to_owned(),
                revision: Some("1".to_owned()),
                label: Some("Development".to_owned()),
                pairs: vec![crate::tui::data::Pair {
                    destination: "dst-alpha".to_owned(),
                    account: "fixture".to_owned(),
                }],
            }],
            identities: vec![Identity {
                id: "idn_alpha".to_owned(),
                fingerprint: "SHA256:fixtureAlphaKey".to_owned(),
                key_type: Some("ssh-ed25519".to_owned()),
                mechanism: Some("native_agent".to_owned()),
                endpoint: Some("/scratch/agent.sock".to_owned()),
                interaction: "none".to_owned(),
                basis: Some("declared".to_owned()),
                declared_at: Some(t("2026-11-01T10:00:00Z")),
                declaration_expires_at: Some(t("2026-12-01T10:00:00Z")),
                noninteractive: Some(true),
                checked_at: Some(t("2026-11-03T09:00:25Z")),
            }],
            operations: vec![
                held_operation(),
                Operation::of(&serde_json::json!({
                    "operation_id": "op_run1", "kind": "ensure", "state": "running",
                    "created_at": "2026-11-03T09:00:10Z",
                }))
                .unwrap(),
            ],
            decisions: vec![apply_decision(), declare_decision()],
            projection_generation: Some(3),
            read_at: Some(t("2026-11-03T09:00:25Z")),
        };
        app.doctor = Some(Doctor {
            report: report(),
            taken_at: t("2026-11-03T09:00:20Z"),
        });
        app
    }

    pub(crate) fn press(app: &mut App, keys: &[Key]) -> Vec<Effect> {
        keys.iter().flat_map(|k| app.key(*k)).collect()
    }

    pub(crate) fn type_text(app: &mut App, text: &str) -> Vec<Effect> {
        text.chars().flat_map(|c| app.key(Key::Char(c))).collect()
    }

    fn worker(effects: &[Effect]) -> Vec<Command> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Worker(c) => Some(c.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn health_is_ready_working_or_needs_attention() {
        let mut app = populated();
        assert_eq!(app.health(), Health::Attention);
        app.catalog.operations.retain(|o| !o.is_held());
        app.catalog.decisions.clear();
        assert_eq!(app.health(), Health::Working, "a running operation");
        app.catalog.operations.clear();
        assert_eq!(app.health(), Health::Ready, "warnings alone are not alarms");
        app.doctor.as_mut().unwrap().report.findings.push(finding(
            "marker_edited",
            FindingSeverity::Problem,
            None,
        ));
        assert_eq!(app.health(), Health::Attention, "a problem finding");
        let mut fresh = App::new(now(), false);
        assert_eq!(fresh.health(), Health::Checking);
        fresh.runtime = Runtime::NotRunning;
        fresh.doctor = Some(Doctor {
            report: DoctorReport {
                findings: Vec::new(),
                ..report()
            },
            taken_at: now(),
        });
        assert_eq!(fresh.health(), Health::Ready, "no runtime is not an alarm");
        // An expired decision is not pending work.
        let mut app = populated();
        app.catalog.operations.clear();
        app.catalog.decisions.truncate(1);
        app.catalog.decisions[0].expired = true;
        assert_eq!(app.health(), Health::Ready);
    }

    /// ADR-0007 §5.7 and m02-plan U10 ⟨r4⟩: a held setup operation is Needs attention,
    /// first, with its two repairs reachable from the overview.
    #[test]
    fn held_setup_operation_is_needs_attention_with_its_two_repairs() {
        let mut app = populated();
        let items = app.overview_items();
        assert_eq!(
            items[0],
            Item::Held {
                op: "op_held1".to_owned(),
                kind: "setup.apply".to_owned()
            }
        );
        let effects = press(&mut app, &[Key::Char('r')]);
        assert_eq!(
            worker(&effects),
            [Command::PreviewRepair {
                operation: "op_held1".to_owned(),
                repair: HeldRepair::Retry
            }]
        );
        assert!(matches!(app.modal, Some(Modal::Repair(_))));
        press(&mut app, &[Key::Esc]);
        let effects = press(&mut app, &[Key::Char('k')]);
        assert_eq!(
            worker(&effects),
            [Command::PreviewRepair {
                operation: "op_held1".to_owned(),
                repair: HeldRepair::Keep
            }]
        );
    }

    /// QR12: a held repair is submitted only after its plan is shown and a typed yes.
    #[test]
    fn held_repair_submits_only_after_plan_and_typed_yes() {
        let plan = |app: &mut App| {
            app.apply(Update::RepairPlan {
                operation: "op_held1".to_owned(),
                repair: HeldRepair::Keep,
                plan: Ok(RepairPlan {
                    digest: "d".repeat(64),
                    lines: vec!["stays in place: ~/.ssh/config".to_owned()],
                }),
            })
        };
        let mut app = populated();
        press(&mut app, &[Key::Char('k')]);
        // Enter before the plan arrives does nothing.
        type_text(&mut app, "yes");
        assert!(press(&mut app, &[Key::Enter]).is_empty());
        press(&mut app, &[Key::Esc]);
        for refusal in ["", "no", "yess", "n"] {
            press(&mut app, &[Key::Char('k')]);
            plan(&mut app);
            type_text(&mut app, refusal);
            assert!(
                worker(&press(&mut app, &[Key::Enter])).is_empty(),
                "{refusal:?}"
            );
            assert!(app.modal.is_none());
        }
        press(&mut app, &[Key::Char('k')]);
        plan(&mut app);
        type_text(&mut app, "yes");
        assert_eq!(
            worker(&press(&mut app, &[Key::Enter])),
            [Command::SubmitRepair {
                operation: "op_held1".to_owned(),
                repair: HeldRepair::Keep,
                plan_digest: "d".repeat(64)
            }]
        );
        // A refused preview never submits.
        press(&mut app, &[Key::Char('r')]);
        app.apply(Update::RepairPlan {
            operation: "op_held1".to_owned(),
            repair: HeldRepair::Retry,
            plan: Err("CONFIG_CONFLICT: stale".to_owned()),
        });
        type_text(&mut app, "yes");
        assert!(worker(&press(&mut app, &[Key::Enter])).is_empty());
    }

    /// m02-plan U10 `decision_modal_requires_typed_yes_default_no` (model level; the
    /// rendered modal is checked in `view`, and end to end in `tests/e2e/tui_m02.rs`).
    #[test]
    fn decision_modal_requires_typed_yes_default_no() {
        let mut app = populated();
        // Activity lists the decisions first.
        press(&mut app, &[Key::Char('4')]);
        let opened = press(&mut app, &[Key::Enter]);
        assert_eq!(
            worker(&opened),
            [Command::Refresh { doctor: false }],
            "opening fetches the exact recorded request"
        );
        let Some(Modal::Decision(p)) = &app.modal else {
            panic!("{:?}", app.modal)
        };
        assert_eq!(p.id, "dec_apply1");
        assert_eq!(p.verdict, Verdict::Approve);
        // Default No: Enter on nothing sends nothing.
        assert!(worker(&press(&mut app, &[Key::Enter])).is_empty());
        assert!(app.modal.is_none());
        assert!(app.status.as_deref().unwrap().contains("default No"));
        for refusal in ["n", "no", "nope", "yess", "ye", "y e s", "1", "true"] {
            press(&mut app, &[Key::Enter]);
            assert!(matches!(app.modal, Some(Modal::Decision(_))));
            type_text(&mut app, refusal);
            assert!(
                worker(&press(&mut app, &[Key::Enter])).is_empty(),
                "{refusal:?} must not decide"
            );
            assert!(app.modal.is_none());
        }
        // Escape and Ctrl-C send nothing, even after a typed yes.
        for k in [Key::Esc, Key::CtrlC] {
            press(&mut app, &[Key::Enter]);
            type_text(&mut app, "yes");
            assert!(worker(&press(&mut app, &[k])).is_empty());
            assert!(app.modal.is_none());
        }
        // A typed yes (any case, surrounding spaces) approves exactly this record.
        for yes in ["yes", "YES", " y ", "Yes"] {
            press(&mut app, &[Key::Enter]);
            type_text(&mut app, yes);
            assert_eq!(
                worker(&press(&mut app, &[Key::Enter])),
                [Command::Decide {
                    id: "dec_apply1".to_owned(),
                    verdict: Verdict::Approve
                }],
                "{yes:?}"
            );
        }
        // Tab switches to deny, which also needs the typed yes.
        press(&mut app, &[Key::Enter, Key::Tab]);
        assert!(worker(&press(&mut app, &[Key::Enter])).is_empty());
        press(&mut app, &[Key::Enter, Key::Tab]);
        type_text(&mut app, "y");
        assert_eq!(
            worker(&press(&mut app, &[Key::Enter])),
            [Command::Decide {
                id: "dec_apply1".to_owned(),
                verdict: Verdict::Deny
            }]
        );
        // A record no longer listed is never decided, even after yes.
        press(&mut app, &[Key::Enter]);
        app.catalog.decisions.clear();
        type_text(&mut app, "yes");
        assert!(worker(&press(&mut app, &[Key::Enter])).is_empty());
    }

    /// m02-plan U10 `config_commands_authorization_requires_typed_yes` (model level):
    /// every real-tree level shows the authorization and runs only after a typed yes,
    /// even when the static pass found nothing; a tree it could not fully read is
    /// declined without the prompt.
    #[test]
    fn config_commands_authorization_requires_typed_yes() {
        let prepared = |app: &mut App, level, executed: &[String]| {
            app.apply(Update::ProbePrepared {
                alias: "alpha".to_owned(),
                level,
                executed: executed.to_vec(),
                not_fully_readable: false,
            })
        };
        for (index, level) in [
            (1, ProbeLevel::Evaluate),
            (4, ProbeLevel::HostVerification),
            (5, ProbeLevel::Authentication),
        ] {
            let mut keys = vec![Key::Down; index];
            keys.push(Key::Enter);
            for executed in [Vec::new(), vec!["~/.ssh/config:7".to_owned()]] {
                let mut app = populated();
                press(&mut app, &[Key::Char('2'), Key::Char('p')]);
                let effects = press(&mut app, &keys);
                assert_eq!(
                    worker(&effects),
                    [Command::PrepareProbe {
                        alias: "alpha".to_owned(),
                        level
                    }],
                    "{level:?}: only the static pass, nothing runs yet"
                );
                // Before the static pass answers, Enter authorizes nothing.
                type_text(&mut app, "yes");
                assert!(worker(&press(&mut app, &[Key::Enter])).is_empty());
                prepared(&mut app, level, &executed);
                let Some(Modal::Authorization(p)) = &app.modal else {
                    panic!("{level:?}: {:?}", app.modal)
                };
                assert_eq!(p.executed.as_deref(), Some(executed.as_slice()));
                // Clear what was typed early; default No refuses.
                press(&mut app, &[Key::Backspace, Key::Backspace, Key::Backspace]);
                assert!(worker(&press(&mut app, &[Key::Enter])).is_empty());
                assert!(
                    app.status
                        .as_deref()
                        .unwrap()
                        .contains("config_commands_not_authorized")
                );
                // A typed "no" refuses.
                press(&mut app, &[Key::Char('p')]);
                press(&mut app, &keys);
                prepared(&mut app, level, &executed);
                type_text(&mut app, "no");
                assert!(worker(&press(&mut app, &[Key::Enter])).is_empty());
                // A typed yes authorizes exactly this level for this alias.
                press(&mut app, &[Key::Char('p')]);
                press(&mut app, &keys);
                prepared(&mut app, level, &executed);
                type_text(&mut app, "yes");
                assert_eq!(
                    worker(&press(&mut app, &[Key::Enter])),
                    [Command::Probe {
                        alias: "alpha".to_owned(),
                        level,
                        allow_config_commands: true
                    }]
                );
                assert!(matches!(app.modal, Some(Modal::Probe(_))));
            }
            // Not fully readable: declined without the prompt, never authorized.
            let mut app = populated();
            press(&mut app, &[Key::Char('2'), Key::Char('p')]);
            press(&mut app, &keys);
            let effects = app.apply(Update::ProbePrepared {
                alias: "alpha".to_owned(),
                level,
                executed: Vec::new(),
                not_fully_readable: true,
            });
            assert_eq!(
                worker(&effects),
                [Command::Probe {
                    alias: "alpha".to_owned(),
                    level,
                    allow_config_commands: false
                }]
            );
            assert!(!matches!(app.modal, Some(Modal::Authorization(_))));
        }
        // The levels that run no configuration run on their labelled action alone.
        for (index, level) in [
            (0, ProbeLevel::Static),
            (2, ProbeLevel::Agent),
            (3, ProbeLevel::Network),
        ] {
            let mut app = populated();
            press(&mut app, &[Key::Char('2'), Key::Char('p')]);
            let mut keys = vec![Key::Down; index];
            keys.push(Key::Enter);
            assert_eq!(
                worker(&press(&mut app, &keys)),
                [Command::Probe {
                    alias: "alpha".to_owned(),
                    level,
                    allow_config_commands: false
                }]
            );
        }
    }

    /// m02-plan U10 `search_never_probes` (model level; end to end with a counting
    /// agent and listener in `tests/e2e/tui_m02.rs`): search is immediate and in
    /// memory, so no key typed into it produces any effect.
    #[test]
    fn search_is_immediate_and_produces_no_effect() {
        let mut app = populated();
        let mut effects = press(&mut app, &[Key::Char('2'), Key::Char('/')]);
        effects.extend(type_text(&mut app, "bet"));
        assert_eq!(app.visible_destinations().len(), 1);
        assert_eq!(app.visible_destinations()[0].alias, "beta");
        effects.extend(press(
            &mut app,
            &[Key::Backspace, Key::Backspace, Key::Backspace],
        ));
        assert_eq!(app.visible_destinations().len(), 2);
        effects.extend(type_text(&mut app, "ALPHA.example"));
        assert_eq!(app.visible_destinations().len(), 1, "host names match too");
        // Keys that are actions elsewhere are text here.
        effects.extend(type_text(&mut app, "cpqRS?1"));
        effects.extend(press(&mut app, &[Key::Esc]));
        assert!(app.searches[0].text.is_empty());
        assert!(effects.is_empty(), "{effects:?}");
        // Leaving the search with Enter keeps the filter; profiles search the same way.
        press(&mut app, &[Key::Char('/')]);
        type_text(&mut app, "zzz");
        press(&mut app, &[Key::Enter]);
        assert!(app.visible_destinations().is_empty());
        press(&mut app, &[Key::Char('3'), Key::Char('/')]);
        assert!(type_text(&mut app, "devel").is_empty());
        assert_eq!(app.visible_profiles().len(), 1);
    }

    /// m02-plan U10 "keyboard-only navigation of every M02 action": each action is
    /// reached from the start screen by keys alone.
    #[test]
    fn keyboard_only_navigation_reaches_every_m02_action() {
        // Tabs: number keys, Tab and Shift-Tab.
        let mut app = populated();
        for (k, tab) in [
            (Key::Char('2'), Tab::Destinations),
            (Key::Char('3'), Tab::Profiles),
            (Key::Char('4'), Tab::Activity),
            (Key::Char('1'), Tab::Overview),
            (Key::Tab, Tab::Destinations),
            (Key::BackTab, Tab::Overview),
        ] {
            press(&mut app, &[k]);
            assert_eq!(app.screen, Screen::Tab(tab));
        }
        // Help, refresh, quit.
        press(&mut app, &[Key::Char('?')]);
        assert_eq!(app.modal, Some(Modal::Help));
        press(&mut app, &[Key::Esc]);
        assert_eq!(
            worker(&press(&mut app, &[Key::Char('R')])),
            [Command::Refresh { doctor: true }]
        );
        assert_eq!(press(&mut app, &[Key::Char('q')]), [Effect::Quit]);
        assert_eq!(press(&mut app, &[Key::CtrlC]), [Effect::Quit]);
        // Destination detail, scroll, back; connect from the list and from the detail.
        press(&mut app, &[Key::Char('2'), Key::Enter]);
        assert_eq!(app.screen, Screen::Destination("alpha".to_owned()));
        press(&mut app, &[Key::Down, Key::Down]);
        assert_eq!(app.scroll, 2);
        assert_eq!(
            press(&mut app, &[Key::Char('c')]),
            [Effect::Connect("alpha".to_owned())]
        );
        press(&mut app, &[Key::Esc]);
        assert_eq!(app.screen, Screen::Tab(Tab::Destinations));
        assert_eq!(
            press(&mut app, &[Key::Down, Key::Char('c')]),
            [Effect::Connect("beta".to_owned())]
        );
        // Probes: the labelled menu from the list and from the detail (each level's
        // path is in `config_commands_authorization_requires_typed_yes`).
        press(&mut app, &[Key::Char('p')]);
        assert!(matches!(app.modal, Some(Modal::ProbeMenu { .. })));
        press(&mut app, &[Key::Esc, Key::Enter, Key::Char('p')]);
        assert!(matches!(&app.modal, Some(Modal::ProbeMenu { alias, .. }) if alias == "beta"));
        press(&mut app, &[Key::Esc, Key::Esc]);
        // Profile detail.
        press(&mut app, &[Key::Char('3'), Key::Enter]);
        assert_eq!(app.screen, Screen::Profile("dev".to_owned()));
        press(&mut app, &[Key::Char('q')]);
        assert_eq!(app.screen, Screen::Tab(Tab::Profiles));
        // Activity: decisions, then the operations; operation detail and its actions.
        press(&mut app, &[Key::Char('4'), Key::Down, Key::Down]);
        let effects = press(&mut app, &[Key::Enter]);
        assert_eq!(app.screen, Screen::Operation("op_held1".to_owned()));
        assert_eq!(
            worker(&effects),
            [Command::Operation {
                id: "op_held1".to_owned()
            }]
        );
        assert!(matches!(
            worker(&press(&mut app, &[Key::Char('r')]))[..],
            [Command::PreviewRepair {
                repair: HeldRepair::Retry,
                ..
            }]
        ));
        press(&mut app, &[Key::Esc]);
        assert!(matches!(
            worker(&press(&mut app, &[Key::Char('k')]))[..],
            [Command::PreviewRepair {
                repair: HeldRepair::Keep,
                ..
            }]
        ));
        press(&mut app, &[Key::Esc, Key::Esc]);
        press(&mut app, &[Key::Char('4'), Key::End, Key::Enter]);
        assert_eq!(app.screen, Screen::Operation("op_run1".to_owned()));
        assert_eq!(
            worker(&press(&mut app, &[Key::Char('x')])),
            [Command::Cancel {
                id: "op_run1".to_owned()
            }]
        );
        // The overview opens a held operation, a decision.
        press(&mut app, &[Key::Char('1'), Key::Home, Key::Enter]);
        assert_eq!(app.screen, Screen::Operation("op_held1".to_owned()));
        press(&mut app, &[Key::Char('1'), Key::Down, Key::Enter]);
        assert!(matches!(app.modal, Some(Modal::Decision(_))));
        press(&mut app, &[Key::Esc]);
        // An operation waiting on a decision opens it with Enter.
        app.catalog.decisions[0].request["operation_id"] = serde_json::json!("op_run1");
        press(
            &mut app,
            &[Key::Char('4'), Key::End, Key::Enter, Key::Enter],
        );
        assert!(matches!(&app.modal, Some(Modal::Decision(p)) if p.id == "dec_apply1"));
        press(&mut app, &[Key::Esc]);
        // Start the runtime when none runs.
        app.runtime = Runtime::NotRunning;
        assert_eq!(
            worker(&press(&mut app, &[Key::Char('S')])),
            [Command::StartRuntime]
        );
        // Without a runtime, connect explains and does nothing.
        assert!(press(&mut app, &[Key::Char('2'), Key::Char('c')]).is_empty());
        assert!(app.status.as_deref().unwrap().contains("start the runtime"));
    }

    #[test]
    fn connect_refuses_an_alias_the_catalog_does_not_list() {
        let mut app = populated();
        assert_eq!(
            app.connect("alpha".to_owned()),
            [Effect::Connect("alpha".to_owned())]
        );
        assert!(app.connect("gamma".to_owned()).is_empty());
        assert!(
            app.status
                .as_deref()
                .unwrap()
                .contains("unknown destination")
        );
    }

    #[test]
    fn a_decision_the_runtime_just_issued_opens_once_listed() {
        let mut app = populated();
        let decisions = std::mem::take(&mut app.catalog.decisions);
        let effects = app.apply(Update::Done {
            what: "keep_held".to_owned(),
            outcome: Outcome {
                ok: false,
                code: "APPROVAL_REQUIRED".to_owned(),
                message: "decide".to_owned(),
                decision_ref: Some("dec_apply1".to_owned()),
            },
        });
        assert_eq!(worker(&effects), [Command::Refresh { doctor: true }]);
        assert!(app.modal.is_none());
        let mut c = app.catalog.clone();
        c.decisions = decisions;
        app.apply(Update::Catalog(Box::new(c)));
        assert!(matches!(&app.modal, Some(Modal::Decision(p)) if p.id == "dec_apply1"));
    }
}
