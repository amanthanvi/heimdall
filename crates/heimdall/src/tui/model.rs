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
//! * **A typed yes is accepted only once the last row of what it confirms has been on
//!   screen** (ADR-0007 §12.31 item 3). The content of a decision, an authorization and
//!   a repair is never truncated; it wraps and scrolls (arrows, PgUp/PgDn, Home/End)
//!   above the fixed prompt. The view reports each frame to the modal's [`Reading`], and
//!   a `yes` before a frame drew the last row is refused: discarded, the modal stays
//!   open and says so. Keys queued behind each other show nothing, so they cannot
//!   outrun the screen.
//! * A probe level that runs the real configuration tree (`evaluate`,
//!   `host_verification`, `authentication`) first shows the authorization text, "runs
//!   your configuration's commands with whatever effects they have", with the file:line
//!   list the static pass found (or "none found now; the configuration can change
//!   before ssh reads it"), and runs only after a typed `yes`, even when the list is
//!   empty (ADR-0007 §6, M2-R06). A tree the static pass could not fully read is
//!   declined without the prompt (`config_not_fully_readable`).
//! * ⟨M07⟩ **A Settings change is sent only when the owner saw it** (M07-W0-R01): its
//!   confirmation is behind the same guard, stricter. Every row of it (the action, its
//!   effect, its target) must have been drawn, the latest frame must have shown its
//!   prompt, and a terminal too small for it confirms nothing
//!   (`m07::SettingPrompt::unseen`). **So is a pause, a stop or a cutoff of the stop
//!   menu** (`m05::StopMenu::unseen`): they only narrow, but they are persistent changes.
//!   Both share one drawn-frame marker ([`Seen`]): the draw path counts its frames
//!   ([`App::begin_frame`]), and only what the latest one drew stands.
//! * ⟨M07⟩ **Two keys that act with no confirmation act only on what the latest frame
//!   drew** (m07-plan U1c): `x`, which cancels the operation whose detail is open, and
//!   Enter on a probe level that contacts something with no typed authorization before
//!   it ([`contacts_unasked`]: `agent` and `network`). Each has a marker of the same kind
//!   ([`Sight`]). A key sequence typed ahead of the screen (`4 Enter x`) sends nothing,
//!   and the status line says why.
//! * ⟨M07⟩ **A stale decision resets only its own confirmation** (M07-W0-R07), and one
//!   the TUI's own request created is asked for again with that same request
//!   ([`Origin`]); its fresh version needs a fresh confirmation.
//! * A held setup operation (ADR-0007 §5.7) is **Needs attention** with its two repairs,
//!   `retry_held` and `keep_held`. Each is previewed first, its plan shown, and it is
//!   submitted only after a typed `yes` (QR12: a client-side confirmation, no decision
//!   record). A repair counts as done only when the refreshed listing shows no held
//!   operation (ADR-0007 §12.19 item 7).

use std::cell::{Cell, OnceCell};
use std::collections::{HashMap, HashSet};

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
    /// ⟨M07⟩ The working directory's project (workspace) and the standing policies (the
    /// screens `w` and `h` open).
    Projects,
    /// ⟨M07⟩ Every environment the runtime knows (`inspect environments`).
    Environments,
    /// ⟨M07⟩ Adopted identities (`inspect identities`).
    Identities,
    /// ⟨M07⟩ Default profile, pause and cutoff, lock behaviour, connection policy.
    Settings,
}

impl Tab {
    /// Every tab, in key order (`1`–`8`). ⟨M07⟩ The M02 views keep their keys (`4` is
    /// still Activity); the new views follow.
    pub(crate) const ALL: [Tab; 8] = [
        Tab::Overview,
        Tab::Destinations,
        Tab::Profiles,
        Tab::Activity,
        Tab::Projects,
        Tab::Environments,
        Tab::Identities,
        Tab::Settings,
    ];

    /// Its title.
    #[must_use]
    pub(crate) fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Destinations => "Destinations",
            Tab::Profiles => "Profiles",
            Tab::Activity => "Activity",
            Tab::Projects => "Projects",
            Tab::Environments => "Environments",
            Tab::Identities => "Identities",
            Tab::Settings => "Settings",
        }
    }

    /// Its position in [`Tab::ALL`] (its key is this plus one).
    #[must_use]
    pub(crate) fn index(self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Destinations => 1,
            Tab::Profiles => 2,
            Tab::Activity => 3,
            Tab::Projects => 4,
            Tab::Environments => 5,
            Tab::Identities => 6,
            Tab::Settings => 7,
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
    /// ⟨M03⟩ One enrollment record's detail, by ID.
    Enrollment(String),
    /// ⟨M05⟩ The working directory's workspace status (`w`).
    Workspace,
    /// ⟨M05⟩ Every policy with each revision's cause and decision (`h`).
    Policies,
    /// ⟨M07⟩ One environment's detail, by ID.
    Environment(String),
    /// ⟨M07⟩ One identity's detail, by ID.
    Identity(String),
    /// ⟨M07⟩ The desktop-lock detail: the saved setting, what is observed, and the
    /// runtime's own statement (M07-W0-R04; Enter on the Settings lock row).
    Lock,
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

/// ⟨M07⟩ M07-W0-R07: a request the TUI itself sent that can be answered with a decision
/// (a Settings change, a stop-menu action, a held repair's submission), exactly as it was
/// sent. It is kept while that decision is pending, so that when the decision turns out
/// stale the same request (with its request ID, where it has one) is sent again, as the
/// CLI does (`cli::retry_stale_decision`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Origin {
    /// What it is, for the status line.
    pub what: String,
    /// The request as sent.
    pub request: Box<heimdall_contract::request::Request>,
    /// Whether `Attend` goes first (as it did when it was first sent).
    pub attends: bool,
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
    /// ⟨M05⟩ A narrowing action of the stop menu, sent as the CLI sends it
    /// ([`super::m05::StopAction::request`]).
    Stop(super::m05::StopAction),
    /// ⟨M07⟩ A Settings change, sent as the CLI sends it
    /// ([`super::m07::SettingAction::request`]); a widening attends first.
    Setting(super::m07::SettingAction),
    /// Attend, then submit a previewed repair by its plan digest.
    SubmitRepair {
        /// The held operation.
        operation: String,
        /// The repair.
        repair: HeldRepair,
        /// The digest of the plan the owner saw.
        plan_digest: String,
    },
    /// ⟨M07⟩ M07-W0-R07: send the TUI's own request again, unchanged, because the
    /// decision it was answered with (`replaces`) turned out stale.
    Resend {
        /// The request.
        origin: Origin,
        /// The stale decision.
        replaces: String,
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
    /// ⟨M03⟩ The chores the store reader finds pending while the runtime is not
    /// connected (F14), one line each.
    OfflineChores(Vec<String>),
    /// A request finished (`what` names it).
    Done {
        /// What was sent.
        what: String,
        /// Its result.
        outcome: Outcome,
    },
    /// ⟨M07⟩ M07-W0-R07: one of the TUI's own requests that can create a decision
    /// finished. As [`Update::Done`], and the request is remembered under the decision
    /// the runtime answered it with.
    Sent {
        /// The request as sent.
        origin: Origin,
        /// Its result.
        outcome: Outcome,
        /// The stale decision this was sent again for, on a retry.
        replaces: Option<String>,
    },
    /// ⟨M07⟩ M07-W0-R07: the `Decide` of decision `id` finished.
    Decided {
        /// The decision.
        id: String,
        /// Its result.
        outcome: Outcome,
    },
}

/// ⟨M07⟩ The code of a decision whose record changed after it was shown (U2).
pub(crate) const DECISION_STALE: &str = "DECISION_STALE";

/// The authorization text of a real-tree level (ADR-0007 §6).
pub(crate) const AUTHORIZATION_TEXT: &str =
    "runs your configuration's commands with whatever effects they have";

/// What the authorization shows when the static pass found no executing construct.
pub(crate) const NONE_FOUND_TEXT: &str =
    "none found now; the configuration can change before ssh reads it";

/// The longest typed confirmation kept.
pub(crate) const MAX_TYPED: usize = 16;

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

/// What a frame showed of a confirmation's content (written by the view).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Drawn {
    /// Fingerprint of the content drawn (what the owner is asked to confirm).
    pub content: u64,
    /// Rows the content takes at the width drawn.
    pub total: usize,
    /// Rows of content the frame had room for.
    pub viewport: usize,
}

/// How far the owner has read a confirmation's content (ADR-0007 §12.31 item 3).
///
/// The content of a decision, an authorization or a repair is never truncated: it is
/// wrapped to the modal's width and scrolled while the prompt stays fixed. The view
/// records here what each frame **actually drew** ([`Reading::record`]); the model
/// accepts a typed `yes` only when a frame has drawn the content's last row
/// ([`Reading::end_shown`]). Keys that were queued behind each other and never reached
/// a frame therefore show nothing, and a typed yes cannot outrun the screen.
///
/// The "last row drawn" fact is bound to a fingerprint of the content, so a content that
/// changes while the modal is open (a replaced record, a plan that arrives) must have
/// its own end drawn again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Reading {
    /// The first content row requested on screen (the view clamps it to the content).
    pub scroll: usize,
    /// The last `yes` was refused because the end had not been shown (until the next
    /// key).
    pub refused: bool,
    /// The geometry of the last frame.
    drawn: Cell<Option<Drawn>>,
    /// The fingerprint of the content whose last row a frame has drawn.
    end_seen: Cell<Option<u64>>,
    /// ⟨M07⟩ How much of the content the frames so far have drawn, as `(content, total,
    /// rows)`: rows `0..rows` of the content laid out in `total` rows have each been on
    /// screen, counted from the first row without a gap ([`Reading::all_shown`]).
    covered: Cell<Option<(u64, usize, usize)>>,
}

impl Reading {
    /// The view's report of one frame: `content` drawn as rows `scroll..scroll +
    /// viewport` of `total`.
    pub(crate) fn record(&self, content: u64, total: usize, viewport: usize, scroll: usize) {
        self.drawn.set(Some(Drawn {
            content,
            total,
            viewport,
        }));
        if viewport > 0 && scroll.saturating_add(viewport) >= total {
            self.end_seen.set(Some(content));
        }
        // ⟨M07⟩ Rows count as read only from the top down: a frame that starts below the
        // rows read so far (a jump to the end) adds nothing.
        let read = match self.covered.get() {
            Some((c, t, rows)) if c == content && t == total => rows,
            _ => 0,
        };
        let read = if viewport > 0 && scroll <= read {
            read.max(scroll.saturating_add(viewport).min(total))
        } else {
            read
        };
        self.covered.set(Some((content, total, read)));
    }

    /// ⟨M07⟩ Whether **every** row of the content last drawn has been on screen in some
    /// frame, read from its first row down without a gap (M07-W0-R01). Stricter than
    /// [`Reading::end_shown`]: a jump to the end before the first frame shows the last row
    /// and nothing of what comes before it. The Settings confirmation asks for this, so
    /// its action and its target have been drawn before a typed `yes` counts.
    #[must_use]
    pub(crate) fn all_shown(&self) -> bool {
        match (self.covered.get(), self.drawn.get()) {
            (Some((content, total, rows)), Some(d)) => {
                content == d.content && total == d.total && rows >= total
            }
            _ => false,
        }
    }

    /// The geometry of the last frame, if one was drawn.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn drawn(&self) -> Option<Drawn> {
        self.drawn.get()
    }

    /// Whether a frame has drawn the last row of the content last drawn.
    #[must_use]
    pub(crate) fn end_shown(&self) -> bool {
        match (self.end_seen.get(), self.drawn.get()) {
            (Some(seen), Some(drawn)) => seen == drawn.content,
            _ => false,
        }
    }

    /// Whether the last frame could not show the whole content at once.
    #[must_use]
    pub(crate) fn scrollable(&self) -> bool {
        self.drawn.get().is_some_and(|d| d.total > d.viewport)
    }

    /// Scroll for `key` (Up/Down one row, PgUp/PgDn a page less one row so no row is
    /// skipped, Home/End the ends); `false` if `key` is not a scroll key.
    pub(crate) fn scroll_key(&mut self, key: Key) -> bool {
        let drawn = self.drawn.get();
        let last = drawn.map(|d| d.total.saturating_sub(d.viewport));
        let page = drawn.map_or(1, |d| d.viewport.saturating_sub(1).max(1));
        let clamp = |row: usize| last.map_or(row, |m| row.min(m));
        let at = clamp(self.scroll);
        self.scroll = match key {
            Key::Up => at.saturating_sub(1),
            Key::Down => clamp(at.saturating_add(1)),
            Key::PageUp => at.saturating_sub(page),
            Key::PageDown => clamp(at.saturating_add(page)),
            Key::Home => 0,
            Key::End => last.unwrap_or(usize::MAX),
            _ => return false,
        };
        self.refused = false;
        true
    }
}

/// ⟨M07⟩ What one frame showed of a confirmation drawn outside the decision modal's
/// dispatch (written by the view; M07-W0-R01).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Shown {
    /// The frame drew nothing of it (no frame yet, a frame with no room for any view, or
    /// a modal drawn over it).
    #[default]
    Nothing,
    /// The frame had no room for its prompt and one row of its content.
    TooSmall,
    /// The frame drew its prompt and a window of its content (which rows: the
    /// [`Reading`]).
    Drawn,
}

/// ⟨M07⟩ Why a typed yes is refused when the last frame drew nothing of the confirmation:
/// it says the screen changed and asks for the answer again (ruled 2026-11-22).
pub(crate) const REFUSED_NOT_DRAWN: &str = "screen changed: not sent; answer again";
/// ⟨M07⟩ Why a typed yes is refused on a terminal too small for the confirmation.
pub(crate) const REFUSED_TOO_SMALL: &str = "too small to show the change: not sent";
/// ⟨M07⟩ Why a typed yes is refused before every row has been drawn.
pub(crate) const REFUSED_UNREAD: &str = "read it all first (PgUp/PgDn): not sent";

/// ⟨M07⟩ The drawn-frame marker of a typed confirmation that sends a persistent change
/// without a decision of the runtime behind it: a Settings change and the stop menu's
/// pause, stop and cutoff (M07-W0-R01 and its ruling for the stop menu).
///
/// The draw path counts its frames ([`App::begin_frame`]). The view reports here what a
/// frame showed of the confirmation, with that frame's number ([`Seen::report`]), and
/// which content rows it drew ([`Reading::record`]). A typed `yes` counts only when
/// ([`Seen::unseen`]):
/// * the **latest** frame reported the confirmation drawn: its prompt and a window of its
///   content. A frame that drew something else instead (no frame at all yet, a terminal
///   too small for any view, a modal over it) reports nothing, and its number is not the
///   one stored here, so what an earlier frame showed never carries over;
/// * the frames so far have drawn **every** row of the content, from the first one down
///   ([`Reading::all_shown`]): the action, its target and its exact effect.
///
/// Keys handled before any frame (a batch) therefore confirm nothing, and neither does a
/// terminal too small to show the confirmation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Seen {
    /// Which rows of the content the frames have drawn (a fresh one for every
    /// confirmation).
    pub reading: Reading,
    /// What a frame showed of the confirmation, and that frame's number (0: none).
    last: Cell<(u64, Shown)>,
    /// Why the last typed yes was refused (shown while [`Reading::refused`] is set).
    why: Option<&'static str>,
}

impl Seen {
    /// The view's report of frame `frame`.
    pub(crate) fn report(&self, frame: u64, shown: Shown) {
        self.last.set((frame, shown));
    }

    /// What frame `frame` showed of the confirmation: nothing, unless that very frame
    /// reported otherwise.
    #[must_use]
    pub(crate) fn shown(&self, frame: u64) -> Shown {
        match self.last.get() {
            (at, shown) if at == frame && frame != 0 => shown,
            _ => Shown::Nothing,
        }
    }

    /// Why a typed yes cannot be accepted now, if it cannot; `frame` is the number of
    /// the latest frame ([`App::frame`]).
    #[must_use]
    pub(crate) fn unseen(&self, frame: u64) -> Option<&'static str> {
        match self.shown(frame) {
            Shown::Nothing => Some(REFUSED_NOT_DRAWN),
            Shown::TooSmall => Some(REFUSED_TOO_SMALL),
            Shown::Drawn if !self.reading.all_shown() => Some(REFUSED_UNREAD),
            Shown::Drawn => None,
        }
    }

    /// Refuse a typed yes for `why` ([`Seen::unseen`]): the answer is discarded (the
    /// owner types it again after reading) and the refusal is remembered for the next
    /// frame. Returns `why`.
    pub(crate) fn refuse(&mut self, why: &'static str, input: &mut String) -> &'static str {
        input.clear();
        self.reading.refused = true;
        self.why = Some(why);
        why
    }

    /// Why the last typed yes was refused, until the next key that types or scrolls.
    #[must_use]
    pub(crate) fn refusal(&self) -> Option<&'static str> {
        self.why.filter(|_| self.reading.refused)
    }
}

/// ⟨M07⟩ Why Enter on the probe menu ran nothing: the latest frame did not draw that
/// level of the menu for that alias.
pub(crate) const REFUSED_PROBE_NOT_DRAWN: &str = "screen changed: no probe; press again";
/// ⟨M07⟩ Why Enter on the probe menu ran nothing on a terminal too small for the menu's
/// alias and that level.
pub(crate) const REFUSED_PROBE_TOO_SMALL: &str = "too small to show the probe: not run";

/// ⟨M07⟩ Whether the level contacts something outside Heimdall (an agent endpoint, the
/// host) on the probe menu's Enter alone, with no typed authorization before it. `static`
/// only reads files again, and the real-tree levels ([`runs_real_tree`]) ask first.
#[must_use]
pub(crate) fn contacts_unasked(level: ProbeLevel) -> bool {
    matches!(level, ProbeLevel::Agent | ProbeLevel::Network)
}

/// The bit of `PROBE_LEVELS[index]` in a [`Sight`]'s level set.
fn level_bit(index: usize) -> u8 {
    u32::try_from(index)
        .ok()
        .and_then(|i| 1u8.checked_shl(i))
        .unwrap_or(0)
}

/// ⟨M07⟩ The drawn-frame marker of an action that one key sends with no typed
/// confirmation before it (m07-plan U1c): an operation's cancel (`x`), and Enter on a
/// probe level that contacts something ([`contacts_unasked`]).
///
/// Neither has a confirmation to read, so the guard is on the key: it acts only on a
/// target the latest frame drew. The marker is named after its target (the operation's
/// ID, the probe menu's alias). The model starts a fresh one where the target is opened
/// ([`Sight::of`]), the view reports to it only while it draws that very target
/// ([`Sight::seen_of`], [`Sight::report_levels`]), and the key is refused when the names
/// differ or the latest frame reported nothing. Keys handled before a frame (a batch such
/// as `4 Enter x`) therefore send nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Sight {
    /// What the marker is of: an operation's ID, or the probe menu's alias.
    target: String,
    /// What the frames drew of it ([`Seen`]): for an operation, also which rows of its
    /// head (its ID, kind and state, and what `x` does).
    seen: Seen,
    /// The probe menu only: the levels whose rows the frame last reported drew in full
    /// ([`level_bit`]).
    levels: Cell<u8>,
}

impl Sight {
    /// A fresh marker of `target`: nothing of it has been drawn.
    fn of(target: &str) -> Self {
        Self {
            target: target.to_owned(),
            ..Self::default()
        }
    }

    /// The marker's [`Seen`], if it is the marker of `target`.
    #[must_use]
    pub(crate) fn seen_of(&self, target: &str) -> Option<&Seen> {
        (self.target == target).then_some(&self.seen)
    }

    /// The view's report of frame `frame` of the probe menu for `alias`: what it showed,
    /// and the levels (by index into [`PROBE_LEVELS`]) whose rows it drew in full under
    /// the alias. A menu for another alias than the marker's reports nothing.
    pub(crate) fn report_levels(
        &self,
        alias: &str,
        frame: u64,
        shown: Shown,
        levels: impl IntoIterator<Item = usize>,
    ) {
        if let Some(seen) = self.seen_of(alias) {
            self.levels
                .set(levels.into_iter().fold(0, |bits, i| bits | level_bit(i)));
            seen.report(frame, shown);
        }
    }

    /// Why `x` cannot cancel operation `id` now, if it cannot: the latest frame (`frame`,
    /// [`App::frame`]) must have drawn that operation's detail, and the frames of this
    /// visit every row of its head ([`Seen::unseen`]).
    #[must_use]
    fn cancel_unseen(&self, id: &str, frame: u64) -> Option<&'static str> {
        match self.seen_of(id) {
            Some(seen) => seen.unseen(frame),
            None => Some(REFUSED_NOT_DRAWN),
        }
    }

    /// Why Enter cannot run `PROBE_LEVELS[index]` for `alias` now, if it cannot: the
    /// latest frame must have drawn the menu with that alias and that level's row in
    /// full.
    #[must_use]
    fn level_unseen(&self, alias: &str, index: usize, frame: u64) -> Option<&'static str> {
        match self.seen_of(alias).map(|s| s.shown(frame)) {
            Some(Shown::TooSmall) => Some(REFUSED_PROBE_TOO_SMALL),
            Some(Shown::Drawn) if self.levels.get() & level_bit(index) != 0 => None,
            _ => Some(REFUSED_PROBE_NOT_DRAWN),
        }
    }

    /// Refuse the key for `why`; the next frame says so until the next key.
    fn refuse(&mut self, why: &'static str) {
        self.seen.refuse(why, &mut String::new());
    }

    /// Forget a refusal (the next key was pressed).
    fn clear_refusal(&mut self) {
        self.seen.reading.refused = false;
    }

    /// Why the last key was refused, until the next key.
    #[must_use]
    pub(crate) fn refusal(&self, target: &str) -> Option<&'static str> {
        self.seen_of(target).and_then(Seen::refusal)
    }
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
    /// How far the recorded request has been read.
    pub reading: Reading,
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
    /// How far the authorization text and the list have been read.
    pub reading: Reading,
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
    /// How far the plan has been read.
    pub reading: Reading,
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
    /// ⟨M05⟩ The stop menu: pause, stop this work, stop all for a profile, cutoff.
    StopMenu(super::m05::StopMenu),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Health {
    /// Nothing waits on the owner and nothing runs.
    Ready,
    /// Work is in progress.
    Working,
    /// Something needs the owner.
    Attention,
    /// Not known yet (first read in progress).
    #[default]
    Checking,
    /// ⟨M07⟩ M07-W0-R03: it cannot be told. A listing could not be read, or the runtime
    /// connection was lost, so what is shown is stale or missing: never "Ready".
    Unknown,
}

impl Health {
    /// Its text marker (never color alone, spec §12.2).
    #[must_use]
    pub(crate) fn marker(self) -> &'static str {
        match self {
            Health::Ready => "[OK]",
            Health::Working => "[..]",
            Health::Attention => "[!!]",
            Health::Checking | Health::Unknown => "[??]",
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
            Health::Unknown => "Not known",
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
    /// ⟨M03⟩ F14: a pending chore with its one command (the time confirmation after a
    /// reboot).
    Chore {
        /// The chore's line, its command first.
        line: String,
    },
    /// ⟨M03⟩ An enrollment record that needs the owner (held, an unknown outcome, a
    /// manual step).
    Enrollment {
        /// Enrollment ID.
        id: String,
        /// State.
        state: String,
    },
    /// ⟨M03⟩ An enrollment record with the `late_write` residual.
    LateWrite {
        /// Enrollment ID.
        id: String,
    },
    /// ⟨M03⟩ F04: a managed pair whose projection is pending.
    ProjectionPending {
        /// Alias.
        alias: String,
    },
    /// ⟨M03⟩ D10 item 2: a managed alias whose slot is free (the doctor's `slot_free`).
    SlotFree {
        /// Alias.
        alias: String,
    },
    /// ⟨M07⟩ The doctor's warning or problem findings about destinations, grouped by
    /// code: one row per code and severity, with the destinations it concerns (probe
    /// P4). Enter opens the destination when there is one, else the Destinations tab.
    Findings {
        /// Severity `problem` (else `warning`).
        problem: bool,
        /// Finding code.
        code: String,
        /// The first finding's message.
        message: String,
        /// ⟨M07⟩ M07-W0-R11: its findings do not all say the same thing, so the row is
        /// worded for the group, not with the first one's message.
        mixed: bool,
        /// The destinations it concerns (aliases, in report order, each once).
        aliases: Vec<String>,
    },
    /// ⟨M07⟩ A listing whose last read failed (Q4): its view shows the error and the
    /// last good data, marked stale.
    ListingFailed {
        /// The subject's wire name.
        subject: String,
        /// The failure's code.
        code: String,
        /// Whether an earlier read succeeded (its data is shown, stale); else nothing
        /// was ever read.
        stale: bool,
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
                | Item::Findings { problem: true, .. }
                | Item::Chore { .. }
                | Item::Enrollment { .. }
        )
    }
}

/// An Activity row: which listing it is in and its index there. ⟨M07⟩ M07-W0-R06: the
/// row at a position is found by arithmetic on the three listings' lengths
/// ([`App::activity_row`]); nothing is built or searched per key or per frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityRow {
    /// A pending decision.
    Decision(usize),
    /// An operation.
    Operation(usize),
    /// ⟨M03⟩ An enrollment record.
    Enrollment(usize),
}

/// ⟨M07⟩ M07-W0-R11: the Destinations list scoped to the destinations one grouped finding
/// concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Scope {
    /// What the group says (its overview wording).
    pub label: String,
    /// The destinations it concerns.
    pub aliases: HashSet<String>,
}

/// The whole TUI state.
///
/// ⟨M07⟩ The listings, the doctor report, the runtime, the clock and the searches change
/// only through [`App::apply`] or a `*_mut`/`set_*` method, which drops exactly the
/// derived data it invalidates (the listings and the clock stay readable as fields
/// inside the `tui` module, for the shared decision-modal dispatch). The derived data (the overview items
/// and health, the per-alias finding counts, the destination-ID-to-alias map and the two
/// filtered lists) is computed at most once per change, never per key or per frame
/// (m07-plan U1, probe P2).
#[derive(Debug, Clone)]
pub(crate) struct App {
    /// The runtime connection.
    runtime: Runtime,
    /// The runtime's latest listings. Readable in the `tui` module as a field (the
    /// shared decision-modal dispatch reads `&app.catalog`, so M06's one-line addition
    /// there keeps its shape); every change goes through [`App::apply`] or
    /// [`App::catalog_mut`], never this field.
    pub(super) catalog: Catalog,
    /// The latest passive doctor report.
    doctor: Option<Doctor>,
    /// The open operation detail.
    pub operation: Option<(String, OperationDetail)>,
    /// What fills the screen.
    pub screen: Screen,
    /// The tab a sub-screen returns to.
    pub tab: Tab,
    /// Selected row per tab.
    pub selected: [usize; 8],
    /// Searches of Destinations and Profiles.
    searches: [Search; 2],
    /// Scroll offset of a detail screen.
    pub scroll: u16,
    /// The open modal.
    pub modal: Option<Modal>,
    /// The status line.
    pub status: Option<String>,
    /// The clock the screen's ages are computed from. Readable in the `tui` module as a
    /// field (the decision-modal dispatch reads `app.now`); set only by
    /// [`App::set_now`].
    pub(super) now: Timestamp,
    /// A decision the runtime just issued, opened once it is listed.
    pub open_when_listed: Option<String>,
    /// Whether the color theme is off (`NO_COLOR`).
    pub no_color: bool,
    /// ⟨M03⟩ The pending chores the store reader found while the runtime is not
    /// connected.
    offline_chores: Vec<String>,
    /// ⟨M07⟩ The open change prompt of the Settings view (drawn inside that view; keys go
    /// to it first).
    pub settings: Option<super::m07::SettingPrompt>,
    /// ⟨M07⟩ The derived overview data, computed once per change.
    derived: OnceCell<Derived>,
    /// ⟨M07⟩ The indices of the destinations the search keeps, computed once per change
    /// of the destinations or of the search text.
    destination_filter: OnceCell<Vec<usize>>,
    /// ⟨M07⟩ The same for the profiles.
    profile_filter: OnceCell<Vec<usize>>,
    /// ⟨M07⟩ Whether an update changed what the screen shows since the main loop last
    /// asked ([`App::take_changed`]).
    changed: bool,
    /// ⟨M07⟩ M07-W0-R06: the Settings rows, built once per change of the listings.
    setting_rows: OnceCell<Vec<super::m07::SettingRow>>,
    /// ⟨M07⟩ M07-W0-R11: the grouped finding the Destinations list is scoped to.
    scope: Option<Scope>,
    /// ⟨M07⟩ M07-W0-R07: the TUI's own requests whose decision is pending, by decision
    /// ID, oldest first (at most [`MAX_ORIGINS`]).
    origins: Vec<(String, Origin)>,
    /// ⟨M07⟩ How many frames the draw path has drawn ([`App::begin_frame`]): the clock
    /// the confirmations outside the decision modal are checked against ([`Seen`]).
    frames: Cell<u64>,
    /// ⟨M07⟩ U1c: what the frames drew of the open operation's detail: `x` cancels only
    /// an operation the latest frame showed (a fresh marker each time one is opened).
    operation_sight: Sight,
    /// ⟨M07⟩ U1c: what the latest frame drew of the open probe menu: Enter runs a level
    /// that contacts something only if that frame showed it (a fresh marker per menu).
    probe_sight: Sight,
}

/// ⟨M07⟩ The most TUI-sent requests remembered for a stale retry.
const MAX_ORIGINS: usize = 16;

/// ⟨M07⟩ What the overview and the lists derive from the listings and the doctor report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Derived {
    /// The overview's lines.
    pub items: Vec<Item>,
    /// Ready, Working, Needs attention or Checking.
    pub health: Health,
    /// Per alias, its (problem, warning) finding counts.
    pub findings_by_alias: HashMap<String, (usize, usize)>,
    /// Destination ID to alias.
    pub alias_by_id: HashMap<String, String>,
    /// The earliest expiry of a pending decision the overview lists: once the clock
    /// passes it, the overview changes.
    pub next_expiry: Option<Timestamp>,
}

/// ⟨M07⟩ The minute a clock reading falls in: relative times change only when it does.
fn minute(t: Timestamp) -> i64 {
    t.as_second().div_euclid(60)
}

/// The alias a finding concerns: its subject, by alias or by destination ID.
fn finding_alias_in(
    alias_by_id: &HashMap<String, String>,
    f: &heimdall_contract::doctor::Finding,
) -> Option<String> {
    if f.subject.kind != "destination" && f.subject.kind != "alias" {
        return None;
    }
    let id = f.subject.id.as_deref()?;
    Some(
        alias_by_id
            .get(id)
            .cloned()
            .unwrap_or_else(|| super::data::clean(id)),
    )
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
            selected: [0; 8],
            searches: [Search::default(), Search::default()],
            scroll: 0,
            modal: None,
            status: None,
            now,
            open_when_listed: None,
            no_color,
            offline_chores: Vec::new(),
            settings: None,
            derived: OnceCell::new(),
            destination_filter: OnceCell::new(),
            profile_filter: OnceCell::new(),
            changed: false,
            setting_rows: OnceCell::new(),
            scope: None,
            origins: Vec::new(),
            frames: Cell::new(0),
            operation_sight: Sight::default(),
            probe_sight: Sight::default(),
        }
    }

    /// ⟨M07⟩ The draw path starts a frame: called once by `view::render`, before it draws
    /// anything (also before it gives up on a terminal too small for any view). Returns
    /// the frame's number, counted from 1.
    pub(crate) fn begin_frame(&self) -> u64 {
        let n = self.frames.get().saturating_add(1);
        self.frames.set(n);
        n
    }

    /// ⟨M07⟩ The number of the latest frame (0: nothing has been drawn yet).
    #[must_use]
    pub(crate) fn frame(&self) -> u64 {
        self.frames.get()
    }

    /// ⟨M07⟩ U1c: the open operation detail's drawn-frame marker (the view reports to it).
    #[must_use]
    pub(crate) fn operation_sight(&self) -> &Sight {
        &self.operation_sight
    }

    /// ⟨M07⟩ U1c: the open probe menu's drawn-frame marker (the view reports to it).
    #[must_use]
    pub(crate) fn probe_sight(&self) -> &Sight {
        &self.probe_sight
    }

    // ---- state and invalidation (M07) -----------------------------------------------

    /// The runtime connection.
    #[must_use]
    pub(crate) fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// The runtime's latest listings.
    #[must_use]
    pub(crate) fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// The latest passive doctor report.
    #[must_use]
    pub(crate) fn doctor(&self) -> Option<&Doctor> {
        self.doctor.as_ref()
    }

    /// The clock the screen's ages are computed from.
    #[must_use]
    pub(crate) fn now(&self) -> Timestamp {
        self.now
    }

    /// The listings, to change in place: everything derived from them is dropped.
    #[cfg(test)]
    pub(crate) fn catalog_mut(&mut self) -> &mut Catalog {
        self.invalidate_all();
        &mut self.catalog
    }

    /// The doctor report, to change in place: the overview data is dropped.
    pub(crate) fn doctor_mut(&mut self) -> &mut Option<Doctor> {
        self.derived = OnceCell::new();
        &mut self.doctor
    }

    /// Set the runtime connection: the overview data is dropped.
    pub(crate) fn set_runtime(&mut self, runtime: Runtime) {
        self.derived = OnceCell::new();
        self.runtime = runtime;
    }

    /// Set the clock. Returns whether the screen is due a redraw: the displayed minute
    /// changed, or a pending decision expired (the overview is then re-derived). Any
    /// other tick changes nothing on screen (m07-plan U1, probe P1).
    pub(crate) fn set_now(&mut self, now: Timestamp) -> bool {
        let expired = self
            .derived
            .get()
            .is_some_and(|d| d.next_expiry.is_some_and(|e| now >= e));
        let due = minute(now) != minute(self.now) || expired;
        if due {
            self.derived = OnceCell::new();
        }
        self.now = now;
        due
    }

    /// Whether an update changed what the screen shows since the last call.
    pub(crate) fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    #[cfg(test)]
    fn invalidate_all(&mut self) {
        self.derived = OnceCell::new();
        self.destination_filter = OnceCell::new();
        self.profile_filter = OnceCell::new();
        self.setting_rows = OnceCell::new();
    }

    /// ⟨M07⟩ M07-W0-R03: whether what the listings say cannot be relied on: a listing's
    /// latest read failed (its data is stale or was never read), the connection failed,
    /// or the runtime stopped after listings were read (they are still shown).
    #[must_use]
    pub(crate) fn reads_unknown(&self) -> bool {
        !self.catalog.failures.is_empty()
            || matches!(self.runtime, Runtime::Failed(_))
            || (self.runtime == Runtime::NotRunning && self.catalog.read_at.is_some())
    }

    /// ⟨M07⟩ M07-W0-R11: the grouped finding the Destinations list is scoped to.
    #[must_use]
    pub(crate) fn scope(&self) -> Option<&Scope> {
        self.scope.as_ref()
    }

    fn set_scope(&mut self, scope: Option<Scope>) {
        if self.scope != scope {
            self.scope = scope;
            self.destination_filter = OnceCell::new();
            self.selected[Tab::Destinations.index()] = 0;
        }
    }

    /// The derived overview data (computed on first use after a change).
    #[must_use]
    pub(crate) fn derived(&self) -> &Derived {
        self.derived.get_or_init(|| self.derive())
    }

    fn derive(&self) -> Derived {
        let alias_by_id: HashMap<String, String> = self
            .catalog
            .destinations
            .iter()
            .filter(|d| !d.id.is_empty())
            .map(|d| (d.id.clone(), d.alias.clone()))
            .collect();
        let mut findings_by_alias: HashMap<String, (usize, usize)> = HashMap::new();
        if let Some(doctor) = &self.doctor {
            for f in &doctor.report.findings {
                let Some(alias) = finding_alias_in(&alias_by_id, f) else {
                    continue;
                };
                let entry = findings_by_alias.entry(alias).or_default();
                match f.severity {
                    FindingSeverity::Problem => entry.0 += 1,
                    FindingSeverity::Warning => entry.1 += 1,
                    _ => {}
                }
            }
        }
        let items = self.overview_items_with(&alias_by_id);
        let health = if items.iter().any(Item::needs_attention) {
            Health::Attention
        } else if self.reads_unknown() {
            // ⟨M07⟩ M07-W0-R03: never Ready (or Working) over listings that failed, were
            // never read, or are stale.
            Health::Unknown
        } else if items.iter().any(|i| matches!(i, Item::Working { .. })) {
            Health::Working
        } else if self.runtime == Runtime::Connecting || self.doctor.is_none() {
            Health::Checking
        } else {
            Health::Ready
        };
        let next_expiry = self
            .catalog
            .decisions
            .iter()
            .filter(|d| !d.expired)
            .filter_map(|d| d.expires_at)
            .filter(|t| *t > self.now)
            .min();
        Derived {
            items,
            health,
            findings_by_alias,
            alias_by_id,
            next_expiry,
        }
    }

    // ---- derived views --------------------------------------------------------------

    /// The overview's lines (cached; [`App::derived`]).
    #[must_use]
    pub(crate) fn overview_items(&self) -> &[Item] {
        &self.derived().items
    }

    /// The (problem, warning) finding counts of `alias` (cached).
    #[must_use]
    pub(crate) fn alias_findings(&self, alias: &str) -> (usize, usize) {
        self.derived()
            .findings_by_alias
            .get(alias)
            .copied()
            .unwrap_or_default()
    }

    /// The overview's lines: what needs attention first, then work in progress, then
    /// warnings. ⟨M07⟩ The doctor's per-destination findings are grouped by code, one
    /// row per code and severity with the destinations it concerns (probe P4).
    fn overview_items_with(&self, alias_by_id: &HashMap<String, String>) -> Vec<Item> {
        let mut attention = Vec::new();
        let mut working = Vec::new();
        let mut warnings = Vec::new();
        let mut info = Vec::new();
        // F14: the runtime's own view while it is connected; otherwise the store
        // reader's (worker U's `doctor_cmd::pending_chores`, read-only).
        if self.runtime == Runtime::Connected {
            if let Some(message) = &self.catalog.m03.time_uncertain {
                attention.push(Item::Chore {
                    line: super::m03::time_chore_line(message),
                });
            }
        } else {
            attention.extend(
                self.offline_chores
                    .iter()
                    .map(|line| Item::Chore { line: line.clone() }),
            );
        }
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
        for e in &self.catalog.m03.enrollments {
            if e.needs_attention() {
                attention.push(Item::Enrollment {
                    id: e.id.clone(),
                    state: e.state.clone(),
                });
            }
            if e.possible_late_write {
                warnings.push(Item::LateWrite { id: e.id.clone() });
            }
        }
        for d in &self.catalog.destinations {
            if d.preference
                .as_ref()
                .is_some_and(super::m03::Preference::projection_pending)
            {
                warnings.push(Item::ProjectionPending {
                    alias: d.alias.clone(),
                });
            }
        }
        // ⟨M07⟩ A listing whose last read failed: its error, never an empty list (Q4).
        // While the runtime is not connected every listing is stale for the one reason
        // the runtime line and the indicator give, so they are not listed one by one.
        if self.runtime == Runtime::Connected {
            for (subject, f) in &self.catalog.failures {
                warnings.push(Item::ListingFailed {
                    subject: subject.clone(),
                    code: f.code.clone(),
                    stale: f.stale_from.is_some(),
                });
            }
        }
        if let Some(doctor) = &self.doctor {
            // ⟨M07⟩ (severity is a problem, code) → its row's index in `attention` or
            // `warnings`, and the aliases already counted.
            let mut groups: HashMap<(bool, String), (usize, HashSet<String>)> = HashMap::new();
            for f in &doctor.report.findings {
                let code = super::data::clean(&f.code);
                let problem = match f.severity {
                    FindingSeverity::Problem => true,
                    FindingSeverity::Warning => false,
                    // ⟨M03⟩ D10 item 2: `slot_free` is informational and still shown,
                    // with its command; other informational findings stay off the
                    // overview.
                    _ => {
                        if code == super::m03::SLOT_FREE
                            && let Some(alias) = finding_alias_in(alias_by_id, f)
                        {
                            info.push(Item::SlotFree { alias });
                        }
                        continue;
                    }
                };
                let message = super::data::clean(&f.message);
                let list = if problem {
                    &mut attention
                } else {
                    &mut warnings
                };
                let Some(alias) = finding_alias_in(alias_by_id, f) else {
                    // Not about one destination: one row, as the doctor reports it.
                    list.push(if problem {
                        Item::Problem {
                            code,
                            alias: None,
                            message,
                        }
                    } else {
                        Item::Warning {
                            code,
                            alias: None,
                            message,
                        }
                    });
                    continue;
                };
                match groups.entry((problem, code.clone())) {
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        let (at, seen) = e.get_mut();
                        if let Some(Item::Findings {
                            aliases,
                            message: first,
                            mixed,
                            ..
                        }) = list.get_mut(*at)
                        {
                            // ⟨M07⟩ M07-W0-R11: one code, different words.
                            *mixed |= *first != message;
                            if seen.insert(alias.clone()) {
                                aliases.push(alias);
                            }
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert((list.len(), HashSet::from([alias.clone()])));
                        list.push(Item::Findings {
                            problem,
                            code,
                            message,
                            mixed: false,
                            aliases: vec![alias],
                        });
                    }
                }
            }
        }
        attention.extend(working);
        attention.extend(warnings);
        attention.extend(info);
        attention
    }

    /// Ready, Working or Needs attention (cached with the overview's items).
    #[must_use]
    pub(crate) fn health(&self) -> Health {
        self.derived().health
    }

    /// The destinations the search keeps, in catalog order (⟨M07⟩ filtered once per
    /// change of the destinations or of the search text).
    #[must_use]
    #[cfg(test)]
    pub(crate) fn visible_destinations(&self) -> Vec<&super::data::Destination> {
        self.destination_indices()
            .iter()
            .filter_map(|i| self.catalog.destinations.get(*i))
            .collect()
    }

    /// The `i`th destination the search keeps.
    #[must_use]
    pub(crate) fn visible_destination(&self, i: usize) -> Option<&super::data::Destination> {
        self.destination_indices()
            .get(i)
            .and_then(|i| self.catalog.destinations.get(*i))
    }

    /// The catalog indices of the destinations the search keeps (cached).
    fn destination_indices(&self) -> &[usize] {
        self.destination_filter.get_or_init(|| {
            let needle = self.searches[0].text.to_lowercase();
            let scope = self.scope.as_ref();
            self.catalog
                .destinations
                .iter()
                .enumerate()
                // ⟨M07⟩ M07-W0-R11: within the grouped finding's destinations, if scoped.
                .filter(|(_, d)| scope.is_none_or(|s| s.aliases.contains(&d.alias)))
                .filter(|(_, d)| {
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
                .map(|(i, _)| i)
                .collect()
        })
    }

    /// The profiles the search keeps (⟨M07⟩ filtered once per change).
    #[must_use]
    #[cfg(test)]
    pub(crate) fn visible_profiles(&self) -> Vec<&super::data::Profile> {
        self.profile_indices()
            .iter()
            .filter_map(|i| self.catalog.profiles.get(*i))
            .collect()
    }

    /// The `i`th profile the search keeps.
    #[must_use]
    pub(crate) fn visible_profile(&self, i: usize) -> Option<&super::data::Profile> {
        self.profile_indices()
            .get(i)
            .and_then(|i| self.catalog.profiles.get(*i))
    }

    /// The catalog indices of the profiles the search keeps (cached).
    fn profile_indices(&self) -> &[usize] {
        self.profile_filter.get_or_init(|| {
            let needle = self.searches[1].text.to_lowercase();
            self.catalog
                .profiles
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    needle.is_empty()
                        || p.id.to_lowercase().contains(&needle)
                        || p.label
                            .as_deref()
                            .is_some_and(|l| l.to_lowercase().contains(&needle))
                })
                .map(|(i, _)| i)
                .collect()
        })
    }

    /// The Activity row at position `i`: pending decisions, then open and unresolved
    /// operations, then enrollment records (⟨M07⟩ by arithmetic, M07-W0-R06).
    #[must_use]
    pub(crate) fn activity_row(&self, i: usize) -> Option<ActivityRow> {
        let (d, o, e) = self.activity_counts();
        if i < d {
            Some(ActivityRow::Decision(i))
        } else if i < d + o {
            Some(ActivityRow::Operation(i - d))
        } else if i < d + o + e {
            Some(ActivityRow::Enrollment(i - d - o))
        } else {
            None
        }
    }

    /// How many decisions, operations and enrollment records Activity lists.
    #[must_use]
    pub(crate) fn activity_counts(&self) -> (usize, usize, usize) {
        (
            self.catalog.decisions.len(),
            self.catalog.operations.len(),
            self.catalog.m03.enrollments.len(),
        )
    }

    /// The number of rows the view of `tab` lists (cached).
    #[must_use]
    pub(crate) fn shown(&self, tab: Tab) -> usize {
        self.row_count(tab)
    }

    fn row_count(&self, tab: Tab) -> usize {
        match tab {
            Tab::Overview => self.overview_items().len(),
            Tab::Destinations => self.destination_indices().len(),
            Tab::Profiles => self.profile_indices().len(),
            Tab::Activity => {
                let (d, o, e) = self.activity_counts();
                d + o + e
            }
            // A scrolled view, not a list.
            Tab::Projects => 0,
            Tab::Environments => self.catalog.environments.items.len(),
            Tab::Identities => self.catalog.identities.len(),
            Tab::Settings => self.setting_rows().len(),
        }
    }

    /// ⟨M07⟩ The Settings view's rows (M07-W0-R06: built on first use after the listings
    /// change, then kept; a key or a frame only reads them).
    #[must_use]
    pub(crate) fn setting_rows(&self) -> &[super::m07::SettingRow] {
        self.setting_rows
            .get_or_init(|| super::m07::settings_rows(&self.catalog))
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
        // ⟨M07⟩ Whether the screen can show something new: an update that changes no
        // state draws nothing (m07-plan U1, probe P1).
        let mut changed = true;
        match update {
            Update::Runtime(r) => {
                if r == Runtime::Connected && self.runtime != Runtime::Connected {
                    effects.push(Effect::Worker(Command::Refresh { doctor: true }));
                }
                if r == self.runtime {
                    changed = false;
                } else {
                    self.set_runtime(r);
                }
            }
            Update::Catalog(c) => {
                if self.catalog.same_listings(&c) {
                    // The same answers, read again: only the read times move, which a
                    // later frame shows; nothing derived changes and nothing is drawn.
                    let c = *c;
                    self.catalog.read_at = c.read_at;
                    self.catalog.identities = c.identities;
                    changed = false;
                } else {
                    // Only what the change touches is derived again.
                    if self.catalog.destinations != c.destinations {
                        self.destination_filter = OnceCell::new();
                    }
                    if self.catalog.profiles != c.profiles {
                        self.profile_filter = OnceCell::new();
                    }
                    self.derived = OnceCell::new();
                    self.setting_rows = OnceCell::new();
                    self.catalog = *c;
                }
                // ⟨M07⟩ Never over an open Settings prompt (it would cover a confirmation
                // being read): the decision opens once the prompt has closed.
                if let Some(id) = self.open_when_listed.clone()
                    && self.catalog.decisions.iter().any(|d| d.id == id)
                    && self.modal.is_none()
                    && self.settings.is_none()
                {
                    self.open_when_listed = None;
                    self.modal = Some(Modal::Decision(DecisionPrompt {
                        id,
                        verdict: Verdict::Approve,
                        input: String::new(),
                        reading: Reading::default(),
                    }));
                    changed = true;
                }
            }
            Update::Doctor(d) => {
                if self.doctor.as_ref() == Some(&*d) {
                    changed = false;
                } else {
                    *self.doctor_mut() = Some(*d);
                }
            }
            Update::OfflineChores(lines) => {
                if self.offline_chores == lines {
                    changed = false;
                } else {
                    self.derived = OnceCell::new();
                    self.offline_chores = lines;
                }
            }
            Update::Operation { id, detail } => {
                let open = matches!(&self.screen, Screen::Operation(open) if *open == id);
                let same = self
                    .operation
                    .as_ref()
                    .is_some_and(|(i, d)| *i == id && *d == detail);
                if open && !same {
                    self.operation = Some((id, detail));
                } else {
                    changed = false;
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
            Update::Done { what, outcome } => self.finished(&what, outcome, &mut effects),
            // ⟨M07⟩ M07-W0-R07: the TUI's own request. Its decision, if the runtime
            // answered with one, is remembered with the request that created it.
            Update::Sent {
                origin,
                outcome,
                replaces,
            } => {
                let what = origin.what.clone();
                match (&outcome.decision_ref, &replaces) {
                    // Sent again, and the runtime still names the stale record: nothing
                    // new to review (the CLI gives up the same way).
                    (Some(d), Some(stale)) if d == stale => {
                        self.remember(d.clone(), origin);
                        self.status = Some(format!(
                            "{what}: asked again, and the runtime still refers to the changed request; nothing was approved (review it from Activity)"
                        ));
                        effects.push(Effect::Worker(Command::Refresh { doctor: true }));
                    }
                    (decision, _) => {
                        if let Some(d) = decision {
                            self.remember(d.clone(), origin);
                        }
                        self.finished(&what, outcome, &mut effects);
                    }
                }
            }
            Update::Decided { id, outcome } if outcome.code == DECISION_STALE => {
                self.decision_stale(&id, &mut effects);
            }
            Update::Decided { id, outcome } => {
                // Completed (or refused for another reason): its request is not needed.
                self.origins.retain(|(d, _)| *d != id);
                self.finished(&format!("decision {id}"), outcome, &mut effects);
            }
        }
        self.changed |= changed;
        effects
    }

    /// A request finished: its result on the status line, the decision it was answered
    /// with (if any) opened once it is listed, and the listings read again.
    fn finished(&mut self, what: &str, outcome: Outcome, effects: &mut Vec<Effect>) {
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

    /// ⟨M07⟩ Remember the TUI's own request under the decision it was answered with.
    fn remember(&mut self, decision: String, origin: Origin) {
        self.origins.retain(|(d, _)| *d != decision);
        self.origins.push((decision, origin));
        if self.origins.len() > MAX_ORIGINS {
            self.origins.remove(0);
        }
    }

    /// ⟨M07⟩ U2, M07-W0-R07: decision `id` changed after the owner reviewed it, so its
    /// `Decide` approved nothing.
    ///
    /// * **Only its own modal is reset.** If the modal open now is the one for `id`, it
    ///   closes and what was typed is gone (a typed yes is never carried to another
    ///   record). Any other modal, opened in between, is left exactly as it is: not
    ///   closed, and nothing is sent for it.
    /// * **A decision the TUI's own request created is retried:** the same request is
    ///   sent again ([`Command::Resend`]), and the decision the runtime answers with
    ///   opens once it is listed, with an empty confirmation and nothing read yet.
    /// * **A decision that came from elsewhere** cannot be asked for again from here: the
    ///   decisions are read again, and its new version appears when its requester
    ///   retries. It does not open by itself.
    fn decision_stale(&mut self, id: &str, effects: &mut Vec<Effect>) {
        if matches!(&self.modal, Some(Modal::Decision(p)) if p.id == id) {
            self.modal = None;
        }
        if self.open_when_listed.as_deref() == Some(id) {
            self.open_when_listed = None;
        }
        let at = self.origins.iter().position(|(d, _)| d == id);
        match at.map(|i| self.origins.remove(i).1) {
            Some(origin) => {
                self.status = Some(format!(
                    "decision {id}: the request changed after you reviewed it, so nothing was approved; asking again ({}), its new version opens for a fresh review",
                    origin.what
                ));
                effects.push(Effect::Worker(Command::Resend {
                    origin,
                    replaces: id.to_owned(),
                }));
            }
            None => {
                self.status = Some(format!(
                    "decision {id}: the request changed after you reviewed it, so nothing was approved; its new version appears here when the requester tries again"
                ));
                effects.push(Effect::Worker(Command::Refresh { doctor: false }));
            }
        }
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
        // ⟨M07⟩ The status line shows the last result until the next key, then the footer's
        // key hints return (a key that reports something sets it again below).
        self.status = None;
        // ⟨M07⟩ An open Settings prompt takes every key (it is typed into).
        if let Some(prompt) = self.settings.take() {
            return self.setting_prompt_key(prompt, key);
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
            // ⟨M05⟩ The trusted-work views: workspace status, policy history, the stop menu.
            Key::Char('w') => return self.open_m05(Screen::Workspace),
            Key::Char('h') => return self.open_m05(Screen::Policies),
            Key::Char('s') => {
                self.modal = Some(Modal::StopMenu(super::m05::StopMenu::default()));
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
            // ⟨M07⟩ Going to a view by its key shows all of it: a grouped finding's
            // scope (M07-W0-R11) lasts for the visit its Enter started.
            Key::Char(c @ '1'..='8') => {
                let i = usize::from(u8::try_from(c).unwrap_or(b'1') - b'1');
                self.set_scope(None);
                self.go_tab(Tab::ALL[i.min(Tab::ALL.len() - 1)]);
                return Vec::new();
            }
            Key::Tab => {
                self.set_scope(None);
                self.go_tab(Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()]);
                return Vec::new();
            }
            Key::BackTab => {
                let n = Tab::ALL.len();
                self.set_scope(None);
                self.go_tab(Tab::ALL[(self.tab.index() + n - 1) % n]);
                return Vec::new();
            }
            _ => {}
        }
        match self.screen.clone() {
            Screen::Tab(tab) => self.tab_key(tab, key),
            Screen::Destination(alias) => self.destination_key(&alias, key),
            Screen::Profile(_) => self.detail_key(key),
            Screen::Operation(id) => self.operation_key(&id, key),
            Screen::Enrollment(_) => self.detail_key(key),
            Screen::Workspace => self.workspace_key(key),
            Screen::Policies | Screen::Environment(_) | Screen::Identity(_) | Screen::Lock => {
                self.detail_key(key)
            }
        }
    }

    /// ⟨M07⟩ One key in the open Settings prompt: it sends only after a typed yes to a
    /// confirmation a frame has drawn in full ([`super::m07::SettingPrompt::unseen`]).
    fn setting_prompt_key(
        &mut self,
        mut prompt: super::m07::SettingPrompt,
        key: Key,
    ) -> Vec<Effect> {
        use super::m07::SettingStep;
        match prompt.key(key, self.frame()) {
            SettingStep::Stay => {
                self.settings = Some(prompt);
                Vec::new()
            }
            SettingStep::Close(text) => {
                self.status = Some(text);
                Vec::new()
            }
            // ⟨M07⟩ M07-W0-R01: a typed yes to a change that was not on screen. The
            // prompt stays open, the answer is gone, and the status line says why.
            SettingStep::Refused(why) => {
                self.settings = Some(prompt);
                self.status = Some(why.to_owned());
                Vec::new()
            }
            SettingStep::Send(action) => {
                self.status = Some(format!(
                    "sending {}{}",
                    action.what(),
                    if action.widening() {
                        "; the runtime will ask for your decision"
                    } else {
                        ""
                    }
                ));
                vec![Effect::Worker(Command::Setting(action))]
            }
        }
    }

    /// ⟨M05⟩ Open a trusted-work view, re-reading the listings first.
    fn open_m05(&mut self, screen: Screen) -> Vec<Effect> {
        self.screen = screen;
        self.scroll = 0;
        vec![Effect::Worker(Command::Refresh { doctor: false })]
    }

    /// ⟨M05⟩ The workspace status: Enter opens the decision that waits for it, if any.
    fn workspace_key(&mut self, key: Key) -> Vec<Effect> {
        if key == Key::Enter {
            return match super::m05::pending_decision(&self.catalog, self.now) {
                Some(id) => self.open_decision(id),
                None => Vec::new(),
            };
        }
        self.detail_key(key)
    }

    /// ⟨M05⟩ One key in the stop menu: it only narrows, and sends only after a typed yes
    /// ⟨M07⟩ to a confirmation the latest frame drew and the frames have shown in full
    /// ([`Seen::unseen`]; M07-W0-R01 applied to the stop menu).
    fn stop_menu_key(
        &mut self,
        mut menu: super::m05::StopMenu,
        key: Key,
    ) -> (Option<Modal>, Vec<Effect>) {
        use super::m05::StopStep;
        let ctx = self.catalog.m05.stop_context();
        match menu.key(key, &ctx, self.frame()) {
            StopStep::Stay => (Some(Modal::StopMenu(menu)), Vec::new()),
            StopStep::Close(text) => {
                self.status = Some(text);
                (None, Vec::new())
            }
            // ⟨M07⟩ A typed yes to an action that was not on screen: the menu stays open
            // on the confirmation, the answer is gone, and the frame says why (the
            // modal's border and the footer; the status line once the menu closes).
            StopStep::Refused(why) => {
                self.status = Some(why.to_owned());
                (Some(Modal::StopMenu(menu)), Vec::new())
            }
            StopStep::Send(action) => {
                self.status = Some(format!("sending {}", action.what()));
                (None, vec![Effect::Worker(Command::Stop(action))])
            }
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
        // ⟨M07⟩ Projects is a scrolled view (the workspace status and the policies).
        if tab == Tab::Projects {
            if key == Key::Char('q') {
                return vec![Effect::Quit];
            }
            if key == Key::Enter {
                return match super::m05::pending_decision(&self.catalog, self.now) {
                    Some(id) => self.open_decision(id),
                    None => Vec::new(),
                };
            }
            self.scroll_key(key);
            return Vec::new();
        }
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
        // ⟨M07⟩ M07-W0-R11: Esc leaves a grouped finding's scope (every destination again).
        if key == Key::Esc && tab == Tab::Destinations && self.scope.is_some() {
            self.set_scope(None);
            return Vec::new();
        }
        let sel = self.selection(tab);
        match tab {
            Tab::Overview => {
                let Some(item) = sel.and_then(|i| self.overview_items().get(i)).cloned() else {
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
                    (Item::Enrollment { id, .. } | Item::LateWrite { id }, Key::Enter) => {
                        self.open_enrollment(id);
                        Vec::new()
                    }
                    (Item::ProjectionPending { alias } | Item::SlotFree { alias }, Key::Enter)
                        if self.catalog.destination(&alias).is_some() =>
                    {
                        self.open_destination(alias);
                        Vec::new()
                    }
                    (
                        Item::Problem { alias: Some(a), .. } | Item::Warning { alias: Some(a), .. },
                        Key::Enter,
                    ) if self.catalog.destination(&a).is_some()
                        || self.doctor_alias(&a).is_some() =>
                    {
                        self.open_destination(a);
                        Vec::new()
                    }
                    // ⟨M07⟩ One destination: its detail. Several: the Destinations tab,
                    // scoped to exactly the destinations this finding concerns
                    // (M07-W0-R11). Its search is cleared, so an earlier, unrelated search
                    // hides none of them, and the list says which finding it shows.
                    (item @ Item::Findings { .. }, Key::Enter) => {
                        let Item::Findings { aliases, .. } = &item else {
                            return Vec::new();
                        };
                        match aliases.as_slice() {
                            [a] if self.catalog.destination(a).is_some()
                                || self.doctor_alias(a).is_some() =>
                            {
                                self.open_destination(a.clone());
                            }
                            _ => {
                                self.searches[0] = Search::default();
                                self.destination_filter = OnceCell::new();
                                self.set_scope(Some(Scope {
                                    label: super::view::finding_words(&item),
                                    aliases: aliases.iter().cloned().collect(),
                                }));
                                self.selected[Tab::Destinations.index()] = 0;
                                self.go_tab(Tab::Destinations);
                            }
                        }
                        Vec::new()
                    }
                    (Item::ListingFailed { subject, .. }, Key::Enter) => {
                        use super::data::subject as s;
                        match subject.as_str() {
                            s::DESTINATIONS => self.go_tab(Tab::Destinations),
                            s::PROFILES => self.go_tab(Tab::Profiles),
                            s::OPERATIONS | s::DECISIONS | s::ENROLLMENTS => {
                                self.go_tab(Tab::Activity);
                            }
                            s::ENVIRONMENTS => self.go_tab(Tab::Environments),
                            s::IDENTITIES => self.go_tab(Tab::Identities),
                            s::POLICIES | s::WORKSPACE => self.go_tab(Tab::Projects),
                            s::CAPABILITIES => {
                                self.tab = Tab::Settings;
                                self.screen = Screen::Lock;
                                self.scroll = 0;
                            }
                            _ => {}
                        }
                        Vec::new()
                    }
                    _ => Vec::new(),
                }
            }
            Tab::Destinations => {
                let alias = sel.and_then(|i| self.visible_destination(i).map(|d| d.alias.clone()));
                let Some(alias) = alias else {
                    return Vec::new();
                };
                match key {
                    Key::Enter => {
                        self.open_destination(alias);
                        Vec::new()
                    }
                    Key::Char('c') => self.connect(alias),
                    Key::Char('p') => self.open_probe_menu(alias),
                    _ => Vec::new(),
                }
            }
            Tab::Profiles => {
                if key == Key::Enter
                    && let Some(id) =
                        sel.and_then(|i| self.visible_profile(i).map(|p| p.id.clone()))
                {
                    self.screen = Screen::Profile(id);
                    self.scroll = 0;
                }
                Vec::new()
            }
            Tab::Activity => {
                if key != Key::Enter {
                    return Vec::new();
                }
                let c = &self.catalog;
                match sel.and_then(|i| self.activity_row(i)) {
                    Some(ActivityRow::Decision(i)) => match c.decisions.get(i) {
                        Some(d) => self.open_decision(d.id.clone()),
                        None => Vec::new(),
                    },
                    Some(ActivityRow::Operation(i)) => match c.operations.get(i) {
                        Some(o) => self.open_operation(o.id.clone()),
                        None => Vec::new(),
                    },
                    Some(ActivityRow::Enrollment(i)) => {
                        if let Some(e) = c.m03.enrollments.get(i) {
                            self.open_enrollment(e.id.clone());
                        }
                        Vec::new()
                    }
                    None => Vec::new(),
                }
            }
            Tab::Projects => Vec::new(),
            Tab::Environments => {
                if key == Key::Enter
                    && let Some(e) = sel.and_then(|i| self.catalog.environments.items.get(i))
                {
                    self.screen = Screen::Environment(e.id.clone());
                    self.scroll = 0;
                }
                Vec::new()
            }
            Tab::Identities => {
                if key == Key::Enter
                    && let Some(i) = sel.and_then(|i| self.catalog.identities.get(i))
                {
                    self.screen = Screen::Identity(i.id.clone());
                    self.scroll = 0;
                }
                Vec::new()
            }
            Tab::Settings => {
                if key != Key::Enter {
                    return Vec::new();
                }
                let Some(row) = sel.and_then(|i| self.setting_rows().get(i)).cloned() else {
                    return Vec::new();
                };
                // ⟨M07⟩ M07-W0-R04: the lock row opens its detail (the saved setting, what
                // is observed, the runtime's own statement), readable at any size.
                if row == super::m07::SettingRow::Lock {
                    self.screen = Screen::Lock;
                    self.scroll = 0;
                }
                match super::m07::choices(&self.catalog, &row) {
                    Ok(choices) => {
                        self.settings = Some(super::m07::SettingPrompt::new(row, choices));
                    }
                    Err(why) => self.status = Some(why),
                }
                Vec::new()
            }
        }
    }

    fn search_key(&mut self, tab: Tab, key: Key) -> Vec<Effect> {
        let i = tab.index();
        let Some(s) = self.search_mut(tab) else {
            return Vec::new();
        };
        let before_len = s.text.len();
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
        // ⟨M07⟩ A changed text drops only its own list's filter (every edit here
        // changes the length when it changes the text).
        if s.text.len() != before_len {
            match tab {
                Tab::Destinations => self.destination_filter = OnceCell::new(),
                Tab::Profiles => self.profile_filter = OnceCell::new(),
                _ => {}
            }
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

    fn open_enrollment(&mut self, id: String) {
        self.screen = Screen::Enrollment(id);
        self.scroll = 0;
    }

    /// ⟨M07⟩ U1c: every probe menu starts with a fresh marker: no frame has drawn it.
    fn open_probe_menu(&mut self, alias: String) -> Vec<Effect> {
        self.probe_sight = Sight::of(&alias);
        self.modal = Some(Modal::ProbeMenu { alias, selected: 0 });
        Vec::new()
    }

    /// ⟨M07⟩ U1c: every visit of an operation's detail starts with a fresh marker.
    fn open_operation(&mut self, id: String) -> Vec<Effect> {
        self.operation_sight = Sight::of(&id);
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
            reading: Reading::default(),
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
            reading: Reading::default(),
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
            Key::Char('p') => self.open_probe_menu(alias.to_owned()),
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
                // ⟨M07⟩ U1c: a cancel stops someone's running work, so `x` cancels only
                // the operation the latest frame showed. Typed ahead of the screen (a
                // batch such as `4 Enter x`) it sends nothing; the status line says why.
                if let Some(why) = self.operation_sight.cancel_unseen(id, self.frame()) {
                    self.status = Some(why.to_owned());
                    return Vec::new();
                }
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
            Modal::ProbeMenu { alias, selected } => self.probe_menu_key(alias, selected, key),
            Modal::Authorization(p) => self.authorization_key(p, key),
            Modal::Repair(p) => self.repair_key(p, key),
            Modal::StopMenu(m) => self.stop_menu_key(m, key),
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

    /// ⟨M03⟩ Whether the listed decision `id` is approved only in the CLI (§17.25 item
    /// 10, §17.26; [`super::m03::cli_only`]): its only verdict here is Deny.
    fn decided_in_cli(&self, id: &str) -> bool {
        self.catalog
            .decisions
            .iter()
            .find(|d| d.id == id)
            .is_some_and(|d| super::m03::cli_only(d).is_some())
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
                // ⟨M03⟩ §17.25 item 10, §17.26: a decision approved only in the CLI has
                // one verdict here, Deny; nothing toggles to Approve.
                p.verdict = if self.decided_in_cli(&p.id) {
                    Verdict::Deny
                } else {
                    match p.verdict {
                        Verdict::Approve => Verdict::Deny,
                        Verdict::Deny => Verdict::Approve,
                    }
                };
                p.input.clear();
                p.reading.refused = false;
                (Some(Modal::Decision(p)), Vec::new())
            }
            Key::Up | Key::Down | Key::PageUp | Key::PageDown | Key::Home | Key::End => {
                p.reading.scroll_key(key);
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
                let Some(listed) = self.catalog.decisions.iter().find(|d| d.id == p.id) else {
                    self.status = Some(format!(
                        "{} is not pending in this runtime: nothing was sent",
                        p.id
                    ));
                    return (None, Vec::new());
                };
                // ⟨M03⟩ §17.25 item 10, §17.26: a decision approved only in the CLI is
                // read-only here except for Deny: whatever the prompt held, only Deny is
                // ever sent for it (after the typed yes above), never Approve.
                if super::m03::cli_only(listed).is_some() {
                    p.verdict = Verdict::Deny;
                }
                // ⟨M03⟩ No approval for a disclosure the owner was not shown.
                if p.verdict == Verdict::Approve
                    && let Some(why) = super::m03::approve_block(&self.catalog, listed)
                        .or_else(|| super::m05::approve_block(listed))
                {
                    self.status = Some(format!(
                        "approve not sent for {}: {why}; nothing was sent",
                        p.id
                    ));
                    return (None, Vec::new());
                }
                if Self::refuse_unread(&mut p.reading, &mut p.input) {
                    return (Some(Modal::Decision(p)), Vec::new());
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
                p.reading.refused = false;
                (Some(Modal::Decision(p)), Vec::new())
            }
        }
    }

    /// A typed `yes` is accepted only once a frame has drawn the last row of the content
    /// it confirms (ADR-0007 §12.31 item 3). If none has, the answer is refused: it is
    /// discarded (the owner types it again after reading), the modal stays open and says
    /// so. Returns whether it was refused.
    fn refuse_unread(reading: &mut Reading, input: &mut String) -> bool {
        if reading.end_shown() {
            return false;
        }
        input.clear();
        reading.refused = true;
        true
    }

    /// One key in the probe menu. ⟨M07⟩ U1c: Enter on a level that contacts something
    /// with no typed authorization ([`contacts_unasked`]) runs it only when the latest
    /// frame drew the menu with this alias and that level's row in full
    /// ([`Sight::level_unseen`]). Otherwise the menu stays open, nothing runs, and the
    /// menu's frame says why until the next key.
    fn probe_menu_key(
        &mut self,
        alias: String,
        selected: usize,
        key: Key,
    ) -> (Option<Modal>, Vec<Effect>) {
        let last = PROBE_LEVELS.len() - 1;
        self.probe_sight.clear_refusal();
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
                let index = selected.min(last);
                let level = PROBE_LEVELS[index].0;
                if contacts_unasked(level)
                    && let Some(why) = self.probe_sight.level_unseen(&alias, index, self.frame())
                {
                    self.probe_sight.refuse(why);
                    return (Some(Modal::ProbeMenu { alias, selected }), Vec::new());
                }
                if runs_real_tree(level) {
                    (
                        Some(Modal::Authorization(AuthPrompt {
                            alias: alias.clone(),
                            level,
                            executed: None,
                            input: String::new(),
                            reading: Reading::default(),
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
            Key::Up | Key::Down | Key::PageUp | Key::PageDown | Key::Home | Key::End => {
                p.reading.scroll_key(key);
                (Some(Modal::Authorization(p)), Vec::new())
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
                if Self::refuse_unread(&mut p.reading, &mut p.input) {
                    return (Some(Modal::Authorization(p)), Vec::new());
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
                p.reading.refused = false;
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
            Key::Up | Key::Down | Key::PageUp | Key::PageDown | Key::Home | Key::End => {
                p.reading.scroll_key(key);
                (Some(Modal::Repair(p)), Vec::new())
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
                if Self::refuse_unread(&mut p.reading, &mut p.input) {
                    return (Some(Modal::Repair(p)), Vec::new());
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
                p.reading.refused = false;
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
            preference: None,
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
            policies: Vec::new(),
            scope: None,
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
            policies: Vec::new(),
            scope: None,
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
            findings: vec![{
                // ⟨M07⟩ The doctor's own words, as the static pass writes them.
                let mut f = finding(
                    "identity_selection_not_exclusive",
                    FindingSeverity::Warning,
                    Some("beta"),
                );
                f.message =
                    "ssh may offer other identities than the adopted key for this alias".to_owned();
                f
            }],
            probes: Vec::new(),
        }
    }

    /// A populated state: two destinations, a profile, an identity with a declaration,
    /// one running operation, a held setup operation and two pending decisions.
    pub(crate) fn populated() -> App {
        let mut app = App::new(now(), false);
        app.set_runtime(Runtime::Connected);
        *app.catalog_mut() = Catalog {
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
            m03: Default::default(),
            m05: Default::default(),
            environments: Default::default(),
            failures: Default::default(),
        };
        *app.doctor_mut() = Some(Doctor {
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

    /// One frame at 120×40, as the event loop draws before it reads a key: the open
    /// confirmation records what the frame showed, and a typed yes needs the end of its
    /// content to have been drawn.
    pub(crate) fn read(app: &App) {
        crate::tui::view::draw_once(app, 120, 40);
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
        app.catalog_mut().operations.retain(|o| !o.is_held());
        app.catalog_mut().decisions.clear();
        assert_eq!(app.health(), Health::Working, "a running operation");
        app.catalog_mut().operations.clear();
        assert_eq!(app.health(), Health::Ready, "warnings alone are not alarms");
        app.doctor_mut()
            .as_mut()
            .unwrap()
            .report
            .findings
            .push(finding("marker_edited", FindingSeverity::Problem, None));
        assert_eq!(app.health(), Health::Attention, "a problem finding");
        let mut fresh = App::new(now(), false);
        assert_eq!(fresh.health(), Health::Checking);
        fresh.set_runtime(Runtime::NotRunning);
        *fresh.doctor_mut() = Some(Doctor {
            report: DoctorReport {
                findings: Vec::new(),
                ..report()
            },
            taken_at: now(),
        });
        assert_eq!(fresh.health(), Health::Ready, "no runtime is not an alarm");
        // An expired decision is not pending work.
        let mut app = populated();
        app.catalog_mut().operations.clear();
        app.catalog_mut().decisions.truncate(1);
        app.catalog_mut().decisions[0].expired = true;
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
        read(&app);
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
            read(&app);
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
        read(&app);
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
        app.catalog_mut().decisions.clear();
        read(&app);
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
                read(&app);
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
        // The levels that run no configuration run on their labelled action alone:
        // ⟨M07⟩ once a frame has drawn the menu (m07-plan U1c;
        // `batched_network_probe_is_not_run_before_its_menu_is_drawn`).
        for (index, level) in [
            (0, ProbeLevel::Static),
            (2, ProbeLevel::Agent),
            (3, ProbeLevel::Network),
        ] {
            let mut app = populated();
            press(&mut app, &[Key::Char('2'), Key::Char('p')]);
            press(&mut app, &vec![Key::Down; index]);
            read(&app);
            assert_eq!(
                worker(&press(&mut app, &[Key::Enter])),
                [Command::Probe {
                    alias: "alpha".to_owned(),
                    level,
                    allow_config_commands: false
                }]
            );
        }
    }

    /// The last row of a frame: the footer, where the status line is shown.
    fn footer_of(rows: &[String]) -> &str {
        rows.last().map_or("", String::as_str)
    }

    /// m07-plan U1c `batched_cancel_is_not_sent_before_its_operation_is_drawn`: `x` stops
    /// someone's running work with no confirmation, so it cancels only the operation
    /// whose detail the latest frame drew. Keys handled before a frame (`4 End Enter x`
    /// in one batch) open the detail and send no cancel, and the status line says why.
    #[test]
    fn batched_cancel_is_not_sent_before_its_operation_is_drawn() {
        use crate::tui::view::draw_once;
        let cancel = |id: &str| [Command::Cancel { id: id.to_owned() }];
        let cancels = |app: &App| worker(&press(&mut app.clone(), &[Key::Char('x')]));
        // Two running operations, so a batch can also reach one from the other's detail.
        let mut base = populated();
        base.catalog_mut().operations.push(
            Operation::of(&serde_json::json!({
                "operation_id": "op_run2", "kind": "ensure", "state": "running",
                "created_at": "2026-11-03T09:00:12Z",
            }))
            .unwrap(),
        );
        draw_once(&base, 120, 40);

        // One batch, no frame between its keys: the detail opens, nothing is cancelled.
        let mut app = base.clone();
        let sent = worker(&press(
            &mut app,
            &[Key::Char('4'), Key::End, Key::Enter, Key::Char('x')],
        ));
        assert_eq!(app.screen, Screen::Operation("op_run2".to_owned()));
        assert_eq!(
            sent,
            [Command::Operation {
                id: "op_run2".to_owned()
            }],
            "only the detail's read: no cancel for an operation no frame has drawn"
        );
        assert_eq!(app.status.as_deref(), Some(REFUSED_NOT_DRAWN));
        // The next frame shows the operation, what x does, and why nothing was sent.
        let rows = draw_once(&app, 120, 40);
        let text = rows.join("\n");
        assert!(text.contains("op_run2 ensure"), "{text}");
        assert!(text.contains("x cancels it"), "{text}");
        assert_eq!(footer_of(&rows), REFUSED_NOT_DRAWN, "{text}");
        // The same key, now that a frame has drawn that operation's detail.
        assert_eq!(
            worker(&press(&mut app, &[Key::Char('x')])),
            cancel("op_run2")
        );
        assert_eq!(app.status.as_deref(), Some("cancelling op_run2"));

        // From one drawn detail to another operation in one batch: that one was not drawn.
        draw_once(&app, 120, 40);
        let sent = worker(&press(
            &mut app,
            &[Key::Esc, Key::Up, Key::Enter, Key::Char('x')],
        ));
        assert_eq!(app.screen, Screen::Operation("op_run1".to_owned()));
        assert!(
            !sent.iter().any(|c| matches!(c, Command::Cancel { .. })),
            "{sent:?}"
        );
        assert_eq!(app.status.as_deref(), Some(REFUSED_NOT_DRAWN));
        // Back to the first one in one batch: what an earlier visit drew does not count.
        let sent = worker(&press(
            &mut app,
            &[Key::Esc, Key::Down, Key::Enter, Key::Char('x')],
        ));
        assert_eq!(app.screen, Screen::Operation("op_run2".to_owned()));
        assert!(
            !sent.iter().any(|c| matches!(c, Command::Cancel { .. })),
            "{sent:?}"
        );
        draw_once(&app, 120, 40);
        assert_eq!(cancels(&app), cancel("op_run2"));

        // Only the latest frame counts: one with no room for any view drew nothing.
        draw_once(&app, 9, 2);
        assert!(cancels(&app).is_empty(), "the latest frame was 9x2");
        // Nor did a frame that drew the key help over the detail.
        draw_once(&app, 120, 40);
        press(&mut app, &[Key::Char('?')]);
        draw_once(&app, 120, 40);
        assert!(
            worker(&press(&mut app, &[Key::Esc, Key::Char('x')])).is_empty(),
            "the latest frame drew the help over the detail"
        );
        assert_eq!(app.status.as_deref(), Some(REFUSED_NOT_DRAWN));
        draw_once(&app, 120, 40);
        assert_eq!(cancels(&app), cancel("op_run2"));

        // A terminal with room for two rows of the detail: every row of the head (the
        // ID and kind, the state, `x cancels it`) has to be drawn, from the top down.
        let mut app = base.clone();
        press(&mut app, &[Key::Char('4'), Key::End, Key::Enter]);
        // A jump past the head before the first frame shows none of it.
        press(&mut app, &[Key::PageDown]);
        draw_once(&app, 40, 4);
        assert!(cancels(&app).is_empty(), "a jump past the head");
        press(&mut app, &[Key::Char('x')]);
        assert_eq!(app.status.as_deref(), Some(REFUSED_UNREAD));
        assert_eq!(footer_of(&draw_once(&app, 40, 4)), REFUSED_UNREAD);
        press(&mut app, &[Key::Home]);
        let mut read_rows = Vec::new();
        let mut frames = 0;
        loop {
            let rows = draw_once(&app, 40, 4);
            read_rows.extend(rows[1..3].iter().cloned());
            if !cancels(&app).is_empty() {
                break;
            }
            frames += 1;
            assert!(frames < 20, "the head is never read:\n{read_rows:#?}");
            press(&mut app, &[Key::Down]);
        }
        assert!(frames > 0, "two rows cannot show the whole head at once");
        let read_text = read_rows.join("\n");
        for shown in ["op_run2 ensure", "State: running", "x cancels it"] {
            assert!(read_text.contains(shown), "{shown}:\n{read_text}");
        }
        // Read through, the cancel is accepted further down too (the events)…
        press(&mut app, &[Key::PageDown]);
        draw_once(&app, 40, 4);
        assert_eq!(cancels(&app), cancel("op_run2"));
        // …also after the clock moved (the relative times are no part of what x names)…
        assert!(app.set_now(t("2026-11-03T09:05:00Z")));
        draw_once(&app, 40, 4);
        assert_eq!(cancels(&app), cancel("op_run2"));
        // …but not once the head says something else: that has to be read again.
        app.catalog_mut().operations[2].effect = Some("started".to_owned());
        draw_once(&app, 40, 4);
        assert!(
            cancels(&app).is_empty(),
            "the state line changed off screen"
        );
        press(&mut app, &[Key::Home]);
        for _ in 0..frames {
            draw_once(&app, 40, 4);
            press(&mut app, &[Key::Down]);
        }
        draw_once(&app, 40, 4);
        assert_eq!(cancels(&app), cancel("op_run2"));
    }

    /// m07-plan U1c `batched_network_probe_is_not_run_before_its_menu_is_drawn`: the
    /// `network` level opens a TCP connection to the host and `agent` asks each agent
    /// endpoint, both on the menu's Enter alone. Enter runs them only when the latest
    /// frame drew the menu with that level's row and its alias. A batch that opens the
    /// menu, moves to the level and presses Enter runs nothing, and the menu says why.
    #[test]
    fn batched_network_probe_is_not_run_before_its_menu_is_drawn() {
        use crate::tui::view::draw_once;
        let probe = |alias: &str, level| {
            [Command::Probe {
                alias: alias.to_owned(),
                level,
                allow_config_commands: false,
            }]
        };
        let to_level = |index: usize| {
            let mut keys = vec![Key::Down; index];
            keys.push(Key::Enter);
            keys
        };
        for (index, level) in [(2, ProbeLevel::Agent), (3, ProbeLevel::Network)] {
            assert!(contacts_unasked(level));
            let name = level_name(level);
            let mut app = populated();
            draw_once(&app, 120, 40);
            // One batch, no frame between its keys.
            let mut keys = vec![Key::Char('2'), Key::Char('p')];
            keys.extend(to_level(index));
            assert_eq!(press(&mut app, &keys), [], "{name}: nothing drawn");
            assert_eq!(
                app.modal,
                Some(Modal::ProbeMenu {
                    alias: "alpha".to_owned(),
                    selected: index
                }),
                "{name}: the menu stays open on the level"
            );
            // The next frame shows the alias, the level, and why nothing ran.
            let rows = draw_once(&app, 120, 40);
            let text = rows.join("\n");
            for shown in [
                "Explicit probes for alpha; each names its level:".to_owned(),
                format!("> {name}"),
                "Enter refused: it was not on screen".to_owned(),
            ] {
                assert!(text.contains(&shown), "{name}: {shown}:\n{text}");
            }
            assert_eq!(footer_of(&rows), REFUSED_PROBE_NOT_DRAWN, "{name}:\n{text}");
            // The same Enter, now that a frame has drawn that level for that alias.
            assert_eq!(
                worker(&press(&mut app, &[Key::Enter])),
                probe("alpha", level)
            );
            assert!(matches!(app.modal, Some(Modal::Probe(_))), "{name}");

            // A menu for another alias in one batch: the frame drew alpha's menu.
            let mut app = populated();
            press(&mut app, &[Key::Char('2'), Key::Char('p')]);
            draw_once(&app, 120, 40);
            let mut keys = vec![Key::Esc, Key::Down, Key::Char('p')];
            keys.extend(to_level(index));
            assert_eq!(press(&mut app, &keys), [], "{name}: beta's menu not drawn");
            assert!(matches!(&app.modal, Some(Modal::ProbeMenu { alias, .. }) if alias == "beta"));
            let rows = draw_once(&app, 120, 40);
            assert_eq!(footer_of(&rows), REFUSED_PROBE_NOT_DRAWN, "{name}");
            // The refusal is said until the next key.
            press(&mut app, &[Key::Up, Key::Down]);
            let rows = draw_once(&app, 120, 40);
            assert!(
                !rows.join("\n").contains("refused") && footer_of(&rows).contains("Enter run"),
                "{name}:\n{}",
                rows.join("\n")
            );
            assert_eq!(
                worker(&press(&mut app, &[Key::Enter])),
                probe("beta", level)
            );

            // Only the latest frame counts: one with no room for any view drew nothing.
            let mut app = populated();
            press(&mut app, &[Key::Char('2'), Key::Char('p')]);
            draw_once(&app, 120, 40);
            draw_once(&app, 9, 2);
            assert_eq!(press(&mut app, &to_level(index)), [], "{name}: 9x2");

            // A frame that drew the menu with every level and the alias, but another level
            // selected: keys typed ahead that move to this level and press Enter run
            // nothing (only the level a frame drew as selected counts). Once a frame has
            // shown it selected, Enter runs it.
            let mut app = populated();
            press(&mut app, &[Key::Char('2'), Key::Char('p')]);
            let text = draw_once(&app, 120, 40).join("\n");
            assert!(text.contains(name) && text.contains("alpha"), "{text}");
            assert_eq!(press(&mut app, &to_level(index)), [], "{name}: typed ahead");
            draw_once(&app, 120, 40);
            assert_eq!(
                worker(&press(&mut app, &[Key::Enter])),
                probe("alpha", level)
            );
        }
        // The other levels are as they were in a batch: `static` only reads files again,
        // and a real-tree level asks for its typed authorization first.
        let mut app = populated();
        assert_eq!(
            worker(&press(
                &mut app,
                &[Key::Char('2'), Key::Char('p'), Key::Enter]
            )),
            probe("alpha", ProbeLevel::Static)
        );
        for (index, level) in [
            (1, ProbeLevel::Evaluate),
            (4, ProbeLevel::HostVerification),
            (5, ProbeLevel::Authentication),
        ] {
            assert!(!contacts_unasked(level) && runs_real_tree(level));
            let mut app = populated();
            let mut keys = vec![Key::Char('2'), Key::Char('p')];
            keys.extend(to_level(index));
            assert_eq!(
                worker(&press(&mut app, &keys)),
                [Command::PrepareProbe {
                    alias: "alpha".to_owned(),
                    level
                }]
            );
            assert!(matches!(app.modal, Some(Modal::Authorization(_))));
        }
    }

    /// m07-plan U1c, the terminal too small for the probe menu: a frame with no room for
    /// the sentence that names the alias and the selected level's rows shows a notice
    /// instead, and Enter on `agent` or `network` runs nothing and says why. A frame
    /// that draws the menu without that level's row does not count for it either.
    #[test]
    fn network_probe_short_terminal_refuses_to_run() {
        use crate::tui::view::draw_once;
        let network = [Command::Probe {
            alias: "alpha".to_owned(),
            level: ProbeLevel::Network,
            allow_config_commands: false,
        }];
        let on_network = || {
            let mut app = populated();
            press(
                &mut app,
                &[
                    Key::Char('2'),
                    Key::Char('p'),
                    Key::Down,
                    Key::Down,
                    Key::Down,
                ],
            );
            app
        };
        for (w, h) in [(120, 5), (120, 4), (120, 3), (40, 6), (20, 8), (12, 10)] {
            let mut app = on_network();
            let text = draw_once(&app, w, h).join("\n");
            assert!(
                text.contains("[!!] Too")
                    && !text.contains("Explicit")
                    && !text.contains("network  "),
                "{w}x{h}: the notice, not a cut menu:\n{text}"
            );
            assert_eq!(press(&mut app, &[Key::Enter]), [], "{w}x{h}: nothing runs");
            assert!(
                matches!(app.modal, Some(Modal::ProbeMenu { .. })),
                "{w}x{h}"
            );
            let rows = draw_once(&app, w, h);
            let said: String = REFUSED_PROBE_TOO_SMALL
                .chars()
                .take(usize::from(w))
                .collect();
            assert_eq!(footer_of(&rows), said.trim_end(), "{w}x{h}: it says why");
            // Enlarged, the same Enter runs it.
            let text = draw_once(&app, 120, 40).join("\n");
            assert!(
                text.contains("> network") && text.contains("alpha"),
                "{text}"
            );
            assert_eq!(worker(&press(&mut app, &[Key::Enter])), network, "{w}x{h}");
        }
        // Drawn in full, then a frame too small for it: only the latest frame counts.
        let mut app = on_network();
        draw_once(&app, 120, 40);
        draw_once(&app, 120, 5);
        assert_eq!(press(&mut app, &[Key::Enter]), []);

        // 40x12 has room for the alias and some levels, not all six. With `static`
        // selected the frame does not show `network`: a batch that moves there and
        // presses Enter runs nothing. The next frame shows it, and Enter runs it.
        let mut app = populated();
        press(&mut app, &[Key::Char('2'), Key::Char('p')]);
        let text = draw_once(&app, 40, 12).join("\n");
        assert!(
            text.contains("> static") && text.contains("alpha") && !text.contains("network"),
            "{text}"
        );
        assert_eq!(
            press(&mut app, &[Key::Down, Key::Down, Key::Down, Key::Enter]),
            []
        );
        let rows = draw_once(&app, 40, 12);
        let text = rows.join("\n");
        assert!(
            text.contains("> network") && text.contains("alpha"),
            "{text}"
        );
        assert_eq!(footer_of(&rows), REFUSED_PROBE_NOT_DRAWN, "{text}");
        assert_eq!(worker(&press(&mut app, &[Key::Enter])), network);
    }

    /// ADR-0007 §12.31 item 3: the scroll keys move a page less one row (so no row is
    /// skipped between two frames), stop at both ends, and the end counts as shown only
    /// for the content whose last row a frame drew.
    #[test]
    fn reading_scrolls_without_skipping_and_remembers_the_end_per_content() {
        let mut r = Reading::default();
        assert!(!r.end_shown() && !r.scrollable(), "no frame yet");
        assert!(!r.scroll_key(Key::Char('a')) && !r.scroll_key(Key::Enter));
        // A frame of 5 rows over 30: pages of 4, one row of overlap.
        let frame = |r: &Reading, content| r.record(content, 30, 5, r.scroll.min(25));
        frame(&r, 1);
        assert!(r.scrollable() && !r.end_shown());
        let mut seen = vec![r.scroll];
        for _ in 0..8 {
            assert!(r.scroll_key(Key::PageDown));
            frame(&r, 1);
            seen.push(r.scroll);
        }
        assert_eq!(seen, [0, 4, 8, 12, 16, 20, 24, 25, 25]);
        assert!(r.end_shown(), "the page that reached row 29 was drawn");
        // Back up and to both ends.
        for (key, to) in [
            (Key::PageUp, 21),
            (Key::Up, 20),
            (Key::Down, 21),
            (Key::Home, 0),
            (Key::Up, 0),
            (Key::End, 25),
            (Key::Down, 25),
        ] {
            assert!(r.scroll_key(key));
            frame(&r, 1);
            assert_eq!(r.scroll, to, "{key:?}");
        }
        // The same content stays read wherever the view is; changed content is not.
        r.scroll_key(Key::Home);
        frame(&r, 1);
        assert!(r.end_shown());
        frame(&r, 2);
        assert!(!r.end_shown(), "another content, drawn from its start");
        r.scroll_key(Key::End);
        frame(&r, 2);
        assert!(r.end_shown());
        // Without a frame in between the keys move a request, and nothing is shown.
        let mut fresh = Reading::default();
        fresh.scroll_key(Key::End);
        assert!(!fresh.end_shown());
        // A screen with no room for a row shows no row.
        let none = Reading::default();
        none.record(3, 30, 0, 0);
        assert!(!none.end_shown() && none.scrollable());
        // Content that fits is read at the first frame.
        let fits = Reading::default();
        fits.record(4, 3, 8, 0);
        assert!(fits.end_shown() && !fits.scrollable());
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
        // ⟨M07⟩ `x` cancels what a frame has shown (m07-plan U1c).
        read(&app);
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
        app.catalog_mut().decisions[0].request["operation_id"] = serde_json::json!("op_run1");
        press(
            &mut app,
            &[Key::Char('4'), Key::End, Key::Enter, Key::Enter],
        );
        assert!(matches!(&app.modal, Some(Modal::Decision(p)) if p.id == "dec_apply1"));
        press(&mut app, &[Key::Esc]);
        // Start the runtime when none runs.
        app.set_runtime(Runtime::NotRunning);
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

    /// ⟨M05; ruling I-27⟩ After an import that skipped a routed destination, the runtime's
    /// destination list (the `inspect destinations` answer the TUI is built from) has only what
    /// import wrote: the TUI's connect refuses the skipped alias as an unknown destination and
    /// hands nothing to `ssh`, while a listed one still connects.
    #[test]
    fn a_destination_an_import_skipped_is_never_connectable_from_the_tui() {
        let mut app = App::new(now(), false);
        app.set_runtime(Runtime::Connected);
        let destinations = serde_json::json!({"destinations": [
            {"destination_id": "bastion", "alias": "bastion", "definition": "observed"}
        ]});
        *app.catalog_mut() = Catalog::from_answers(
            &destinations,
            &serde_json::Value::Null,
            &serde_json::Value::Null,
            &serde_json::Value::Null,
            &serde_json::Value::Null,
            &serde_json::Value::Null,
            now(),
        );
        assert!(
            app.catalog.destination("bastion").is_some(),
            "{:?}",
            app.catalog.destinations
        );
        assert!(app.connect("lab-inner".to_owned()).is_empty());
        assert!(
            app.status
                .as_deref()
                .unwrap()
                .contains("lab-inner: unknown destination")
        );
        assert_eq!(
            app.connect("bastion".to_owned()),
            [Effect::Connect("bastion".to_owned())]
        );
    }

    /// ⟨M07⟩ U1 (probe P1, P2): an update that changes nothing keeps the derived data
    /// and sets no redraw; a change drops what it touches; a search change recomputes only
    /// its own list; the clock asks for a redraw only when the displayed minute changes or
    /// a pending decision expires.
    #[test]
    fn derived_data_is_computed_once_per_change() {
        let mut app = populated();
        let derive_all = |app: &App| {
            let _ = app.overview_items();
            let _ = app.shown(Tab::Destinations);
            let _ = app.shown(Tab::Profiles);
        };
        derive_all(&app);
        let _ = app.take_changed();
        let cached = |app: &App| {
            (
                app.derived.get().is_some(),
                app.destination_filter.get().is_some(),
                app.profile_filter.get().is_some(),
            )
        };
        assert_eq!(cached(&app), (true, true, true));
        // The same answers read again (only the read time moves).
        let mut same = app.catalog().clone();
        same.read_at = Some(t("2026-11-03T09:00:28Z"));
        same.identities[0].checked_at = Some(t("2026-11-03T09:00:28Z"));
        let before = app.derived().clone();
        app.apply(Update::Catalog(Box::new(same)));
        assert!(!app.take_changed(), "an identical poll draws nothing");
        assert_eq!(cached(&app), (true, true, true), "nothing is derived again");
        assert_eq!(*app.derived(), before);
        assert_eq!(app.catalog().read_at, Some(t("2026-11-03T09:00:28Z")));
        assert_eq!(
            app.catalog().identities[0].checked_at,
            Some(t("2026-11-03T09:00:28Z"))
        );
        for unchanged in [
            Update::Runtime(Runtime::Connected),
            Update::Doctor(Box::new(app.doctor().cloned().unwrap())),
            Update::OfflineChores(Vec::new()),
        ] {
            app.apply(unchanged.clone());
            assert!(!app.take_changed(), "{unchanged:?}");
            assert_eq!(cached(&app), (true, true, true), "{unchanged:?}");
        }
        // An operation that changed: the overview is derived again, the lists are not.
        let mut ops = app.catalog().clone();
        ops.operations.retain(|o| !o.is_held());
        app.apply(Update::Catalog(Box::new(ops)));
        assert!(app.take_changed());
        assert_eq!(cached(&app), (false, true, true));
        assert_eq!(app.health(), Health::Attention, "the decisions still wait");
        // A new destination: its filter too.
        derive_all(&app);
        let mut more = app.catalog().clone();
        more.destinations.push(destination("gamma", false));
        app.apply(Update::Catalog(Box::new(more)));
        assert!(app.take_changed());
        assert_eq!(cached(&app), (false, false, true));
        // A search keystroke recomputes only its own list.
        derive_all(&app);
        press(&mut app, &[Key::Char('2'), Key::Char('/')]);
        assert_eq!(
            cached(&app),
            (true, true, true),
            "opening the search filters nothing"
        );
        type_text(&mut app, "gam");
        assert_eq!(cached(&app), (true, false, true));
        assert_eq!(app.shown(Tab::Destinations), 1);
        // A key that does not change the text keeps the filter.
        press(&mut app, &[Key::Left]);
        assert_eq!(cached(&app), (true, true, true));
        // The clock: the same minute asks for nothing; the next minute redraws.
        assert!(!app.set_now(t("2026-11-03T09:00:59Z")));
        assert_eq!(cached(&app), (true, true, true));
        assert!(app.set_now(t("2026-11-03T09:01:00Z")));
        // A pending decision that expires mid-minute: a redraw, and it leaves the
        // overview.
        app.catalog_mut().decisions.truncate(1);
        app.catalog_mut().decisions[0].expires_at = Some(t("2026-11-03T09:01:30Z"));
        assert!(
            app.overview_items()
                .iter()
                .any(|i| matches!(i, Item::Decision { .. }))
        );
        assert!(!app.set_now(t("2026-11-03T09:01:29Z")));
        assert!(app.set_now(t("2026-11-03T09:01:30Z")));
        assert!(
            !app.overview_items()
                .iter()
                .any(|i| matches!(i, Item::Decision { .. }))
        );
    }

    /// M07-W0-R06: Settings and Activity do no catalog-sized work per key. The Settings
    /// rows are built once per change of the listings and then only read: keys on
    /// Settings, and a poll that changes nothing, keep the very same rows; a changed
    /// listing drops them. A connection row is its destination's index (no alias is
    /// searched for), and an Activity row is found by arithmetic on the three listings.
    #[test]
    fn settings_and_activity_rows_are_not_rebuilt_per_key() {
        use crate::tui::m07::SettingRow;
        use crate::tui::view::draw_once;
        let mut app = crate::tui::m07::fixtures::app();
        let managed = 5000;
        app.catalog_mut().destinations = (0..managed)
            .map(|i| destination(&format!("m{i:06}"), true))
            .chain([destination("observed", false)])
            .collect();
        press(&mut app, &[Key::Char('8')]);
        // The fixture's own rows (a default profile, two policies, the lock row), then
        // one row per managed destination (the observed one has none).
        assert_eq!(app.shown(Tab::Settings), 4 + managed);
        let built = app.setting_rows().as_ptr();
        press(&mut app, &[Key::Down, Key::PageDown, Key::End]);
        draw_once(&app, 120, 40);
        assert_eq!(app.selection(Tab::Settings), Some(4 + managed - 1));
        assert_eq!(
            app.setting_rows().as_ptr(),
            built,
            "keys and frames read the rows; they do not build them"
        );
        let last = app.setting_rows().last().cloned().unwrap();
        assert_eq!(last, SettingRow::Connection { at: managed - 1 });
        let screen = draw_once(&app, 40, 12).join("\n");
        assert!(screen.contains("> [??] m004999: not reported"), "{screen}");
        assert!(
            !screen.contains("m000000"),
            "only the window is drawn: {screen}"
        );
        // A poll with the same answers keeps them; a changed listing builds them again.
        let mut same = app.catalog().clone();
        same.read_at = Some(t("2026-11-03T09:00:28Z"));
        app.apply(Update::Catalog(Box::new(same)));
        assert!(app.setting_rows.get().is_some());
        let mut fewer = app.catalog().clone();
        fewer.destinations.truncate(10);
        app.apply(Update::Catalog(Box::new(fewer)));
        assert!(app.setting_rows.get().is_none(), "dropped with the listing");
        assert_eq!(app.shown(Tab::Settings), 4 + 10);
        // Activity: decisions, then operations, then enrollment records, by position.
        let (d, o, e) = app.activity_counts();
        assert!(d > 0 && o > 0, "{d} {o} {e}");
        assert_eq!(app.shown(Tab::Activity), d + o + e);
        assert_eq!(app.activity_row(0), Some(ActivityRow::Decision(0)));
        assert_eq!(app.activity_row(d - 1), Some(ActivityRow::Decision(d - 1)));
        assert_eq!(app.activity_row(d), Some(ActivityRow::Operation(0)));
        assert_eq!(
            app.activity_row(d + o),
            None,
            "no enrollment records listed"
        );
        // Enter on a position opens that listing's record.
        press(&mut app, &[Key::Char('4'), Key::End]);
        let last_op = app.catalog().operations[o - 1].id.clone();
        assert_eq!(
            worker(&press(&mut app, &[Key::Enter])),
            [Command::Operation {
                id: last_op.clone()
            }]
        );
        assert_eq!(app.screen, Screen::Operation(last_op));
    }

    #[test]
    fn a_decision_the_runtime_just_issued_opens_once_listed() {
        let mut app = populated();
        let decisions = std::mem::take(&mut app.catalog_mut().decisions);
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

    fn stale(id: &str, decision_ref: Option<&str>) -> Update {
        Update::Decided {
            id: id.to_owned(),
            outcome: Outcome {
                ok: false,
                code: DECISION_STALE.to_owned(),
                message: "the decision is stale".to_owned(),
                decision_ref: decision_ref.map(str::to_owned),
            },
        }
    }

    /// ⟨M07⟩ U2 `decision_stale_resets_the_confirmation_and_never_reuses_yes`: a decision
    /// another client's request created cannot be asked for again from the TUI. On
    /// `DECISION_STALE` its own confirmation is reset (its modal closes, whatever was typed
    /// is gone), the decisions are read again, a plain status line says the request
    /// changed, and the new version does not open by itself: the owner opens it and types
    /// `yes` to it afresh. A typed yes is never applied to another record. (M07-W0-R07:
    /// the refresh-only path, kept for decisions that came from elsewhere.)
    #[test]
    fn decision_stale_resets_the_confirmation_and_never_reuses_yes() {
        let mut app = populated();
        // The owner reads dec_apply1 to its end and confirms it: Decide is sent.
        press(&mut app, &[Key::Char('4'), Key::Enter]);
        read(&app);
        press(&mut app, &[Key::End]);
        read(&app);
        type_text(&mut app, "yes");
        let sent = worker(&press(&mut app, &[Key::Enter]));
        assert_eq!(
            sent,
            [Command::Decide {
                id: "dec_apply1".to_owned(),
                verdict: Verdict::Approve
            }]
        );
        // Before the answer arrives, the owner opens the same record again and types yes.
        press(&mut app, &[Key::Enter]);
        read(&app);
        type_text(&mut app, "yes");
        // The answer: the record changed (the runtime may even name another record).
        let effects = app.apply(stale("dec_apply1", Some("dec_apply2")));
        assert_eq!(
            worker(&effects),
            [Command::Refresh { doctor: false }],
            "not the TUI's request: it is only read again"
        );
        assert!(
            app.modal.is_none(),
            "the confirmation is reset: {:?}",
            app.modal
        );
        assert_eq!(app.open_when_listed, None, "nothing opens by itself");
        let status = app.status.clone().unwrap();
        assert!(
            status.contains("the request changed") && status.contains("nothing was approved"),
            "{status}"
        );
        assert!(
            status.contains("when the requester tries again"),
            "{status}"
        );
        assert!(!status.contains("DECISION_STALE"), "plain words: {status}");
        // The typed yes went with the modal: Enter now decides nothing (it opens the
        // selected record afresh, with an empty confirmation).
        let sent = worker(&press(&mut app, &[Key::Enter]));
        assert!(
            !sent.iter().any(|c| matches!(c, Command::Decide { .. })),
            "{sent:?}"
        );
        assert!(matches!(&app.modal, Some(Modal::Decision(p)) if p.input.is_empty()));
        press(&mut app, &[Key::Esc]);
        // The requester's retry lists the new version; it does not open by itself, and
        // when the owner opens it the confirmation starts empty: Enter is default No.
        let mut c = app.catalog.clone();
        let mut renewed = apply_decision();
        renewed.id = "dec_apply2".to_owned();
        c.decisions = vec![renewed, declare_decision()];
        app.apply(Update::Catalog(Box::new(c)));
        assert!(app.modal.is_none());
        press(&mut app, &[Key::Char('4'), Key::Home, Key::Enter]);
        let Some(Modal::Decision(p)) = &app.modal else {
            panic!("{:?}", app.modal);
        };
        assert_eq!(p.id, "dec_apply2");
        assert!(p.input.is_empty(), "an earlier yes never carries over");
        read(&app);
        press(&mut app, &[Key::End]);
        read(&app);
        assert!(
            worker(&press(&mut app, &[Key::Enter])).is_empty(),
            "default No"
        );
        // A stale answer while no modal is open changes nothing but the status, and a
        // later modal opened for the same record also starts empty.
        let mut app = populated();
        app.apply(stale("dec_apply1", None));
        assert!(app.modal.is_none());
        press(&mut app, &[Key::Char('4'), Key::Enter]);
        assert!(matches!(&app.modal, Some(Modal::Decision(p)) if p.input.is_empty()));
    }

    /// The TUI's own widening, as the worker reports it: `resume pol-per1`, answered with
    /// the decision `decision`.
    fn resume_sent(decision: &str, replaces: Option<&str>) -> (Origin, Update) {
        use heimdall_contract::ids::{PolicyId, RequestId};
        let action = crate::tui::m07::SettingAction::Resume {
            policy: PolicyId::parse("pol-per1").unwrap(),
        };
        let origin = Origin {
            what: action.what(),
            request: Box::new(action.request(RequestId::parse("req-origin-1").unwrap())),
            attends: action.attends(),
        };
        let update = Update::Sent {
            origin: origin.clone(),
            outcome: Outcome {
                ok: false,
                code: "DECISION_REQUIRED".to_owned(),
                message: "needs your decision".to_owned(),
                decision_ref: Some(decision.to_owned()),
            },
            replaces: replaces.map(str::to_owned),
        };
        (origin, update)
    }

    /// The listings of `app` with the pending widening `id` added.
    fn listing_with(app: &App, id: &str) -> Update {
        let mut c = app.catalog().clone();
        let mut d = crate::tui::m05::fixtures::decision(
            id,
            "widen_policy",
            serde_json::json!({"action": {"action": "resume", "policy_id": "pol-per1"}}),
        );
        d.expires_at = Some(t("2026-11-03T09:30:00Z"));
        c.decisions.push(d);
        Update::Catalog(Box::new(c))
    }

    /// Read the open decision to its end and answer yes; what was sent.
    fn approve_open(app: &mut App) -> Vec<Command> {
        read(app);
        press(app, &[Key::End]);
        read(app);
        type_text(app, "yes");
        worker(&press(app, &[Key::Enter]))
    }

    /// ⟨M07⟩ U2 `decision_stale_retries_with_the_same_key_and_resets_the_confirmation`
    /// (M07-W0-R07): a decision the TUI's own request created is retried when it goes
    /// stale. The same request is sent again, unchanged (so with its request ID), the
    /// decision the runtime answers with opens once listed, and it needs a fresh
    /// confirmation under the reading guard: nothing typed for the stale record counts.
    #[test]
    fn decision_stale_retries_with_the_same_key_and_resets_the_confirmation() {
        let mut app = crate::tui::m07::fixtures::app();
        // The Settings change was sent; the runtime answered with dec_resume1.
        let (origin, sent) = resume_sent("dec_resume1", None);
        assert_eq!(
            worker(&app.apply(sent)),
            [Command::Refresh { doctor: true }]
        );
        let listed = listing_with(&app, "dec_resume1");
        app.apply(listed);
        assert!(matches!(&app.modal, Some(Modal::Decision(p)) if p.id == "dec_resume1"));
        assert_eq!(
            approve_open(&mut app),
            [Command::Decide {
                id: "dec_resume1".to_owned(),
                verdict: Verdict::Approve
            }]
        );
        // The record changed after it was reviewed: the TUI's own request goes again.
        let effects = app.apply(stale("dec_resume1", None));
        assert_eq!(
            worker(&effects),
            [Command::Resend {
                origin: origin.clone(),
                replaces: "dec_resume1".to_owned()
            }],
            "the same request, request ID included"
        );
        let status = app.status.clone().unwrap();
        assert!(
            status.contains("nothing was approved") && status.contains("asking again"),
            "{status}"
        );
        assert!(app.modal.is_none());
        // The runtime answers the retry with a fresh decision, which opens once listed.
        let (_, again) = resume_sent("dec_resume2", Some("dec_resume1"));
        app.apply(again);
        assert_eq!(app.open_when_listed.as_deref(), Some("dec_resume2"));
        let listed = listing_with(&app, "dec_resume2");
        app.apply(listed);
        let Some(Modal::Decision(p)) = &app.modal else {
            panic!("the fresh decision is shown: {:?}", app.modal);
        };
        assert_eq!(p.id, "dec_resume2");
        assert!(p.input.is_empty(), "nothing typed carries over");
        // A fresh confirmation under the reading guard: a yes before any frame of the
        // new record is refused, and after it was read it approves that record.
        type_text(&mut app, "yes");
        assert!(worker(&press(&mut app, &[Key::Enter])).is_empty(), "unread");
        assert!(matches!(&app.modal, Some(Modal::Decision(p)) if p.reading.refused));
        assert_eq!(
            approve_open(&mut app),
            [Command::Decide {
                id: "dec_resume2".to_owned(),
                verdict: Verdict::Approve
            }]
        );
        // If that one goes stale too, it is retried the same way (its request is kept
        // under the decision it was last answered with).
        let effects = app.apply(stale("dec_resume2", None));
        assert_eq!(
            worker(&effects),
            [Command::Resend {
                origin: origin.clone(),
                replaces: "dec_resume2".to_owned()
            }]
        );
        // A retry the runtime answers with the stale record itself shows nothing new.
        let (_, same) = resume_sent("dec_resume2", Some("dec_resume2"));
        app.apply(same);
        assert_eq!(app.open_when_listed, None);
        let status = app.status.clone().unwrap();
        assert!(
            status.contains("still refers to the changed request"),
            "{status}"
        );
        // A completed decision's request is forgotten: a late stale answer for it takes
        // the refresh-only path.
        let mut app = crate::tui::m07::fixtures::app();
        let (_, sent) = resume_sent("dec_resume1", None);
        app.apply(sent);
        app.apply(Update::Decided {
            id: "dec_resume1".to_owned(),
            outcome: Outcome {
                ok: true,
                code: "OK".to_owned(),
                message: String::new(),
                decision_ref: None,
            },
        });
        assert_eq!(
            worker(&app.apply(stale("dec_resume1", None))),
            [Command::Refresh { doctor: false }]
        );
    }

    /// M07-W0-R07: a stale answer is matched with its own modal. A modal the owner opened
    /// in between (another decision with a typed yes, the key help, a Settings prompt) is
    /// not closed and nothing is sent for it; the retried request's fresh decision waits
    /// until that modal is closed, and never opens over it.
    #[test]
    fn a_stale_answer_leaves_an_unrelated_modal_alone() {
        let mut app = crate::tui::m07::fixtures::app();
        let (origin, sent) = resume_sent("dec_resume1", None);
        app.apply(sent);
        let listed = listing_with(&app, "dec_resume1");
        app.apply(listed);
        assert_eq!(approve_open(&mut app).len(), 1, "Decide for dec_resume1");
        // In between, the owner opens another decision, reads it and types yes.
        press(&mut app, &[Key::Char('4'), Key::Home, Key::Enter]);
        let Some(Modal::Decision(p)) = &app.modal else {
            panic!("{:?}", app.modal);
        };
        let other = p.id.clone();
        assert_ne!(other, "dec_resume1");
        read(&app);
        press(&mut app, &[Key::End]);
        read(&app);
        type_text(&mut app, "yes");
        let before = app.modal.clone();
        // The stale answer for dec_resume1 arrives.
        let effects = app.apply(stale("dec_resume1", None));
        assert_eq!(
            worker(&effects),
            [Command::Resend {
                origin,
                replaces: "dec_resume1".to_owned()
            }],
            "only the retry: nothing is decided for the open modal"
        );
        assert_eq!(
            app.modal, before,
            "the unrelated modal is exactly as it was"
        );
        // The retry's fresh decision is listed while that modal is still open: it waits.
        let (_, again) = resume_sent("dec_resume2", Some("dec_resume1"));
        app.apply(again);
        let listed = listing_with(&app, "dec_resume2");
        app.apply(listed.clone());
        assert!(
            matches!(&app.modal, Some(Modal::Decision(p)) if p.id == other && p.input == "yes"),
            "{:?}",
            app.modal
        );
        // The owner cancels the unrelated one: nothing is sent for it, and the fresh
        // decision opens with the next listing, empty.
        assert!(worker(&press(&mut app, &[Key::Esc])).is_empty());
        app.apply(listed);
        assert!(
            matches!(&app.modal, Some(Modal::Decision(p)) if p.id == "dec_resume2" && p.input.is_empty()),
            "{:?}",
            app.modal
        );
        // The same for a decision from elsewhere, and for a modal that is no decision.
        let mut app = populated();
        press(&mut app, &[Key::Char('4'), Key::Down, Key::Enter]);
        type_text(&mut app, "yes");
        let before = app.modal.clone();
        assert!(matches!(&before, Some(Modal::Decision(p)) if p.id == "dec_declare1"));
        app.apply(stale("dec_apply1", None));
        assert_eq!(app.modal, before);
        let mut app = populated();
        press(&mut app, &[Key::Char('?')]);
        app.apply(stale("dec_apply1", None));
        assert_eq!(app.modal, Some(Modal::Help));
    }
}
