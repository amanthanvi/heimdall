//! Rendering (m02-plan U10; spec §12.1, §12.2). Pure: draws an [`App`] into a frame.
//!
//! **Meaning is never carried by color alone.** Every state has a text marker
//! (`[OK]` Ready, `[..]` Working, `[!!]` Needs attention, `[??]` Checking, `[ !]` a
//! warning), the selected row starts with `> `, the current tab is bracketed, and each
//! value of the detail view names its provenance in words (`[managed]`, `[observed]`,
//! `[inherited]`, `[undetermined]`). Color only repeats what the text says, and with
//! `NO_COLOR` no cell carries a foreground or background color at all.
//!
//! Rendering never queries the terminal (no cursor-position request; the backend
//! refuses one) and draws only when something changed, so the screen is not
//! continually repainted (spec §12.2).
//!
//! **Confirmations are never truncated** (ADR-0007 §12.31 item 3): a decision, an
//! authorization and a repair wrap long lines, stack the diff's columns when the cells
//! do not fit side by side, and scroll above a prompt that stays fixed. The one place
//! where drawing writes state is the report each such frame makes to the modal's
//! [`Reading`]: which rows it drew, so the model can tell when the last one has been on
//! screen. ⟨M07⟩ A Settings change and the stop menu's confirmation are drawn by one
//! renderer of their own ([`render_guarded_confirm`]), which also reports to their
//! [`Seen`] whether this frame, counted by [`App::begin_frame`], drew them at all.

use heimdall_contract::Timestamp;
use heimdall_contract::doctor::{
    AliasDefinition, ConfigFileRole, DirectiveCertainty, DoctorReport, ProbeOutcome,
    ProjectionState,
};
use heimdall_contract::provider::{IdentitySelection, ProbeLevel};
use heimdall_contract::request::Verdict;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use super::data::{Decision, Runtime, clean};
use super::keys::Key;
use super::model::{
    AUTHORIZATION_TEXT, ActivityRow, App, AuthPrompt, DecisionPrompt, Health, Item, MAX_TYPED,
    Modal, NONE_FOUND_TEXT, PROBE_LEVELS, ProbeView, REFUSED_UNREAD, Reading, RepairPrompt, Screen,
    Seen, Shown, Tab, level_name,
};

/// The decision text of a `DeclareInteraction` decision (ADR-0007 §7, verbatim).
pub(crate) const DECLARATION_TEXT: &str = "Heimdall will treat this key as needing no confirmation and will launch non-interactive work with it. If the key in fact asks for confirmation, the agent's dialog can still appear.";

/// The disclosure every confirmation carries (ADR-0006 §3.1).
const IMITATION_TEXT: &str = "Heimdall cannot verify that this prompt was shown: a program running as your user could imitate it.";

/// The heading of every probe record's command list (ADR-0007 §6, M2-S04).
const INVENTORY_HEADING: &str = heimdall_localenv::doctor::INVENTORY_WORDING;

/// Styles, or none at all under `NO_COLOR`.
#[derive(Debug, Clone, Copy)]
struct Theme {
    color: bool,
}

impl Theme {
    fn fg(self, c: Color) -> Style {
        if self.color {
            Style::new().fg(c)
        } else {
            Style::new()
        }
    }

    fn bold(self) -> Style {
        Style::new().add_modifier(Modifier::BOLD)
    }

    fn selected(self) -> Style {
        if self.color {
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::BOLD)
        }
    }

    fn health(self, h: Health) -> Style {
        self.fg(match h {
            Health::Ready => Color::Green,
            Health::Working => Color::Yellow,
            Health::Attention => Color::Red,
            Health::Checking => Color::Blue,
            Health::Unknown => Color::Magenta,
        })
    }

    fn dim(self) -> Style {
        self.fg(Color::DarkGray)
    }
}

/// `ts` as `HH:MM:SSZ`.
fn hms(ts: Timestamp) -> String {
    ts.strftime("%H:%M:%SZ").to_string()
}

/// `ts` as `YYYY-MM-DDTHH:MM:SSZ` (whole seconds).
fn full(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// How long ago (or from now) `ts` is, coarsely: ⟨M07⟩ at minute granularity, so an
/// idle screen changes at most once a minute (m07-plan U1, probe P1).
fn age(now: Timestamp, ts: Timestamp) -> String {
    let d = now.as_second() - ts.as_second();
    let a = d.unsigned_abs();
    if a < 60 {
        return if d >= 0 {
            "just now".to_owned()
        } else {
            "in under a minute".to_owned()
        };
    }
    let n = if a < 3600 {
        format!("{} min", a / 60)
    } else if a < 86_400 {
        format!("{} h", a / 3600)
    } else {
        format!("{} d", a / 86_400)
    };
    if d >= 0 {
        format!("{n} ago")
    } else {
        format!("in {n}")
    }
}

fn when(now: Timestamp, ts: Option<Timestamp>) -> String {
    ts.map_or_else(
        || "unknown".to_owned(),
        |t| format!("{} ({})", hms(t), age(now, t)),
    )
}

fn plain(s: impl Into<String>) -> Line<'static> {
    Line::from(s.into())
}

/// Draw the whole screen.
pub(crate) fn render(frame: &mut Frame<'_>, app: &App) {
    let theme = Theme {
        color: !app.no_color,
    };
    // ⟨M07⟩ Every frame is counted, this early so that one with no room for any view
    // counts too: a confirmation outside the decision modal's dispatch is accepted only
    // if the latest frame drew it (`Seen`), and such a frame draws none.
    let number = app.begin_frame();
    let area = frame.area();
    if area.width < 10 || area.height < 3 {
        frame.render_widget(Paragraph::new("terminal too small"), area);
        return;
    }
    // ⟨M07⟩ M07-W0-R03: a failed or stale read is said in a row of its own under the
    // header, outside every list, so no scrolling hides it.
    let notice = stale_notice(app, area.width < 60).filter(|_| area.height >= 5);
    let [header, notice_area, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(u16::from(notice.is_some())),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);
    render_header(frame, app, header, theme);
    if let Some(text) = notice {
        frame.render_widget(
            Paragraph::new(Line::styled(
                text,
                theme.fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
            notice_area,
        );
    }
    match &app.screen {
        Screen::Tab(Tab::Overview) => render_overview(frame, app, body, theme),
        Screen::Tab(Tab::Destinations) => render_destinations(frame, app, body, theme),
        Screen::Tab(Tab::Profiles) => render_profiles(frame, app, body, theme),
        Screen::Tab(Tab::Activity) => render_activity(frame, app, body, theme),
        // ⟨M07⟩ The new views.
        Screen::Tab(Tab::Projects) => render_scrolled(
            frame,
            body,
            super::m07::projects_lines(app.catalog(), app.now(), &read_when(app)),
            app.scroll,
        ),
        Screen::Tab(Tab::Environments) => render_environments(frame, app, body, theme),
        Screen::Tab(Tab::Identities) => render_identities(frame, app, body, theme),
        Screen::Tab(Tab::Settings) => render_settings(frame, app, number, body, theme),
        Screen::Environment(id) => render_scrolled(
            frame,
            body,
            super::m07::environment_lines(app.catalog(), id, &read_when(app)),
            app.scroll,
        ),
        Screen::Lock => render_scrolled(
            frame,
            body,
            super::m07::lock_screen_lines(app.catalog(), &read_when(app)),
            app.scroll,
        ),
        Screen::Identity(id) => {
            let checked = app
                .catalog()
                .identity(id)
                .map_or_else(|| "unknown".to_owned(), |i| when(app.now(), i.checked_at));
            render_scrolled(
                frame,
                body,
                super::m07::identity_lines(app.catalog(), id, &read_when(app), &checked, &|t| {
                    t.map_or_else(|| "?".to_owned(), full)
                }),
                app.scroll,
            );
        }
        Screen::Destination(alias) => {
            render_scrolled(
                frame,
                body,
                destination_lines(app, alias, theme),
                app.scroll,
            );
        }
        Screen::Profile(id) => render_scrolled(frame, body, profile_lines(app, id), app.scroll),
        Screen::Operation(id) => {
            render_scrolled(frame, body, operation_lines(app, id, theme), app.scroll);
        }
        Screen::Enrollment(id) => render_scrolled(
            frame,
            body,
            super::m03::enrollment_lines(app.catalog(), id),
            app.scroll,
        ),
        // ⟨M05⟩ The trusted-work views.
        Screen::Workspace => render_scrolled(
            frame,
            body,
            super::m05::workspace_lines(app.catalog(), app.now()),
            app.scroll,
        ),
        Screen::Policies => render_scrolled(
            frame,
            body,
            super::m05::policy_history_lines(app.catalog(), app.now()),
            app.scroll,
        ),
    }
    match &app.modal {
        // ⟨M07⟩ The stop menu's confirmation is drawn behind the reading guard, as a
        // Settings change is (M07-W0-R01); the shared modal dispatch draws the rest.
        Some(Modal::StopMenu(menu)) if let super::m05::StopPhase::Confirm(action) = &menu.phase => {
            render_stop_confirm(frame, number, body, menu, action, theme);
        }
        Some(modal) => render_modal(frame, app, modal, body, theme),
        None => {}
    }
    // After the modal: its footer hint reads what the modal's frame has just recorded.
    render_footer(frame, app, footer, theme);
}

/// The header: every tab when they fit (the current one bracketed), else ⟨M07⟩ the current
/// tab and its place among the eight (`[2 Destinations] 2/8`); then the health marker, and,
/// as room allows, how to pause or stop, the health in words and the name.
fn render_header(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let width = usize::from(area.width);
    let health = app.health();
    let words = format!(" {}", health.words());
    const STOP: &str = " - s stop";
    const NAME: &str = "Heimdall ";
    let marker = health.marker().len();
    let tabs_width: usize = Tab::ALL.iter().map(|t| t.title().len() + 4).sum();
    let mut spans = Vec::new();
    if tabs_width + 1 + marker <= width {
        let mut used = tabs_width + 1 + marker;
        let stop = used + STOP.len() <= width;
        used += if stop { STOP.len() } else { 0 };
        let show_words = used + words.len() <= width;
        used += if show_words { words.len() } else { 0 };
        if used + NAME.len() <= width {
            spans.push(Span::styled(NAME, theme.bold()));
        }
        for (i, tab) in Tab::ALL.iter().enumerate() {
            let label = format!("{} {}", i + 1, tab.title());
            if app.tab == *tab {
                spans.push(Span::styled(format!("[{label}]"), theme.selected()));
            } else {
                spans.push(Span::raw(format!(" {label} ")));
            }
        }
        spans.push(Span::raw(" "));
        spans.push(Span::styled(health.marker(), theme.health(health)));
        if show_words {
            spans.push(Span::styled(words, theme.health(health)));
        }
        if stop {
            spans.push(Span::styled(STOP, theme.dim()));
        }
    } else {
        let n = app.tab.index() + 1;
        let label = format!("[{n} {}]", app.tab.title());
        let place = format!(" {n}/{}", Tab::ALL.len());
        let used = label.len() + place.len() + 1 + marker;
        spans.push(Span::styled(label, theme.selected()));
        spans.push(Span::raw(place));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(health.marker(), theme.health(health)));
        if used + words.len() <= width {
            spans.push(Span::styled(words, theme.health(health)));
        } else if used + STOP.len() <= width {
            spans.push(Span::styled(STOP, theme.dim()));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// ⟨M07⟩ M07-W0-R03: the compact indicator of a failed or stale read, or `None` when
/// every listing shown was read in the latest refresh. It is drawn under the header on
/// every screen. It says which case holds, in words (the codes are in the views' own error
/// states):
/// * the connection failed, or the runtime stopped after listings were read: everything
///   shown is as it was last read, which it dates;
/// * one listing could not be read: which, and whether its last good data is shown
///   (stale) or nothing was ever read;
/// * several: how many.
fn stale_notice(app: &App, narrow: bool) -> Option<String> {
    use super::m07::subject_words;
    let c = app.catalog();
    // What is on screen was last read at the oldest of the failed listings' good reads.
    let last_good =
        c.failures
            .values()
            .filter_map(|f| f.stale_from)
            .min()
            .or(if c.failures.is_empty() {
                c.read_at
            } else {
                None
            });
    let disconnected = match app.runtime() {
        Runtime::Failed(_) => Some(("Not connected", "S reconnects")),
        Runtime::NotRunning if c.read_at.is_some() => Some(("The runtime stopped", "S starts it")),
        _ => None,
    };
    if let Some((what, key)) = disconnected {
        return Some(match (last_good, narrow) {
            (Some(t), false) => format!(
                "[!!] {what}: what is shown was read {} and may have changed · {key}",
                when(app.now(), Some(t))
            ),
            (Some(t), true) => format!(
                "[!!] {} · read {}",
                if matches!(app.runtime(), Runtime::Failed(_)) {
                    "not connected"
                } else {
                    "runtime stopped"
                },
                age(app.now(), t)
            ),
            (None, false) => {
                format!("[!!] {what}: nothing has been read from the runtime · {key}")
            }
            (None, true) => "[!!] not connected: nothing read".to_owned(),
        });
    }
    if app.runtime() != &Runtime::Connected {
        return None;
    }
    let failed: Vec<_> = c.failures.iter().collect();
    match failed.as_slice() {
        [] => None,
        [(name, f)] => {
            let words = subject_words(name);
            Some(match (f.stale_from, narrow) {
                (Some(t), false) => format!(
                    "[!!] Stale: the {words} could not be read; it is shown as read {}",
                    when(app.now(), Some(t))
                ),
                (Some(_), true) => format!("[!!] stale: {words}"),
                (None, false) => format!(
                    "[!!] Not read: the {words} could not be read; nothing is known from it"
                ),
                (None, true) => format!("[!!] not read: {words}"),
            })
        }
        many if narrow => Some(format!("[!!] {} lists stale or not read", many.len())),
        many => Some(format!(
            "[!!] {} lists could not be read ({}); what they show is stale or missing",
            many.len(),
            many.iter()
                .map(|(name, _)| subject_words(name))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// ⟨M07⟩ When the listings were read, for the new views' provenance lines.
fn read_when(app: &App) -> String {
    when(app.now(), app.catalog().read_at)
}

fn render_footer(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let text = match (&app.status, &app.modal) {
        (_, Some(_)) => modal_hint(app).to_owned(),
        (Some(s), None) => clean(s),
        (None, None) => footer_text(&screen_hints(app), area.width < 60),
    };
    frame.render_widget(Paragraph::new(Span::styled(text, theme.dim())), area);
}

/// ⟨M07⟩ One key hint of a footer: the keys it names and its words, wide and (when it is
/// kept on a narrow screen) narrow. `every_footer_and_help_key_is_bound` presses `keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hint {
    /// The keys the hint names.
    pub keys: &'static [Key],
    /// Its words on a wide screen.
    pub wide: &'static str,
    /// Its words on a narrow screen; `None`: left out there.
    pub narrow: Option<&'static str>,
}

const fn hint(keys: &'static [Key], wide: &'static str, narrow: Option<&'static str>) -> Hint {
    Hint { keys, wide, narrow }
}

const UP_DOWN: &[Key] = &[Key::Up, Key::Down];
const DIGITS: &[Key] = &[
    Key::Char('1'),
    Key::Char('2'),
    Key::Char('3'),
    Key::Char('4'),
    Key::Char('5'),
    Key::Char('6'),
    Key::Char('7'),
    Key::Char('8'),
];
const HELP: Hint = hint(&[Key::Char('?')], "? help", Some("? help"));
const QUIT: Hint = hint(&[Key::Char('q')], "q quit", Some("q quit"));
const BACK: Hint = hint(&[Key::Esc], "Esc back", Some("Esc back"));
const SCROLL: Hint = hint(UP_DOWN, "Up/Down scroll", None);
const MOVE: Hint = hint(UP_DOWN, "Up/Down move", None);
const SEARCH: Hint = hint(&[Key::Char('/')], "/ search", Some("/ search"));

/// ⟨M07⟩ The footer's key hints of the screen (no modal open).
pub(crate) fn screen_hints(app: &App) -> Vec<Hint> {
    if let Some(p) = &app.settings {
        return match p.phase {
            super::m07::SettingPhase::Choose => vec![
                hint(UP_DOWN, "Up/Down choose", None),
                hint(&[Key::Enter], "Enter select", Some("Enter select")),
                hint(&[Key::Esc], "Esc close", Some("Esc close")),
            ],
            super::m07::SettingPhase::Value => vec![
                hint(&[Key::Char('d')], "type the profile ID", None),
                hint(&[Key::Enter], "Enter next", Some("Enter next")),
                hint(&[Key::Esc], "Esc cancel", Some("Esc cancel")),
            ],
            super::m07::SettingPhase::Confirm(_) => {
                let mut out = Vec::new();
                // ⟨M07⟩ A confirmation that does not fit says how to read on.
                if p.seen.reading.scrollable() {
                    out.push(hint(
                        &[Key::PageDown, Key::PageUp],
                        "PgUp/PgDn read",
                        Some("PgDn read"),
                    ));
                }
                out.extend([
                    hint(
                        &[Key::Char('y'), Key::Enter],
                        "type yes, Enter",
                        Some("type yes, Enter"),
                    ),
                    hint(&[Key::Esc], "Esc cancel", Some("Esc cancel")),
                ]);
                out
            }
        };
    }
    let waiting = || super::m05::pending_decision(app.catalog(), app.now()).is_some();
    match &app.screen {
        Screen::Tab(Tab::Overview) => {
            let held = matches!(
                app.selection(Tab::Overview)
                    .and_then(|i| app.overview_items().get(i)),
                Some(Item::Held { .. })
            );
            let mut out = vec![hint(&[Key::Enter], "Enter open", Some("Enter open"))];
            if held {
                out.push(hint(&[Key::Char('r')], "r retry", None));
                out.push(hint(&[Key::Char('k')], "k keep", None));
            }
            out.extend([
                hint(&[Key::Char('s')], "s pause or stop", Some("s stop")),
                hint(&[Key::Char('R')], "R refresh", None),
                hint(DIGITS, "1-8 views", None),
                HELP,
                QUIT,
            ]);
            out
        }
        Screen::Tab(Tab::Destinations) => {
            // ⟨M07⟩ M07-W0-R11: scoped to a grouped finding's destinations, the way out
            // is named (and the narrow footer drops the search hint to keep `q`).
            let scoped = app.scope().is_some();
            let mut out = vec![
                if scoped {
                    hint(&[Key::Char('/')], "/ search", None)
                } else {
                    SEARCH
                },
                hint(&[Key::Enter], "Enter detail", Some("Enter open")),
            ];
            if scoped {
                out.push(hint(&[Key::Esc], "Esc all", Some("Esc all")));
            }
            out.extend([
                hint(&[Key::Char('c')], "c connect", None),
                hint(&[Key::Char('p')], "p probes", None),
                HELP,
                QUIT,
            ]);
            out
        }
        Screen::Tab(Tab::Profiles) => vec![
            SEARCH,
            hint(&[Key::Enter], "Enter detail", Some("Enter open")),
            HELP,
            QUIT,
        ],
        Screen::Tab(Tab::Activity) => vec![
            hint(&[Key::Enter], "Enter review", Some("Enter review")),
            HELP,
            QUIT,
        ],
        Screen::Tab(Tab::Projects) => {
            let mut out = Vec::new();
            if waiting() {
                out.push(hint(&[Key::Enter], "Enter decision", None));
            }
            out.extend([
                hint(&[Key::Char('w')], "w project", Some("w project")),
                hint(&[Key::Char('h')], "h history", Some("h history")),
                hint(&[Key::Char('s')], "s stop", None),
                SCROLL,
                HELP,
                QUIT,
            ]);
            out
        }
        Screen::Tab(Tab::Environments | Tab::Identities) => vec![
            hint(&[Key::Enter], "Enter detail", Some("Enter detail")),
            MOVE,
            HELP,
            QUIT,
        ],
        Screen::Tab(Tab::Settings) => vec![
            hint(&[Key::Enter], "Enter change", Some("Enter change")),
            MOVE,
            HELP,
            QUIT,
        ],
        Screen::Destination(_) => vec![
            hint(&[Key::Char('c')], "c connect", Some("c connect")),
            hint(&[Key::Char('p')], "p probes", Some("p probes")),
            SCROLL,
            BACK,
        ],
        Screen::Profile(_)
        | Screen::Enrollment(_)
        | Screen::Environment(_)
        | Screen::Lock
        | Screen::Identity(_) => vec![
            hint(UP_DOWN, "Up/Down scroll", Some("Up/Down scroll")),
            BACK,
        ],
        Screen::Operation(id) => {
            let op = app
                .catalog()
                .operations
                .iter()
                .find(|o| &o.id == id)
                .or_else(|| {
                    app.operation
                        .as_ref()
                        .and_then(|(_, d)| d.operation.as_ref())
                });
            let mut out = Vec::new();
            if op.is_some_and(super::data::Operation::is_held) {
                out.push(hint(&[Key::Char('r')], "r retry", Some("r retry")));
                out.push(hint(&[Key::Char('k')], "k keep", Some("k keep")));
            }
            if op.is_some_and(super::data::Operation::is_active) {
                out.push(hint(&[Key::Char('x')], "x cancel", Some("x cancel")));
            }
            if app
                .catalog()
                .decisions
                .iter()
                .any(|d| d.operation().as_deref() == Some(id.as_str()))
            {
                out.push(hint(
                    &[Key::Enter],
                    "Enter decision",
                    Some("Enter decision"),
                ));
            }
            out.extend([SCROLL, BACK]);
            out
        }
        Screen::Workspace => {
            let mut out = Vec::new();
            if waiting() {
                out.push(hint(
                    &[Key::Enter],
                    "Enter decision",
                    Some("Enter decision"),
                ));
            }
            out.extend([
                hint(&[Key::Char('s')], "s stop menu", Some("s stop")),
                hint(&[Key::Char('h')], "h history", None),
                BACK,
            ]);
            out
        }
        Screen::Policies => vec![
            SCROLL,
            hint(&[Key::Char('s')], "s stop menu", Some("s stop")),
            BACK,
        ],
    }
}

/// The footer's text: the hints joined, wide or narrow.
pub(crate) fn footer_text(hints: &[Hint], narrow: bool) -> String {
    hints
        .iter()
        .filter_map(|h| if narrow { h.narrow } else { Some(h.wide) })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// The footer while a modal is open. A confirmation whose content does not fit says how
/// to read on, and after a refused `yes` that the end has to be shown first.
fn modal_hint(app: &App) -> &'static str {
    let reading = match &app.modal {
        Some(Modal::Decision(p)) => Some(&p.reading),
        Some(Modal::Authorization(p)) => Some(&p.reading),
        Some(Modal::Repair(p)) => Some(&p.reading),
        _ => None,
    };
    let (refused, scrollable) = reading.map_or((false, false), |r| (r.refused, r.scrollable()));
    match &app.modal {
        _ if refused => "Read to the end first (PgDn, End) · Esc",
        Some(Modal::Decision(_) | Modal::Authorization(_) | Modal::Repair(_)) if scrollable => {
            "Up/Down PgUp/PgDn Home/End · Esc cancel"
        }
        Some(Modal::Decision(_)) => "type yes, Enter · Tab approve/deny · Esc cancel",
        Some(Modal::Authorization(_) | Modal::Repair(_)) => "type yes, Enter · Esc cancel",
        Some(Modal::ProbeMenu { .. }) => "Up/Down choose · Enter run · Esc close",
        Some(Modal::Probe(_)) => "Up/Down scroll · Esc close",
        Some(Modal::StopMenu(m)) => match m.phase {
            super::m05::StopPhase::Choose => "Up/Down or 1-4 choose · Enter select · Esc close",
            super::m05::StopPhase::Value => "type the value · Enter next · Esc cancel",
            // ⟨M07⟩ A refused yes says why here (the status line is under the menu); a
            // confirmation that does not fit says how to read on.
            super::m05::StopPhase::Confirm(_) => match m.seen.refusal() {
                Some(why) => why,
                None if m.seen.shown(app.frame()) == Shown::TooSmall => {
                    "enlarge the terminal · Esc cancel"
                }
                None if m.seen.reading.scrollable() => "PgDn read · type yes, Enter · Esc cancel",
                None => "type yes, Enter · Esc cancel",
            },
        },
        Some(Modal::Help) | None => "any key closes",
    }
}

/// ⟨M07⟩ Draw `header` then `rows` rows into `area`, keeping row `selected` visible,
/// building only the lines that fit (`row(i)` builds row `i`): the per-frame work does
/// not grow with the list (m07-plan U1, probe P2). The window keeps the selected line on
/// the last row once it is past the first screenful.
fn render_window(
    frame: &mut Frame<'_>,
    area: Rect,
    header: Vec<Line<'static>>,
    rows: usize,
    selected: Option<usize>,
    mut row: impl FnMut(usize) -> Line<'static>,
) {
    let height = usize::from(area.height.max(1));
    let first = (header.len() + selected.unwrap_or(0)).saturating_sub(height - 1);
    let total = header.len() + rows;
    let header_len = header.len();
    let mut header = header.into_iter().skip(first);
    let lines: Vec<Line<'static>> = (first..total.min(first + height))
        .map(|i| {
            if i < header_len {
                header.next().unwrap_or_default()
            } else {
                row(i - header_len)
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_scrolled(frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>, scroll: u16) {
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
}

fn row(selected: bool, theme: Theme, mut spans: Vec<Span<'static>>) -> Line<'static> {
    let prefix = if selected { "> " } else { "  " };
    spans.insert(0, Span::raw(prefix));
    let line = Line::from(spans);
    if selected {
        line.style(theme.selected())
    } else {
        line
    }
}

// ---- overview ------------------------------------------------------------------------

fn runtime_line(app: &App) -> String {
    match app.runtime() {
        Runtime::Connecting => "Runtime: connecting".to_owned(),
        // ⟨M07⟩ M07-W0-R03: a refresh whose reads failed did not read the listings.
        Runtime::Connected if !app.catalog().failures.is_empty() => format!(
            "Runtime: connected; {} of its lists could not be read at the last refresh, {}",
            app.catalog().failures.len(),
            when(app.now(), app.catalog().read_at)
        ),
        Runtime::Connected if app.catalog().read_at.is_none() => {
            "Runtime: connected; reading its lists".to_owned()
        }
        Runtime::Connected => format!(
            "Runtime: connected; listings read {}",
            when(app.now(), app.catalog().read_at)
        ),
        Runtime::NotRunning => {
            "Runtime: not running (ordinary ssh still works; S starts it)".to_owned()
        }
        Runtime::Failed(m) => format!("Runtime: unavailable: {}", clean(m)),
    }
}

fn item_marker(item: &Item) -> &'static str {
    match item {
        Item::Working { .. } => "[..]",
        Item::Warning { .. }
        | Item::Findings { problem: false, .. }
        | Item::ListingFailed { .. }
        | Item::LateWrite { .. }
        | Item::ProjectionPending { .. } => "[ !]",
        Item::SlotFree { .. } => "[ i]",
        _ => "[!!]",
    }
}

/// ⟨M07⟩ An enrollment's state on the overview: a one-word state as it is (`is held`),
/// a coded one in words.
fn enrollment_state_text(id: &str, state: &str) -> String {
    if state.contains('_') {
        format!("enrollment {id}: {}", super::m03::state_class(state).1)
    } else {
        format!("enrollment {id} is {state}")
    }
}

/// An overview row's text. ⟨M07⟩ U2: in everyday words (spec §5.1): a decision's or an
/// operation's kind and a state read as words, and a finding shows its message; the codes
/// stay in the detail views. The one code left is the time chore's, which
/// tests/e2e/tui_m03.rs pins on the overview.
fn item_text(item: &Item) -> String {
    use super::m07::{kind_words, operation_words, state_words};
    match item {
        Item::Held { op, kind } => format!(
            "held: {} {op} is held for you (a file it manages changed; nothing was moved). r retry · k keep",
            operation_words(kind)
        ),
        Item::Decision { id, kind } => format!(
            "decision waiting: {} ({id}; Enter to review)",
            kind_words(kind)
        ),
        Item::Unresolved { op, kind } => format!(
            "unresolved: {} {op} (outcome unknown)",
            operation_words(kind)
        ),
        Item::Problem { alias, message, .. } | Item::Warning { alias, message, .. } => {
            match alias {
                Some(a) => format!("{a}: {message}"),
                None => message.clone(),
            }
        }
        Item::Working { op, kind, state } => format!(
            "working: {} {op} {}",
            operation_words(kind),
            state_words(state)
        ),
        Item::Chore { line } => line.clone(),
        Item::Enrollment { id, state } => format!(
            "{} (Enter for its reason and next step)",
            enrollment_state_text(id, state)
        ),
        Item::LateWrite { id } => format!(
            "enrollment {id} may have a late write (Enter for the residual and its command)"
        ),
        Item::ProjectionPending { alias } => format!(
            "{alias}: run `{}` (its managed setup is not applied yet)",
            super::m03::SETUP_APPLY_COMMAND
        ),
        Item::SlotFree { alias } => super::m03::slot_free_line(alias),
        // ⟨M07⟩ Grouped: the count first, so narrow rows stay distinct (probe P4).
        Item::Findings { aliases, .. } => match aliases.as_slice() {
            [one] => format!("{one}: {}", finding_words(item)),
            many => format!(
                "{} destinations: {} (Enter: which ones)",
                many.len(),
                finding_words(item)
            ),
        },
        // ⟨M07⟩ M07-W0-R03: whether stale data is shown, or nothing was ever read.
        Item::ListingFailed { subject, stale, .. } => format!(
            "the {} could not be read (Enter for why; {})",
            super::m07::subject_words(subject),
            if *stale {
                "the last good one is shown, stale"
            } else {
                "nothing was read from it yet"
            }
        ),
    }
}

/// ⟨M07⟩ M07-W0-R11: what a grouped finding says. When every finding of the group says
/// the same thing, those words (the doctor's own); when they differ, the finding itself
/// in words, never the first one's message as if it held for all.
pub(crate) fn finding_words(item: &Item) -> String {
    match item {
        Item::Findings { message, mixed, .. } if !mixed => message.clone(),
        Item::Findings { code, .. } => {
            format!("{} (the details differ for each)", super::m07::spaced(code))
        }
        other => item_text(other),
    }
}

/// ⟨M07⟩ An overview row on a narrow screen: what tells it apart (its ID, alias or
/// count) first, so no two rows truncate to the same text (probe P4). Rows whose wide
/// text already starts that way keep it.
fn item_text_narrow(item: &Item) -> String {
    use super::m07::{kind_words, operation_words, state_words};
    match item {
        Item::Held { op, .. } => format!("held {op}: r retry · k keep"),
        Item::Decision { id, kind } => format!("decision {id}: {}", kind_words(kind)),
        Item::Unresolved { op, kind } => format!("unresolved {op}: {}", operation_words(kind)),
        Item::Working { op, kind, state } => format!(
            "working {op}: {} {}",
            operation_words(kind),
            state_words(state)
        ),
        Item::LateWrite { id } => format!("enrollment {id}: may have a late write"),
        Item::ProjectionPending { alias } => format!("{alias}: setup not applied"),
        Item::SlotFree { alias } => format!("{alias}: slot free"),
        Item::ListingFailed { subject, .. } => {
            format!("{}: not read", super::m07::subject_words(subject))
        }
        _ => item_text(item),
    }
}

fn item_style(item: &Item, theme: Theme) -> Style {
    match item {
        Item::Working { .. } => theme.fg(Color::Yellow),
        Item::Warning { .. }
        | Item::Findings { problem: false, .. }
        | Item::ListingFailed { .. }
        | Item::LateWrite { .. }
        | Item::ProjectionPending { .. } => theme.fg(Color::Magenta),
        Item::SlotFree { .. } => theme.fg(Color::Blue),
        _ => theme.fg(Color::Red),
    }
}

fn render_overview(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let health = app.health();
    let items = app.overview_items();
    let narrow = area.width < 60;
    let mut lines = vec![Line::from(vec![
        Span::styled(
            health.marker(),
            theme.health(health).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(health.words(), theme.bold()),
    ])];
    lines.push(plain(if narrow {
        match app.runtime() {
            Runtime::Connected if !app.catalog().failures.is_empty() => format!(
                "Runtime: connected, {} list(s) unread",
                app.catalog().failures.len()
            ),
            Runtime::Connected => format!(
                "Runtime: connected, read {}",
                app.catalog()
                    .read_at
                    .map_or_else(|| "not yet".to_owned(), |t| age(app.now(), t))
            ),
            Runtime::Connecting => "Runtime: connecting".to_owned(),
            Runtime::NotRunning => "Runtime: not running (S starts it)".to_owned(),
            Runtime::Failed(_) => "Runtime: unavailable (S retries)".to_owned(),
        }
    } else {
        runtime_line(app)
    }));
    lines.push(plain(match (app.doctor(), narrow) {
        (Some(d), true) => format!("Static pass: {}", age(app.now(), d.taken_at)),
        (Some(d), false) => format!(
            "Static pass: {}; {} destinations, {} profiles, {} identities",
            when(app.now(), Some(d.taken_at)),
            app.catalog().destinations.len(),
            app.catalog().profiles.len(),
            app.catalog().identities.len()
        ),
        (None, true) => "Static pass: running".to_owned(),
        (None, false) => {
            "Static pass: running (reads your configuration; executes nothing)".to_owned()
        }
    }));
    // ⟨M05⟩ The working directory's workspace, when the runtime serves it.
    // ⟨M07⟩ M07-W0-R03: marked stale when its latest read failed.
    if let Some(line) = super::m05::overview_line(app.catalog(), narrow) {
        let known = app.catalog().known(&[super::data::subject::WORKSPACE]);
        lines.push(plain(format!("{line}{}", known.suffix())));
    }
    // ⟨M07⟩ Spec §12.1 and A30: this environment and its active work, which environment
    // has access, whether work continues while the desktop is locked, how to pause or stop.
    if app.runtime() == &Runtime::Connected {
        lines.push(plain(super::m07::environment_line(app.catalog(), narrow)));
        lines.push(plain(super::m07::access_line(
            app.catalog(),
            app.now(),
            narrow,
        )));
        lines.push(plain(super::m07::lock_line(app.catalog(), narrow)));
    }
    if !narrow || app.runtime() != &Runtime::Connected {
        lines.push(plain(super::m07::stop_line(narrow)));
    }
    let selected = app.selection(Tab::Overview);
    if items.is_empty() {
        // ⟨M07⟩ M07-W0-R03: "nothing" is said only of lists that were read.
        let read = app.runtime() == &Runtime::Connected && app.catalog().read_at.is_some();
        lines.push(plain(match (app.reads_unknown(), read, narrow) {
            (true, _, false) => {
                "  What needs you is not known: the runtime's lists could not be read."
            }
            (true, _, true) => "  Not known: the lists were not read.",
            (false, true, _) => "  Nothing needs you; nothing is running.",
            (false, false, false) => {
                "  Nothing is read from the runtime yet: what needs you there is not known."
            }
            (false, false, true) => "  Not known yet: nothing read so far.",
        }));
    }
    let mut tail = Vec::new();
    if !narrow && let Some(Item::Held { .. }) = selected.and_then(|i| items.get(i)) {
        tail.push(plain(""));
        tail.push(plain(format!(
            "  r {}",
            super::model::HeldRepair::Retry.sentence()
        )));
        tail.push(plain(format!(
            "  k {}",
            super::model::HeldRepair::Keep.sentence()
        )));
    }
    // ⟨M07⟩ M07-W0-R06: only the rows in the window are built (the items can be as many
    // as the destinations: one per pending projection or free slot).
    let sections = vec![Section {
        head: lines,
        rows: items.len(),
    }];
    render_sections(frame, area, sections, tail, selected, |i| {
        let Some(item) = items.get(i) else {
            return Line::default();
        };
        row(
            selected == Some(i),
            theme,
            vec![
                Span::styled(item_marker(item), item_style(item, theme)),
                Span::raw(" "),
                Span::raw(if narrow {
                    item_text_narrow(item)
                } else {
                    item_text(item)
                }),
            ],
        )
    });
}

// ---- lists ---------------------------------------------------------------------------

fn search_line(app: &App, tab: Tab, shown: usize, total: usize, stale: bool) -> Line<'static> {
    let total = if stale {
        format!("{total} (stale)")
    } else {
        total.to_string()
    };
    // ⟨M07⟩ M07-W0-R11: scoped to one grouped finding's destinations (counts and the way
    // out first, so a narrow row keeps them).
    if tab == Tab::Destinations
        && let Some(scope) = app.scope()
    {
        let search = match app.search(tab) {
            Some(s) if s.editing => format!(" · search: {}_", s.text),
            Some(s) if !s.text.is_empty() => format!(" · filter: {}", s.text),
            _ => String::new(),
        };
        return plain(format!(
            "Finding: {shown} of {total} · Esc all{search} · {}",
            scope.label
        ));
    }
    match app.search(tab) {
        Some(s) if s.editing => plain(format!("Search: {}_  ({shown} of {total})", s.text)),
        Some(s) if !s.text.is_empty() => plain(format!(
            "Filter: {}  ({shown} of {total}; / edits, Esc in search clears)",
            s.text
        )),
        _ => plain(format!("{total} total · / to search (never probes)")),
    }
}

/// ⟨M07⟩ The error state of a listing whose last read failed (Q4): its code and message,
/// and whether what is shown is the last good data (stale) or nothing was ever read.
/// Never the empty-state text.
fn failure_lines(
    app: &App,
    what: &str,
    f: &super::data::ListingFailure,
    width: u16,
    theme: Theme,
) -> Vec<Line<'static>> {
    let marker = Span::styled("[!!]", theme.fg(Color::Red));
    let mut lines = if width < 60 {
        // Narrow: the code on its own row, so it is never cut.
        vec![
            Line::from(vec![marker, Span::raw(format!(" {what} listing failed"))]),
            plain(format!("  {}", f.code)),
        ]
    } else {
        vec![Line::from(vec![
            marker,
            Span::raw(format!(" {what} listing failed: {}", f.code)),
        ])]
    };
    lines.extend([
        plain(format!("  {}", f.message)),
        plain(match f.stale_from {
            Some(t) => format!(
                "  stale: showing the last good listing, read {}; failing since {}",
                when(app.now(), Some(t)),
                when(app.now(), Some(f.since))
            ),
            None => format!(
                "  nothing listed yet: no read has succeeded; failing since {}",
                when(app.now(), Some(f.since))
            ),
        }),
    ]);
    lines
}

fn render_destinations(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let failure = app.catalog().failure(super::data::subject::DESTINATIONS);
    let shown = app.shown(Tab::Destinations);
    let mut header = vec![search_line(
        app,
        Tab::Destinations,
        shown,
        app.catalog().destinations.len(),
        failure.is_some_and(|f| f.stale_from.is_some()),
    )];
    if let Some(f) = failure {
        header.extend(failure_lines(app, "destination", f, area.width, theme));
    } else if app.catalog().destinations.is_empty() {
        header.push(plain(match app.runtime() {
            Runtime::Connected => "  No catalog destinations.",
            _ => "  The catalog is read from the runtime (S starts it).",
        }));
    }
    let selected = app.selection(Tab::Destinations);
    render_window(frame, area, header, shown, selected, |i| {
        let Some(d) = app.visible_destination(i) else {
            return Line::default();
        };
        let (problems, warnings) = app.alias_findings(&d.alias);
        let marker = if problems > 0 {
            "[!!]"
        } else if warnings > 0 {
            "[ !]"
        } else {
            "[OK]"
        };
        let target = if d.is_managed() {
            format!(
                "managed  {}:{} as {}",
                d.hostname.as_deref().unwrap_or("?"),
                d.port.as_deref().unwrap_or("22"),
                d.account.as_deref().unwrap_or("?")
            )
        } else {
            "observed (defined in your configuration)".to_owned()
        };
        row(
            selected == Some(i),
            theme,
            vec![
                Span::styled(
                    marker,
                    theme.fg(if problems > 0 {
                        Color::Red
                    } else if warnings > 0 {
                        Color::Magenta
                    } else {
                        Color::Green
                    }),
                ),
                Span::raw(format!(" {:<12} {target}", d.alias)),
            ],
        )
    });
}

fn render_profiles(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let failure = app.catalog().failure(super::data::subject::PROFILES);
    let shown = app.shown(Tab::Profiles);
    let mut header = vec![search_line(
        app,
        Tab::Profiles,
        shown,
        app.catalog().profiles.len(),
        failure.is_some_and(|f| f.stale_from.is_some()),
    )];
    if let Some(f) = failure {
        header.extend(failure_lines(app, "profile", f, area.width, theme));
    } else if app.catalog().profiles.is_empty() {
        header.push(plain("  No profiles."));
    }
    let selected = app.selection(Tab::Profiles);
    render_window(frame, area, header, shown, selected, |i| {
        let Some(p) = app.visible_profile(i) else {
            return Line::default();
        };
        row(
            selected == Some(i),
            theme,
            vec![Span::raw(format!(
                "{:<12} {}  {} pair(s)  rev {}",
                p.id,
                p.label.as_deref().unwrap_or(""),
                p.pairs.len(),
                p.revision.as_deref().unwrap_or("?")
            ))],
        )
    });
}

/// ⟨M07⟩ One section of a sectioned list: its heading lines, then `rows` rows.
struct Section {
    head: Vec<Line<'static>>,
    rows: usize,
}

/// ⟨M07⟩ M07-W0-R06: draw `sections` (each its heading lines, then its rows; rows are
/// numbered through the sections) and then `tail` into `area`, keeping row `selected`
/// visible. Only the lines inside the window are built (`row(i)` builds row `i`), so a
/// frame costs the window's height and the number of sections, whatever the rows' number.
/// The window keeps the selected line on its last row once it is past the first
/// screenful (as [`render_window`] does).
fn render_sections(
    frame: &mut Frame<'_>,
    area: Rect,
    sections: Vec<Section>,
    tail: Vec<Line<'static>>,
    selected: Option<usize>,
    mut row: impl FnMut(usize) -> Line<'static>,
) {
    let height = usize::from(area.height.max(1));
    // The line the selected row is on.
    let (mut line, mut first_row, mut sel_line) = (0, 0, 0);
    for s in &sections {
        if let Some(sel) = selected
            && (first_row..first_row + s.rows).contains(&sel)
        {
            sel_line = line + s.head.len() + (sel - first_row);
        }
        line += s.head.len() + s.rows;
        first_row += s.rows;
    }
    let first = sel_line.saturating_sub(height - 1);
    let window = first..first + height;
    let mut out = Vec::with_capacity(height);
    let (mut line, mut first_row) = (0, 0);
    for s in sections {
        for h in s.head {
            if window.contains(&line) {
                out.push(h);
            }
            line += 1;
        }
        for at in window.start.max(line)..window.end.min(line + s.rows) {
            out.push(row(first_row + (at - line)));
        }
        line += s.rows;
        first_row += s.rows;
    }
    for t in tail {
        if window.contains(&line) {
            out.push(t);
        }
        line += 1;
    }
    frame.render_widget(Paragraph::new(out), area);
}

/// The Activity view: pending decisions, operations, enrollment records. ⟨M07⟩
/// M07-W0-R06: each row is read from its listing by index and only the visible rows are
/// built ([`render_sections`]); nothing here grows with the lists.
fn render_activity(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    use super::data::subject;
    let c = app.catalog();
    let (decisions, operations, enrollments) = app.activity_counts();
    let selected = app.selection(Tab::Activity);
    // ⟨M07⟩ A failed read shows its error, never "none" (Q4).
    let failed = |what: &str, name: &str| {
        c.failure(name)
            .map(|f| failure_lines(app, what, f, area.width, theme))
    };
    let mut sections = Vec::new();
    let mut head = vec![Line::styled("Pending decisions", theme.bold())];
    match failed("decision", subject::DECISIONS) {
        Some(lines) => head.extend(lines),
        None if decisions == 0 => head.push(plain("  none")),
        None => {}
    }
    sections.push(Section {
        head,
        rows: decisions,
    });
    let mut head = vec![Line::styled("Operations", theme.bold())];
    match failed("operation", subject::OPERATIONS) {
        Some(lines) => head.extend(lines),
        None if operations == 0 => head.push(plain("  none open")),
        None => {}
    }
    sections.push(Section {
        head,
        rows: operations,
    });
    let enrollments_failed = failed("enrollment", subject::ENROLLMENTS);
    if enrollments > 0 || enrollments_failed.is_some() {
        let mut head = vec![Line::styled("Enrollments", theme.bold())];
        head.extend(enrollments_failed.unwrap_or_default());
        sections.push(Section {
            head,
            rows: enrollments,
        });
    }
    render_sections(frame, area, sections, Vec::new(), selected, |i| {
        let spans = match app.activity_row(i) {
            Some(ActivityRow::Enrollment(at)) => {
                let e = c.m03.enrollments.get(at);
                let (marker, _) = e.map_or(("[??]", ""), |e| super::m03::state_class(&e.state));
                vec![
                    Span::styled(marker, theme.fg(Color::Red)),
                    Span::raw(e.map_or_else(String::new, |e| super::m03::enrollment_row(c, e))),
                ]
            }
            Some(ActivityRow::Decision(at)) => {
                let d = c.decisions.get(at);
                let expiry = d.and_then(|d| d.expires_at).map_or_else(String::new, |t| {
                    format!("  expires {} ({})", hms(t), age(app.now(), t))
                });
                let expired =
                    d.is_some_and(|d| d.expired || d.expires_at.is_some_and(|t| t <= app.now()));
                vec![
                    Span::styled(if expired { "[--]" } else { "[!!]" }, theme.fg(Color::Red)),
                    Span::raw(format!(
                        " {}  {}{expiry}{}",
                        d.map_or("?", |d| d.id.as_str()),
                        d.map_or("?", |d| d.kind.as_str()),
                        if expired { " (expired)" } else { "" }
                    )),
                ]
            }
            Some(ActivityRow::Operation(at)) => {
                let o = c.operations.get(at);
                let (marker, color) = match o {
                    Some(o) if o.is_held() || o.is_unresolved() => ("[!!]", Color::Red),
                    Some(o) if o.is_active() => ("[..]", Color::Yellow),
                    _ => ("[--]", Color::Gray),
                };
                vec![
                    Span::styled(marker, theme.fg(color)),
                    Span::raw(format!(
                        " {}  {}  {}{}",
                        o.map_or("?", |o| o.id.as_str()),
                        o.map_or("?", |o| o.kind.as_str()),
                        o.map_or("?", |o| o.state.as_str()),
                        if o.is_some_and(super::data::Operation::is_held) {
                            " (held)"
                        } else {
                            ""
                        }
                    )),
                ]
            }
            None => Vec::new(),
        };
        row(selected == Some(i), theme, spans)
    });
}

// ---- ⟨M07⟩ environments, identities, settings ----------------------------------------

fn marker_style(marker: &str, theme: Theme) -> Style {
    theme.fg(match marker {
        "[OK]" => Color::Green,
        "[!!]" => Color::Red,
        "[ !]" => Color::Magenta,
        "[..]" => Color::Yellow,
        _ => Color::Blue,
    })
}

fn render_environments(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let envs = &app.catalog().environments;
    let failure = app.catalog().failure(super::data::subject::ENVIRONMENTS);
    let mut header = vec![plain(format!(
        "{} environment(s) the runtime knows, its own first · Enter for detail",
        envs.items.len()
    ))];
    if let Some(f) = failure {
        header.extend(failure_lines(app, "environment", f, area.width, theme));
    } else if envs.items.is_empty() {
        header.push(plain(match app.runtime() {
            Runtime::Connected => "  No environments listed.",
            _ => "  Environments are read from the runtime (S starts it).",
        }));
    }
    let selected = app.selection(Tab::Environments);
    render_window(frame, area, header, envs.items.len(), selected, |i| {
        let Some(e) = envs.items.get(i) else {
            return Line::default();
        };
        let (marker, text) = super::m07::environment_row(envs, e);
        row(
            selected == Some(i),
            theme,
            vec![
                Span::styled(marker, marker_style(marker, theme)),
                Span::raw(format!(" {text}")),
            ],
        )
    });
}

fn render_identities(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let identities = &app.catalog().identities;
    let failure = app.catalog().failure(super::data::subject::IDENTITIES);
    let mut header = vec![plain(format!(
        "{} adopted identit{} · Enter for detail",
        identities.len(),
        if identities.len() == 1 { "y" } else { "ies" }
    ))];
    if let Some(f) = failure {
        header.extend(failure_lines(app, "identity", f, area.width, theme));
    } else if identities.is_empty() {
        header.push(plain(match app.runtime() {
            Runtime::Connected => "  No adopted identities.",
            _ => "  Identities are read from the runtime (S starts it).",
        }));
    }
    let selected = app.selection(Tab::Identities);
    render_window(frame, area, header, identities.len(), selected, |i| {
        let Some(id) = identities.get(i) else {
            return Line::default();
        };
        let (marker, text) = super::m07::identity_row(id);
        row(
            selected == Some(i),
            theme,
            vec![
                Span::styled(marker, marker_style(marker, theme)),
                Span::raw(format!(" {text}")),
            ],
        )
    });
}

/// The Settings view. ⟨M07⟩ M07-W0-R06: the rows are the model's cached ones
/// (`App::setting_rows`, built once per change of the listings; a connection row is its
/// destination's index, so no row is looked up by alias), the sections' sizes come from
/// the few rows before the lock row, and only the visible rows are built.
fn render_settings(frame: &mut Frame<'_>, app: &App, number: u64, area: Rect, theme: Theme) {
    use super::data::subject;
    use super::m07::{SettingPhase, SettingRow, unread_note};
    let catalog = app.catalog();
    let rows = app.setting_rows();
    let selected = app.selection(Tab::Settings);
    // The rows come in sections: default profiles, standing access, the lock row, then
    // one row per managed destination.
    let defaults = rows
        .iter()
        .take_while(|r| matches!(r, SettingRow::DefaultProfile { .. }))
        .count();
    let policies = rows[defaults..]
        .iter()
        .take_while(|r| matches!(r, SettingRow::Policy { .. }))
        .count();
    let lock = usize::from(rows.get(defaults + policies) == Some(&SettingRow::Lock));
    let connections = rows.len() - defaults - policies - lock;
    let heading = |text: &'static str, blank: bool| {
        let mut head = Vec::new();
        if blank {
            head.push(plain(""));
        }
        head.push(Line::styled(text, theme.bold()));
        head
    };
    let mut sections = vec![Section {
        head: heading("Default profile (a preference, never authority)", false),
        rows: defaults,
    }];
    // No policy rows: the standing-access heading still says why (M07-W0-R03: "none"
    // only of a list that was read).
    let mut head = heading(
        "Standing access: pause, resume, lock behaviour, connections",
        true,
    );
    if policies == 0 {
        head.push(plain(
            match (
                unread_note(catalog, subject::POLICIES),
                &catalog.m05.policies,
            ) {
                (Some(why), _) => format!("  {why}"),
                (None, None) => "  not listed by this runtime".to_owned(),
                (None, Some(_)) => "  none".to_owned(),
            },
        ));
    }
    sections.push(Section {
        head,
        rows: policies,
    });
    sections.push(Section {
        head: heading("When your desktop locks", true),
        rows: lock,
    });
    let mut head = heading(
        "Connections at the deadline (each managed destination)",
        true,
    );
    if connections == 0 {
        head.push(plain(match unread_note(catalog, subject::DESTINATIONS) {
            Some(why) => format!("  {why}"),
            None => "  no managed destinations".to_owned(),
        }));
    }
    sections.push(Section {
        head,
        rows: connections,
    });
    let draw_list = |frame: &mut Frame<'_>, area: Rect, tail: Vec<Line<'static>>| {
        render_sections(frame, area, sections, tail, selected, |i| {
            let Some(r) = rows.get(i) else {
                return Line::default();
            };
            let (marker, text) = super::m07::setting_row(catalog, app.now(), r);
            row(
                selected == Some(i),
                theme,
                vec![
                    Span::styled(marker, marker_style(marker, theme)),
                    Span::raw(format!(" {text}")),
                ],
            )
        });
    };
    match &app.settings {
        // ⟨M07⟩ M07-W0-R01: the confirmation, behind the reading guard.
        Some(prompt) if let SettingPhase::Confirm(action) = &prompt.phase => {
            let confirm = Guarded {
                title: "Change a setting",
                content: super::m07::confirm_lines(app.catalog(), app.now(), action),
                ask: super::m07::confirm_ask(&prompt.input),
                ask_full: super::m07::confirm_ask(&full_answer()),
                seen: &prompt.seen,
                covered: app.modal.is_some(),
                too_small: SETTING_TOO_SMALL,
                width: area.width,
            };
            // The box sits under the list, which keeps the rows above it.
            let place = |frame: &mut Frame<'_>, height: u16| {
                let [list_area, box_area] =
                    Layout::vertical([Constraint::Min(0), Constraint::Length(height)]).areas(area);
                draw_list(frame, list_area, Vec::new());
                box_area
            };
            render_guarded_confirm(frame, number, area, confirm, place, theme);
        }
        Some(prompt) => {
            let content = super::m07::prompt_lines(prompt);
            let inner = area.width.saturating_sub(2).max(1);
            let want = wrapped_rows(&content, inner).saturating_add(2);
            let height = want
                .min(area.height.saturating_sub(1).max(3))
                .min(area.height);
            let [list_area, prompt_area] =
                Layout::vertical([Constraint::Min(0), Constraint::Length(height)]).areas(area);
            draw_list(frame, list_area, Vec::new());
            frame.render_widget(Clear, prompt_area);
            let block = Block::new()
                .borders(Borders::ALL)
                .title(Span::styled("Change a setting", theme.bold()));
            let inner_area = block.inner(prompt_area);
            frame.render_widget(block, prompt_area);
            // A prompt that does not fit keeps on screen the change being chosen, or
            // the line being typed (it loses its top rows).
            let through = match prompt.phase {
                SettingPhase::Choose => (prompt.selected + 2).min(content.len()),
                _ => content.len(),
            };
            let rows_needed = wrapped_rows(&content[..through], inner);
            let scroll = rows_needed.saturating_sub(inner_area.height);
            frame.render_widget(
                Paragraph::new(content)
                    .wrap(Wrap { trim: false })
                    .scroll((scroll, 0)),
                inner_area,
            );
        }
        None => {
            // The selected row's detail, under the list.
            let mut tail = Vec::new();
            if let Some(r) = selected.and_then(|i| rows.get(i)) {
                tail.push(plain(""));
                tail.extend(wrap_lines(
                    &super::m07::setting_detail(catalog, r, &read_when(app)),
                    usize::from(area.width.max(1)),
                ));
            }
            draw_list(frame, area, tail);
        }
    }
}

/// ⟨M07⟩ What the Settings confirmation says when the terminal cannot show it.
const SETTING_TOO_SMALL: &str =
    "[!!] Too small to show this change. Enlarge the terminal: nothing is sent. Esc cancels.";

/// ⟨M07⟩ What the stop menu's confirmation says when the terminal cannot show it.
const STOP_TOO_SMALL: &str =
    "[!!] Too small to show this action. Enlarge the terminal: nothing is sent. Esc cancels.";

/// ⟨M07⟩ A typed confirmation behind the reading guard, before layout (M07-W0-R01): a
/// Settings change, or a pause, a stop or a cutoff of the stop menu.
struct Guarded<'a> {
    /// The box's title.
    title: &'static str,
    /// What is confirmed, one logical line per entry: the action, its exact effect and
    /// its target.
    content: Vec<Line<'static>>,
    /// The fixed prompt line with what was typed.
    ask: Line<'static>,
    /// The prompt line with the longest answer typed, so its rows, and the room left for
    /// the content, do not change as the owner types.
    ask_full: Line<'static>,
    /// The confirmation's drawn-frame marker, which this frame reports to.
    seen: &'a Seen,
    /// Whether this frame draws a modal over the confirmation.
    covered: bool,
    /// What the frame says instead when it has no room for the confirmation.
    too_small: &'static str,
    /// The outer width of the box.
    width: u16,
}

/// ⟨M07⟩ M07-W0-R01: lay a guarded confirmation out, draw it and report what frame
/// `number` drew of it to its marker ([`Seen`], and its [`Reading`]).
///
/// The content is wrapped, never cut, and scrolls above the prompt line, which stays
/// fixed and keeps the rows its longest answer needs. The model accepts a typed `yes`
/// only when the latest frame drew the prompt with a window of the content, and the
/// frames so far have drawn every content row. So:
/// * a frame with no room in `area` for the prompt and one content row draws a notice
///   instead and reports `TooSmall` (nothing can be confirmed until the terminal is
///   larger);
/// * a frame that draws a modal over the confirmation reports `Nothing` and records no
///   rows;
/// * the content's fingerprint includes the width it was wrapped to and everything the
///   lines say, so a resize or a listing that changes the target must be read again.
///
/// `place` is given the box's height and returns where it goes (`width` wide), after
/// drawing what stays around it.
fn render_guarded_confirm(
    frame: &mut Frame<'_>,
    number: u64,
    area: Rect,
    confirm: Guarded<'_>,
    place: impl FnOnce(&mut Frame<'_>, u16) -> Rect,
    theme: Theme,
) {
    let Guarded {
        title,
        content,
        ask,
        ask_full,
        seen,
        covered,
        too_small,
        width,
    } = confirm;
    let report = |shown: Shown| seen.report(number, if covered { Shown::Nothing } else { shown });
    let inner_width = usize::from(width.saturating_sub(2)).max(1);
    let rows = wrap_lines(&content, inner_width);
    let ask = wrap_lines(&[ask], inner_width);
    let reserve = wrap_lines(&[ask_full], inner_width).len().max(ask.len());
    let most = usize::from(area.height).saturating_sub(2);
    if most < reserve + 1 {
        report(Shown::TooSmall);
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(Line::styled(too_small, theme.bold())).wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let room = most - reserve;
    let height = u16::try_from(rows.len().clamp(1, room) + reserve + 2).unwrap_or(area.height);
    let box_area = place(frame, height);
    frame.render_widget(Clear, box_area);
    let mut block = Block::new()
        .borders(Borders::ALL)
        .title(Span::styled(title, theme.bold()));
    let inner = block.inner(box_area);
    let ask_height = u16::try_from(reserve).unwrap_or(u16::MAX);
    let [content_area, ask_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(ask_height)]).areas(inner);
    // What is drawn is what is recorded: the clamped offset and the rows that fit.
    let viewport = usize::from(content_area.height);
    let scroll = seen.reading.scroll.min(rows.len().saturating_sub(viewport));
    let end = (scroll + viewport).min(rows.len());
    let whole: Vec<String> = rows.iter().map(ToString::to_string).collect();
    let mut parts: Vec<&str> = whole.iter().map(String::as_str).collect();
    let width_text = inner_width.to_string();
    parts.push(&width_text);
    // A box with less room than the layout asked for (rows or columns) shows a cut
    // confirmation: that is not shown.
    let cut = viewport == 0
        || usize::from(ask_area.height) < ask.len()
        || usize::from(inner.width) < inner_width;
    if covered || cut {
        report(Shown::TooSmall);
    } else {
        seen.reading
            .record(fingerprint(&parts), rows.len(), viewport, scroll);
        report(Shown::Drawn);
    }
    let below = rows.len() - end;
    let status = if let Some(why) = seen.refusal() {
        Some(Line::styled(
            if why == REFUSED_UNREAD {
                " yes refused: read it all first (PgUp/PgDn) "
            } else {
                " yes refused: it was not on screen "
            },
            theme.bold(),
        ))
    } else if below > 0 {
        Some(Line::styled(
            format!(
                " {below} more {} below (PgDn) ",
                if below == 1 { "row" } else { "rows" }
            ),
            theme.dim(),
        ))
    } else if rows.len() > viewport && !covered && !seen.reading.all_shown() {
        // At the end with rows above not drawn yet (a jump, or a re-wrap).
        Some(Line::styled(" read from the top (Home) ", theme.dim()))
    } else {
        (rows.len() > viewport).then(|| Line::styled(" end of the content ", theme.dim()))
    };
    if let Some(status) = status {
        block = block.title_bottom(status);
    }
    frame.render_widget(block, box_area);
    frame.render_widget(Paragraph::new(rows[scroll..end].to_vec()), content_area);
    frame.render_widget(Paragraph::new(ask), ask_area);
}

/// ⟨M07⟩ The stop menu's confirmation (pause, stop this work, stop all for a profile,
/// cutoff), drawn behind the reading guard in the menu's place: the same centred box,
/// with the action and its target ([`super::m05::stop_confirm_lines`]) wrapped and
/// scrolling above the fixed prompt, and what frame `number` drew reported to the menu
/// ([`super::m05::StopMenu::unseen`]). The shared modal dispatch draws the menu's other
/// phases, and nothing is ever drawn over a modal.
fn render_stop_confirm(
    frame: &mut Frame<'_>,
    number: u64,
    body: Rect,
    menu: &super::m05::StopMenu,
    action: &super::m05::StopAction,
    theme: Theme,
) {
    let width = body.width.saturating_sub(2).clamp(10, 110).min(body.width);
    let confirm = Guarded {
        title: "Pause or stop access",
        content: super::m05::stop_confirm_lines(menu, action),
        ask: super::m05::stop_confirm_ask(&menu.input),
        ask_full: super::m05::stop_confirm_ask(&full_answer()),
        seen: &menu.seen,
        covered: false,
        too_small: STOP_TOO_SMALL,
        width,
    };
    let place = |_: &mut Frame<'_>, height: u16| {
        let height = height.min(body.height);
        Rect::new(
            body.x + (body.width - width) / 2,
            body.y + (body.height - height) / 2,
            width,
            height,
        )
    };
    render_guarded_confirm(frame, number, body, confirm, place, theme);
}

// ---- details -------------------------------------------------------------------------

fn role_of(report: &DoctorReport, path: &str) -> Option<ConfigFileRole> {
    report
        .config_files
        .iter()
        .find(|f| f.path_display == path)
        .map(|f| f.role)
}

/// The provenance class of one effective value (m02-plan U10: managed, observed,
/// inherited, undetermined).
fn provenance_class(
    report: &DoctorReport,
    definition: AliasDefinition,
    certainty: DirectiveCertainty,
    path: Option<&str>,
) -> &'static str {
    if certainty == DirectiveCertainty::Undetermined {
        return "[undetermined]";
    }
    match path.and_then(|p| role_of(report, p)) {
        Some(ConfigFileRole::Managed) => "[managed]",
        Some(ConfigFileRole::System) => "[inherited]",
        _ if definition == AliasDefinition::Managed => "[inherited]",
        Some(_) => "[observed]",
        None => "[default]",
    }
}

fn destination_lines(app: &App, alias: &str, theme: Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let dest = app.catalog().destination(alias);
    let observation = app.doctor_alias(alias);
    let kind = match (dest, observation.map(|o| o.definition)) {
        (Some(d), _) if d.is_managed() => "managed destination",
        (Some(_), _) => "observed destination",
        (None, Some(_)) => "in your configuration only (not in the catalog)",
        (None, None) => "unknown",
    };
    lines.push(Line::styled(format!("{alias}: {kind}"), theme.bold()));
    if let Some(d) = dest {
        lines.push(plain(format!(
            "Catalog: {} rev {}, updated {}; listing read {}",
            d.id,
            d.revision.as_deref().unwrap_or("?"),
            d.updated_at.map_or_else(|| "?".to_owned(), full),
            when(app.now(), app.catalog().read_at)
        )));
        if d.is_managed() {
            lines.push(plain(format!(
                "  [managed] rendered: HostName {} Port {} User {}",
                d.hostname.as_deref().unwrap_or("?"),
                d.port.as_deref().unwrap_or("22"),
                d.account.as_deref().unwrap_or("?")
            )));
        }
        // ⟨M03⟩ U12: managed readiness (projection, deadline wording, lock behaviour,
        // owned connections, enrollments) for a managed-certificate pair.
        lines.extend(super::m03::managed_lines(app.catalog(), d));
    }
    let doctor = app.doctor();
    match (doctor, observation) {
        (Some(doc), Some(obs)) => {
            lines.push(Line::styled(
                format!(
                    "Effective values (static pass at {}, {}; nothing executed):",
                    hms(doc.taken_at),
                    age(app.now(), doc.taken_at)
                ),
                theme.bold(),
            ));
            for d in &obs.behavior {
                if d.certainty == DirectiveCertainty::Unset {
                    continue;
                }
                let at = d.provenance.first().map(|p| clean(&p.path_display));
                let class =
                    provenance_class(&doc.report, obs.definition, d.certainty, at.as_deref());
                let values = d
                    .values
                    .iter()
                    .map(|v| clean(v))
                    .collect::<Vec<_>>()
                    .join(" | ");
                let place = d
                    .provenance
                    .iter()
                    .map(|p| format!("{}:{}", clean(&p.path_display), p.line))
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {class:<15}"),
                        theme.fg(match class {
                            "[managed]" => Color::Green,
                            "[undetermined]" => Color::Red,
                            _ => Color::Blue,
                        }),
                    ),
                    Span::raw(format!("{} {values}  ({place})", clean(&d.directive))),
                ]));
            }
            match &obs.identity_selection {
                Some(sel) => {
                    let verdict = match sel.selection {
                        IdentitySelection::Exclusive => {
                            "exclusive (only the adopted key is offered)"
                        }
                        IdentitySelection::NotExclusive => {
                            "NOT exclusive (other identities may be offered)"
                        }
                        IdentitySelection::Undetermined => "undetermined",
                        _ => "unknown",
                    };
                    lines.push(Line::styled(
                        format!(
                            "Identity selection: {verdict}; IdentitiesOnly {}",
                            match sel.identities_only {
                                heimdall_contract::provider::IdentitiesOnly::DeterminedYes => "yes",
                                heimdall_contract::provider::IdentitiesOnly::DeterminedNo => "no",
                                _ => "undetermined",
                            }
                        ),
                        theme.bold(),
                    ));
                    for (i, e) in sel.entries.iter().enumerate() {
                        lines.push(plain(format!(
                            "  {}. {} {} {} ({}){}",
                            i + 1,
                            name_of(&e.source),
                            name_of(&e.kind),
                            e.fingerprint
                                .as_deref()
                                .map_or_else(|| "public key unknown".to_owned(), clean),
                            name_of(&e.backing),
                            e.provenance.as_ref().map_or_else(String::new, |p| format!(
                                "  {}:{}",
                                clean(&p.path_display),
                                p.line
                            ))
                        )));
                    }
                }
                None => lines.push(plain(
                    "Identity selection: not evaluated (no adopted identity)",
                )),
            }
        }
        (Some(doc), None) => lines.push(plain(format!(
            "Effective values: the static pass ({}) did not evaluate this alias",
            when(app.now(), Some(doc.taken_at))
        ))),
        (None, _) => lines.push(plain("Effective values: static pass running")),
    }
    identity_lines(app, alias, &mut lines, theme);
    if let Some(doc) = doctor {
        for p in &doc.report.providers {
            lines.push(plain(format!(
                "Provider: {} availability {}, interaction {} ({} level at {}, {})",
                name_of(&p.provider),
                name_of(&p.availability),
                name_of(&p.interaction),
                name_of(&p.observed_level),
                when(app.now(), Some(p.observed_at)),
                name_of(&p.basis)
            )));
        }
        let projection = doc.report.projection.as_ref().map_or_else(
            || "not installed".to_owned(),
            |p| {
                let state = match p.state {
                    ProjectionState::Absent => "absent",
                    ProjectionState::Healthy => "healthy",
                    ProjectionState::Conflict => "conflict",
                    ProjectionState::Manual => "manual mode",
                    ProjectionState::Conditional => "conditional include",
                    _ => "unknown",
                };
                match p.conflict {
                    Some(c) => format!("{state} ({})", name_of(&c)),
                    None => state.to_owned(),
                }
            },
        );
        lines.push(plain(format!(
            "Projection: {projection}; committed generation {}",
            app.catalog()
                .projection_generation
                .map_or_else(|| "none".to_owned(), |g| g.to_string())
        )));
        let findings: Vec<_> = doc
            .report
            .findings
            .iter()
            .filter(|f| {
                f.subject.id.as_deref() == Some(alias)
                    || (dest.is_some_and(|d| f.subject.id.as_deref() == Some(d.id.as_str())))
            })
            .collect();
        if !findings.is_empty() {
            lines.push(Line::styled("Findings:", theme.bold()));
            for f in findings {
                let marker = match f.severity {
                    heimdall_contract::doctor::FindingSeverity::Problem => "[!!]",
                    heimdall_contract::doctor::FindingSeverity::Warning => "[ !]",
                    _ => "[ i]",
                };
                lines.push(plain(format!(
                    "  {marker} {}: {}",
                    clean(&f.code),
                    clean(&f.message)
                )));
            }
        }
    }
    lines
}

/// A contract enum's wire name.
fn name_of<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "?".to_owned())
}

fn identity_lines(app: &App, alias: &str, lines: &mut Vec<Line<'static>>, theme: Theme) {
    let dest = app.catalog().destination(alias);
    let by_id = dest
        .and_then(|d| d.identity_id.as_deref())
        .and_then(|id| app.catalog().identity(id));
    let by_entry = || {
        app.doctor_alias(alias)?
            .identity_selection
            .as_ref()?
            .entries
            .iter()
            .find_map(|e| {
                e.fingerprint
                    .as_deref()
                    .and_then(|f| app.catalog().identity_by_fingerprint(f))
            })
    };
    let Some(identity) = by_id.or_else(by_entry) else {
        lines.push(plain(
            "Identity: no adopted identity is known for this alias",
        ));
        return;
    };
    lines.push(Line::styled(
        format!(
            "Identity: {} {} via {} at {}",
            identity.fingerprint,
            identity.key_type.as_deref().unwrap_or("?"),
            identity.mechanism.as_deref().unwrap_or("?"),
            identity.endpoint.as_deref().unwrap_or("?")
        ),
        theme.bold(),
    ));
    let basis = match identity.basis.as_deref() {
        Some("declared") => format!(
            "declared {} (expires {})",
            identity.declared_at.map_or_else(|| "?".to_owned(), full),
            identity
                .declaration_expires_at
                .map_or_else(|| "?".to_owned(), full)
        ),
        Some(b) => b.to_owned(),
        None => "unknown".to_owned(),
    };
    lines.push(plain(format!(
        "  Interaction: {}, basis {basis}",
        identity.interaction
    )));
    lines.push(plain(format!(
        "  Non-interactive use: {} (checked {})",
        match identity.noninteractive {
            Some(true) => "eligible",
            Some(false) => "not eligible",
            None => "unknown",
        },
        when(app.now(), identity.checked_at)
    )));
}

fn profile_lines(app: &App, id: &str) -> Vec<Line<'static>> {
    let Some(p) = app.catalog().profiles.iter().find(|p| p.id == id) else {
        return vec![plain(format!("{id}: not in the latest listing"))];
    };
    let mut lines = vec![plain(format!(
        "{}: {} (rev {}; listing read {})",
        p.id,
        p.label.as_deref().unwrap_or("no label"),
        p.revision.as_deref().unwrap_or("?"),
        when(app.now(), app.catalog().read_at)
    ))];
    lines.push(plain("Pairs:"));
    for pair in &p.pairs {
        let alias = app
            .catalog()
            .destinations
            .iter()
            .find(|d| d.id == pair.destination)
            .map_or("(not in the catalog)", |d| d.alias.as_str());
        lines.push(plain(format!(
            "  {} as {}  alias {alias}",
            pair.destination, pair.account
        )));
    }
    lines
}

fn operation_lines(app: &App, id: &str, theme: Theme) -> Vec<Line<'static>> {
    let listed = app.catalog().operations.iter().find(|o| o.id == id);
    let detail = app
        .operation
        .as_ref()
        .filter(|(open, _)| open == id)
        .map(|(_, d)| d);
    let op = detail.and_then(|d| d.operation.as_ref()).or(listed);
    let mut lines = Vec::new();
    match op {
        Some(o) => {
            lines.push(Line::styled(format!("{} {}", o.id, o.kind), theme.bold()));
            lines.push(plain(format!(
                "State: {}{} · code {} · effect {}",
                o.state,
                if o.is_held() { " (held)" } else { "" },
                o.code.as_deref().unwrap_or("-"),
                o.effect.as_deref().unwrap_or("-")
            )));
            lines.push(plain(format!(
                "Created {} · updated {}",
                when(app.now(), o.created_at),
                when(app.now(), o.updated_at)
            )));
            if let Some(m) = o.message() {
                lines.push(plain(format!("Result: {m}")));
            }
            if o.is_held() {
                lines.push(Line::styled(
                    "[!!] Held for you: a file it manages changed while it ran, and nothing was moved.",
                    theme.fg(Color::Red),
                ));
                lines.push(plain(format!(
                    "  r {}",
                    super::model::HeldRepair::Retry.sentence()
                )));
                lines.push(plain(format!(
                    "  k {}",
                    super::model::HeldRepair::Keep.sentence()
                )));
            }
            if o.is_active() {
                lines.push(plain("  x cancels it"));
            }
            if let Some(d) = app
                .catalog()
                .decisions
                .iter()
                .find(|d| d.operation().as_deref() == Some(id))
            {
                lines.push(plain(format!(
                    "  Waiting on decision {} (Enter to review)",
                    d.id
                )));
            }
        }
        None => lines.push(plain(format!("{id}: reading the operation"))),
    }
    lines.push(Line::styled("Events (observe events):", theme.bold()));
    match detail {
        Some(d) => {
            if let Some(e) = &d.error {
                lines.push(plain(format!("  {}", clean(e))));
            }
            if d.events.is_empty() {
                lines.push(plain("  none yet"));
            }
            for e in &d.events {
                lines.push(plain(format!(
                    "  {} {} {}",
                    e.at.map_or_else(|| "?".to_owned(), hms),
                    e.kind,
                    e.summary
                )));
            }
        }
        None => lines.push(plain("  reading")),
    }
    lines
}

// ---- modals --------------------------------------------------------------------------

/// A plain modal's parts (key help, the probe menu, a probe's result): title, content
/// and the content's scroll offset. Confirmations are [`ConfirmParts`].
struct ModalParts {
    title: String,
    content: Vec<Line<'static>>,
    scroll: u16,
}

/// Rows `lines` take when wrapped to `width` (an estimate by characters, enough to
/// size a prompt area).
fn wrapped_rows(lines: &[Line<'static>], width: u16) -> u16 {
    let w = usize::from(width.max(1));
    let rows: usize = lines.iter().map(|l| l.width().max(1).div_ceil(w)).sum();
    u16::try_from(rows).unwrap_or(u16::MAX)
}

// ---- confirmations: wrapped, scrollable content over a fixed prompt --------------------
//
// A decision, an authorization and a repair ask the owner to type `yes` to what the
// content says (ADR-0006 §3.1). Nothing of that content may be cut off (ADR-0007 §12.31
// item 3): long lines wrap onto further rows, the diff falls back to stacked columns
// when its cells do not fit side by side, and what does not fit the modal scrolls
// (arrows, PgUp/PgDn, Home/End) above a prompt that stays fixed. The bottom border says
// how many rows remain below, and the model accepts a typed `yes` only once a frame has
// drawn the last row (`Reading`).

/// Display width of `s` in terminal cells.
fn cells(s: &str) -> usize {
    Span::raw(s).width()
}

/// Display width of one character.
fn char_cells(c: char) -> usize {
    let mut buf = [0u8; 4];
    cells(c.encode_utf8(&mut buf))
}

/// The shortest whitespace-free token that is broken after a path separator.
const PATH_LIKE: usize = 12;

/// Whether a row may end after `chars[k - 1]`: after whitespace, or after a path
/// separator inside a token long enough to be a path (`[y/N]` stays whole).
fn breaks_after(chars: &[char], k: usize) -> bool {
    let c = chars[k - 1];
    if c.is_whitespace() {
        return true;
    }
    if c != '/' && c != '\\' {
        return false;
    }
    let before = chars[..k]
        .iter()
        .rev()
        .take_while(|c| !c.is_whitespace())
        .count();
    let after = chars[k..]
        .iter()
        .take_while(|c| !c.is_whitespace())
        .take(PATH_LIKE)
        .count();
    before + after >= PATH_LIKE
}

/// `text` as rows of at most `width` cells. **Every character lands in a row**; only the
/// whitespace that is itself the break between two rows is not carried over. A row
/// prefers to end after a space (or a path separator in a long token) when one lies in
/// its second half, and breaks mid-word otherwise. Continuation rows of an indented line
/// are indented two further spaces (never more than half the width), so they read as
/// continuations.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    if cells(text) <= width {
        return vec![text.to_owned()];
    }
    let chars: Vec<char> = text.chars().collect();
    let lead = chars.iter().take_while(|c| **c == ' ').count();
    let hang = if lead == 0 {
        0
    } else {
        (lead + 2).min(width / 2)
    };
    let mut rows = Vec::new();
    let mut start = 0;
    let mut indent = 0;
    while start < chars.len() {
        let room = width.saturating_sub(indent).max(1);
        let (mut used, mut end) = (0, start);
        while let Some(c) = chars.get(end) {
            let w = char_cells(*c);
            if used + w > room {
                break;
            }
            used += w;
            end += 1;
        }
        if end == start {
            // A character wider than the room still takes a row of its own.
            end += 1;
        }
        // The row ends exactly where a word ends: the whitespace between it and the next
        // word is the break itself and is not carried onto the next row.
        let at_word_end = chars.get(end).is_some_and(|c| c.is_whitespace());
        if end < chars.len() && !at_word_end {
            let half = start + (end - start) / 2;
            if let Some(k) = (half + 1..=end).rev().find(|k| breaks_after(&chars, *k)) {
                end = k;
            }
        }
        let mut row = " ".repeat(indent);
        row.extend(&chars[start..end]);
        rows.push(row);
        start = end;
        if at_word_end {
            while chars.get(start).is_some_and(|c| c.is_whitespace()) {
                start += 1;
            }
        }
        indent = hang;
    }
    rows
}

/// `line` wrapped to `width` cells ([`wrap_text`]); every row keeps the line's style.
/// The confirmation content is built of single-style lines.
fn wrap_line(line: &Line<'_>, width: usize) -> Vec<Line<'static>> {
    let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
    wrap_text(&text, width)
        .into_iter()
        .map(|row| Line::styled(row, line.style))
        .collect()
}

fn wrap_lines(lines: &[Line<'_>], width: usize) -> Vec<Line<'static>> {
    lines.iter().flat_map(|l| wrap_line(l, width)).collect()
}

/// A fingerprint of what a confirmation asks the owner to confirm.
fn fingerprint(parts: &[&str]) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    hasher.finish()
}

/// A confirmation, before layout.
struct ConfirmParts {
    title: String,
    /// The content, one logical line per entry (wrapped at layout).
    content: Vec<Line<'static>>,
    /// Fingerprint of what the content asks to confirm.
    key: u64,
    /// The prompt as it is now.
    prompt: Vec<Line<'static>>,
    /// Worst-case forms of the prompt (the longest verb with a full answer typed), so
    /// its rows, and the room left for the content, do not change as the owner types.
    prompt_reserve: Vec<Vec<Line<'static>>>,
    /// Fill the body (a decision), or fit the content when it is short.
    fill: bool,
}

/// How the status in the bottom border reads: how many rows remain below, that the end
/// is on screen, or that a `yes` was refused because it was not. Nothing when the whole
/// content fits.
fn confirm_status(
    reading: &Reading,
    scrollable: bool,
    below: usize,
    theme: Theme,
) -> Option<Line<'static>> {
    let rows = if below == 1 { "row" } else { "rows" };
    if reading.refused {
        let text = if below > 0 {
            format!(" yes refused: {below} more {rows} below ")
        } else {
            " yes refused: the end is not on screen ".to_owned()
        };
        return Some(Line::styled(text, theme.bold()));
    }
    if below > 0 {
        return Some(Line::styled(
            format!(" {below} more {rows} below (PgDn, End) "),
            theme.dim(),
        ));
    }
    scrollable.then(|| Line::styled(" end of the content ", theme.dim()))
}

/// Lay a confirmation out, draw it and report what was drawn to its `reading`.
fn render_confirm(
    frame: &mut Frame<'_>,
    body: Rect,
    parts: ConfirmParts,
    reading: &Reading,
    theme: Theme,
) {
    let width = body.width.saturating_sub(2).clamp(10, 110);
    let inner_width = usize::from(width.saturating_sub(2)).max(1);
    let rows = wrap_lines(&parts.content, inner_width);
    let prompt = wrap_lines(&parts.prompt, inner_width);
    let reserve = parts
        .prompt_reserve
        .iter()
        .map(|p| wrap_lines(p, inner_width).len())
        .chain([prompt.len()])
        .max()
        .unwrap_or(0);
    // Inner rows: the prompt keeps its (worst-case) rows and the content at least one.
    let most = usize::from(body.height).saturating_sub(2).max(1);
    let prompt_rows = reserve.min(most - 1);
    let room = most - prompt_rows;
    let inner_rows = if parts.fill {
        most
    } else {
        rows.len().clamp(1, room) + prompt_rows
    };
    let height = u16::try_from(inner_rows + 2)
        .unwrap_or(u16::MAX)
        .min(body.height);
    let area = Rect::new(
        body.x + (body.width.saturating_sub(width)) / 2,
        body.y + (body.height.saturating_sub(height)) / 2,
        width.min(body.width),
        height,
    );
    frame.render_widget(Clear, area);
    let mut block = Block::new()
        .borders(Borders::ALL)
        .title(Span::styled(clean(&parts.title), theme.bold()));
    let inner = block.inner(area);
    let prompt_height = u16::try_from(prompt_rows)
        .unwrap_or(u16::MAX)
        .min(inner.height.saturating_sub(1));
    let [content_area, prompt_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(prompt_height)]).areas(inner);
    // What is drawn is what is recorded: the clamped offset and the rows that fit.
    let viewport = usize::from(content_area.height);
    let last = rows.len().saturating_sub(viewport);
    let scroll = reading.scroll.min(last);
    let end = (scroll + viewport).min(rows.len());
    reading.record(parts.key, rows.len(), viewport, scroll);
    if let Some(status) = confirm_status(reading, rows.len() > viewport, rows.len() - end, theme) {
        block = block.title_bottom(status);
    }
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(rows[scroll..end].to_vec()), content_area);
    if prompt_height > 0 {
        // A prompt that does not fit loses its top rows, never the line being typed.
        let from = prompt.len().saturating_sub(usize::from(prompt_height));
        frame.render_widget(Paragraph::new(prompt[from..].to_vec()), prompt_area);
    }
}

fn render_modal(frame: &mut Frame<'_>, app: &App, modal: &Modal, body: Rect, theme: Theme) {
    let width = body.width.saturating_sub(2).clamp(10, 110);
    let inner_width = width.saturating_sub(2);
    let parts = match modal {
        Modal::Decision(p) => {
            let parts = decision_modal(app, p, usize::from(inner_width), theme);
            render_confirm(frame, body, parts, &p.reading, theme);
            return;
        }
        Modal::Authorization(p) => {
            render_confirm(frame, body, authorization_parts(p), &p.reading, theme);
            return;
        }
        Modal::Repair(p) => {
            render_confirm(frame, body, repair_parts(p), &p.reading, theme);
            return;
        }
        Modal::Help => ModalParts {
            title: "Keys".to_owned(),
            content: help_lines(),
            scroll: 0,
        },
        Modal::ProbeMenu { alias, selected } => {
            let mut content = vec![plain(format!(
                "Explicit probes for {alias}; each names its level:"
            ))];
            for (i, (_, name, label)) in PROBE_LEVELS.iter().enumerate() {
                content.push(row(
                    i == *selected,
                    theme,
                    vec![Span::raw(format!("{name:<17} {label}"))],
                ));
            }
            ModalParts {
                title: "Probes".to_owned(),
                content,
                scroll: 0,
            }
        }
        Modal::Probe(v) => ModalParts {
            title: format!("{} probe: {}", level_name(v.level), v.alias),
            content: probe_lines(app, v),
            scroll: v.scroll,
        },
        // ⟨M05⟩ The selected action stays on screen when the terminal is short.
        Modal::StopMenu(m) => {
            let (content, selected) =
                super::m05::stop_menu_lines(m, &app.catalog.m05.stop_context());
            let through = wrapped_rows(&content[..(selected + 2).min(content.len())], inner_width);
            let room = body.height.saturating_sub(2).max(1);
            ModalParts {
                title: "Pause or stop access".to_owned(),
                content,
                scroll: through.saturating_sub(room),
            }
        }
    };
    let content_rows = wrapped_rows(&parts.content, inner_width);
    let height = if matches!(modal, Modal::Probe(_)) {
        body.height
    } else {
        content_rows.saturating_add(2)
    }
    .clamp(3, body.height.max(3));
    let area = Rect::new(
        body.x + (body.width.saturating_sub(width)) / 2,
        body.y + (body.height.saturating_sub(height)) / 2,
        width.min(body.width),
        height.min(body.height),
    );
    frame.render_widget(Clear, area);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(Span::styled(clean(&parts.title), theme.bold()));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(parts.content)
            .wrap(Wrap { trim: false })
            .scroll((parts.scroll, 0)),
        inner,
    );
}

/// ⟨M07⟩ The key help: each line's keys (what `every_footer_and_help_key_is_bound`
/// presses) and its text.
pub(crate) const HELP_LINES: [(&[Key], &str); 16] = [
    (
        &[Key::Char('1'), Key::Tab, Key::BackTab],
        "1-8, Tab, Shift-Tab   switch view: 1 Overview 2 Destinations 3 Profiles 4 Activity",
    ),
    (
        &[],
        "                      5 Projects 6 Environments 7 Identities 8 Settings",
    ),
    (
        &[
            Key::Up,
            Key::Down,
            Key::PageUp,
            Key::PageDown,
            Key::Home,
            Key::End,
        ],
        "Up/Down, PgUp/PgDn    move or scroll; Home/End go to the first and last row",
    ),
    (
        &[Key::Enter],
        "Enter                 open the selected item; on Settings, change it",
    ),
    (
        &[Key::Char('/')],
        "/                     search Destinations or Profiles (in memory; never probes)",
    ),
    (
        &[Key::Char('c')],
        "c                     connect: hand the terminal to ssh <alias> (Destinations)",
    ),
    (
        &[Key::Char('p')],
        "p                     explicit probes, each labelled by its level (Destinations)",
    ),
    (
        &[Key::Char('r'), Key::Char('k')],
        "r / k                 retry or keep a held setup operation",
    ),
    (
        &[Key::Char('x')],
        "x                     cancel the open operation",
    ),
    (
        &[Key::Char('w'), Key::Char('h'), Key::Char('s')],
        "w / h / s             project status, policy history, pause or stop access",
    ),
    (
        &[Key::Char('R')],
        "R                     refresh, re-running the passive static pass",
    ),
    (
        &[Key::Char('S')],
        "S                     start the runtime (the TUI never starts it itself)",
    ),
    (
        &[Key::Esc, Key::Char('q'), Key::CtrlC],
        "Esc, q                back; q on a view quits; Ctrl-C quits",
    ),
    (&[Key::Char('?')], "?                     this key help"),
    (
        &[],
        "Confirmations need a typed yes once their last row has been on screen;",
    ),
    (&[], "anything else is No and sends nothing."),
];

fn help_lines() -> Vec<Line<'static>> {
    HELP_LINES.iter().map(|(_, text)| plain(*text)).collect()
}

fn prompt_line(verb: &str, input: &str) -> Line<'static> {
    plain(format!("{verb}? Type yes to confirm [y/N]: {input}_"))
}

/// The diff's before and after lines, file by file: each file's heading starts on the
/// same row in both columns, so the side-by-side form lines up. The removal of one of
/// Heimdall's own files is its summary line, in the before column.
fn diff_columns(diff: &str) -> (Vec<String>, Vec<String>) {
    let (mut before, mut after) = (Vec::new(), Vec::new());
    let level = |b: &mut Vec<String>, a: &mut Vec<String>| {
        let n = b.len().max(a.len());
        b.resize(n, String::new());
        a.resize(n, String::new());
    };
    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("--- ") {
            level(&mut before, &mut after);
            before.push(format!("{}:", clean(path)));
            after.push(format!("{}:", clean(path)));
        } else if let Some(text) = crate::output::own_removal_text(line) {
            // ADR-0007 §12.34 item 7: a file of Heimdall's own that the plan removes is one
            // summary line (name, line count, SHA-256), under Before: what is going away.
            before.push(format!("  {}", clean(&text)));
        } else if let Some(l) = line.strip_prefix('-') {
            before.push(format!("  {}", clean(l)));
        } else if let Some(l) = line.strip_prefix('+') {
            after.push(format!("  {}", clean(l)));
        }
    }
    (before, after)
}

fn restore_column(request: &serde_json::Value) -> Vec<String> {
    let mut out = vec!["if its section were removed now:".to_owned()];
    let entries = request
        .get("restore")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if entries.is_empty() {
        out.push("  (no item)".to_owned());
    }
    for e in entries {
        let item = e
            .get("item")
            .and_then(|v| v.as_str())
            .map_or_else(|| "?".to_owned(), clean);
        let digest = e.get("digest").and_then(|v| v.as_str()).map_or_else(
            || "?".to_owned(),
            |d| clean(&d.chars().take(16).collect::<String>()),
        );
        out.push(format!("  {item}"));
        out.push(format!("    behavior {digest}"));
    }
    out
}

fn count(request: &serde_json::Value, key: &str) -> String {
    match request.get(key) {
        Some(serde_json::Value::Array(a)) => a.len().to_string(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => "?".to_owned(),
    }
}

/// `s` padded with spaces to `width` cells.
fn pad(s: &str, width: usize) -> String {
    format!("{s}{}", " ".repeat(width.saturating_sub(cells(s))))
}

/// The gap between side-by-side columns.
const COLUMN_GAP: usize = 2;

/// The before, after and restore columns of an `ApplyProjection` record. Side by side
/// when every cell fits its column in `width` cells; otherwise one under the other,
/// where a long line wraps at layout. A cell is never cut (ADR-0007 §12.31 item 3).
fn apply_projection_lines(d: &Decision, width: usize, theme: Theme) -> Vec<Line<'static>> {
    let r = &d.request;
    let s = |k: &str| {
        r.get(k)
            .and_then(|v| v.as_str())
            .map_or_else(|| "?".to_owned(), clean)
    };
    let mut lines = vec![plain(format!(
        "Intent {} · aliases {} added, {} changed, {} removed · {} file(s) · Git selection {}",
        s("intent"),
        count(r, "added_aliases"),
        count(r, "changed_aliases"),
        count(r, "removed_aliases"),
        count(r, "files"),
        if r.get("git").and_then(serde_json::Value::as_bool) == Some(true) {
            "changes"
        } else {
            "unchanged"
        }
    ))];
    lines.push(plain(format!("Plan digest {}", s("plan_digest"))));
    let (before, after) = diff_columns(r.get("diff_text").and_then(|v| v.as_str()).unwrap_or(""));
    let restore = restore_column(r);
    let columns = [
        ("Before", &before),
        ("After", &after),
        ("Restore", &restore),
    ];
    let widths: Vec<usize> = columns
        .iter()
        .map(|(title, col)| {
            col.iter()
                .map(|l| cells(l))
                .chain([cells(title)])
                .max()
                .unwrap_or(0)
        })
        .collect();
    if widths.iter().sum::<usize>() + 2 * COLUMN_GAP <= width {
        let gap = " ".repeat(COLUMN_GAP);
        let join = |cell: &dyn Fn(usize) -> String| {
            (0..3)
                .map(|i| pad(&cell(i), widths[i]))
                .collect::<Vec<_>>()
                .join(&gap)
                .trim_end()
                .to_owned()
        };
        lines.push(Line::styled(
            join(&|i| columns[i].0.to_owned()),
            theme.bold(),
        ));
        let n = before.len().max(after.len()).max(restore.len());
        for row in 0..n {
            lines.push(plain(join(&|i| {
                columns[i].1.get(row).cloned().unwrap_or_default()
            })));
        }
    } else {
        for (title, col) in columns {
            lines.push(Line::styled(format!("{title}:"), theme.bold()));
            // The empty cells only keep the side-by-side rows level: not a stacked line.
            lines.extend(
                col.iter()
                    .filter(|l| !l.is_empty())
                    .map(|l| plain(l.clone())),
            );
        }
    }
    lines
}

fn declare_lines(d: &Decision) -> Vec<Line<'static>> {
    let r = &d.request;
    let s = |k: &str| {
        r.get(k)
            .and_then(|v| v.as_str())
            .map_or_else(|| "?".to_owned(), clean)
    };
    let endpoint = r
        .get("endpoint")
        .and_then(|e| e.get("locator").and_then(|l| l.as_str()))
        .map_or_else(|| "?".to_owned(), clean);
    vec![
        plain(DECLARATION_TEXT),
        plain(format!(
            "Identity {} ({})",
            s("identity_id"),
            s("fingerprint")
        )),
        plain(format!("At endpoint {endpoint}")),
        plain(format!(
            "Declared interaction: {} · valid until {}",
            s("interaction"),
            s("valid_until")
        )),
    ]
}

/// The worst-case answer typed, to reserve the prompt's rows before anything is typed.
fn full_answer() -> String {
    "W".repeat(MAX_TYPED)
}

/// A decision's fixed prompt: the keys it takes, and the typed confirmation.
fn decision_prompt(verdict: Verdict, input: &str, theme: Theme) -> Vec<Line<'static>> {
    let verb = match verdict {
        Verdict::Approve => "Approve",
        Verdict::Deny => "Deny",
    };
    vec![
        Line::styled(
            format!(
                "Tab: {} · Esc: send nothing",
                match verdict {
                    Verdict::Approve => "deny",
                    Verdict::Deny => "approve",
                }
            ),
            theme.dim(),
        ),
        prompt_line(verb, input).style(theme.bold()),
    ]
}

fn decision_modal(app: &App, p: &DecisionPrompt, width: usize, theme: Theme) -> ConfirmParts {
    let Some(d) = app.catalog.decisions.iter().find(|d| d.id == p.id) else {
        return ConfirmParts {
            title: format!("Owner decision {}", p.id),
            content: vec![
                plain(
                    "This decision is not pending in this runtime (completed, expired and replaced, or unknown).",
                ),
                plain("There is no recorded request to show, and nothing can be sent."),
            ],
            key: fingerprint(&["not pending", &p.id]),
            prompt: vec![plain("Esc closes.")],
            prompt_reserve: Vec::new(),
            fill: true,
        };
    };
    // ⟨M03⟩ §17.25 item 10, §17.26: approved only in the CLI; Deny is the one verdict.
    let cli_only = super::m03::cli_only(d);
    let verdict = if cli_only.is_some() {
        Verdict::Deny
    } else {
        p.verdict
    };
    let verb = match verdict {
        Verdict::Approve => "Approve",
        Verdict::Deny => "Deny",
    };
    let mut content = vec![plain(format!(
        "Recorded {} · expires {}{}",
        when(app.now, d.created_at),
        when(app.now, d.expires_at),
        if d.expired {
            " (expired: the runtime will refuse it)"
        } else {
            ""
        }
    ))];
    content.push(Line::styled(
        format!("Exactly what {} applies to:", verb.to_ascii_lowercase()),
        theme.bold(),
    ));
    match d.kind.as_str() {
        "apply_projection" => content.extend(apply_projection_lines(d, width, theme)),
        "declare_interaction" => content.extend(declare_lines(d)),
        _ if let Some(lines) = super::m03::decision_lines(&app.catalog, d) => {
            content.extend(lines);
        }
        // ⟨M05⟩ The first-trust view and the delta review: the recorded action only.
        _ if let Some(lines) = super::m05::decision_lines(&app.catalog, d) => {
            content.extend(lines);
        }
        _ => {
            let text = serde_json::to_string_pretty(&d.request).unwrap_or_default();
            content.extend(text.lines().map(|l| plain(format!("  {}", clean(l)))));
        }
    }
    content.push(plain(IMITATION_TEXT));
    // What the owner confirms is the record itself, not its age.
    let key = fingerprint(&[&d.id, &d.kind, &d.request.to_string()]);
    if let Some(command) = cli_only {
        let prompt = |input: &str| {
            vec![
                Line::styled(
                    format!("Approve in the CLI: run `{command}` · Esc: send nothing"),
                    theme.dim(),
                ),
                prompt_line("Deny", input).style(theme.bold()),
            ]
        };
        return ConfirmParts {
            title: format!("Owner decision {} ({}, read-only)", d.id, clean(&d.kind)),
            content,
            key,
            prompt: prompt(&p.input),
            prompt_reserve: vec![prompt(&full_answer())],
            fill: true,
        };
    }
    let worst = full_answer();
    ConfirmParts {
        title: format!("Owner decision {} ({})", d.id, clean(&d.kind)),
        content,
        key,
        prompt: decision_prompt(p.verdict, &p.input, theme),
        prompt_reserve: [Verdict::Approve, Verdict::Deny]
            .into_iter()
            .map(|v| decision_prompt(v, &worst, theme))
            .collect(),
        fill: true,
    }
}

fn authorization_parts(p: &AuthPrompt) -> ConfirmParts {
    let mut content = vec![plain(format!(
        "The {} level for {} {AUTHORIZATION_TEXT}.",
        level_name(p.level),
        p.alias
    ))];
    let mut prompt = Vec::new();
    let mut prompt_reserve = Vec::new();
    let mut key = vec!["authorization", level_name(p.level), &p.alias];
    match &p.executed {
        None => {
            key.push("pending");
            content.push(plain(
                "Reading your configuration first (static pass; nothing executes)...",
            ));
        }
        Some(found) => {
            content.push(plain("Configuration commands the static pass found:"));
            if found.is_empty() {
                content.push(plain(format!("  {NONE_FOUND_TEXT}")));
            }
            for f in found {
                content.push(plain(format!("  {}", clean(f))));
                key.push(f);
            }
            content.push(plain(
                "Without a typed yes the level is declined (config_commands_not_authorized) and nothing runs.",
            ));
            prompt.push(prompt_line("Authorize", &p.input));
            prompt_reserve.push(vec![prompt_line("Authorize", &full_answer())]);
        }
    }
    ConfirmParts {
        title: format!("Authorize {}", level_name(p.level)),
        content,
        key: fingerprint(&key),
        prompt,
        prompt_reserve,
        fill: false,
    }
}

fn repair_parts(p: &RepairPrompt) -> ConfirmParts {
    let mut content = vec![plain(p.repair.sentence())];
    let mut prompt = Vec::new();
    let mut prompt_reserve = Vec::new();
    let mut key = vec!["repair", p.repair.name(), &p.operation];
    match &p.plan {
        None => {
            key.push("pending");
            content.push(plain("Previewing the repair (nothing changes yet)..."));
        }
        Some(Err(e)) => {
            key.push("refused");
            content.push(plain(format!("The preview was refused: {}", clean(e))));
            prompt.push(plain("Nothing can be sent. Esc closes."));
        }
        Some(Ok(plan)) => {
            key.push(&plan.digest);
            content.push(plain(format!("Plan digest {}", clean(&plan.digest))));
            for line in &plan.lines {
                content.push(plain(format!("  {}", clean(line))));
                key.push(line);
            }
            content.push(plain(
                "It is done only when the refreshed listing shows no held operation.",
            ));
            prompt.push(prompt_line("Submit this repair", &p.input));
            prompt_reserve.push(vec![prompt_line("Submit this repair", &full_answer())]);
        }
    }
    ConfirmParts {
        title: format!("Repair {}: {}", p.operation, p.repair.name()),
        content,
        key: fingerprint(&key),
        prompt,
        prompt_reserve,
        fill: false,
    }
}

fn probe_lines(app: &App, v: &ProbeView) -> Vec<Line<'static>> {
    let report = match &v.report {
        None => {
            return vec![plain(format!(
                "Running the {} level for {}...",
                level_name(v.level),
                v.alias
            ))];
        }
        Some(Err(e)) => return vec![plain(format!("The probe could not run: {}", clean(e)))],
        Some(Ok(r)) => r,
    };
    let mut lines = Vec::new();
    for r in report
        .probes
        .iter()
        .filter(|r| r.level == v.level || v.level == ProbeLevel::Static)
    {
        lines.push(plain(format!(
            "{} {}: {}{}{} ({} ms)",
            level_name(r.level),
            clean(&r.target),
            match r.outcome {
                ProbeOutcome::Ok => "ok",
                ProbeOutcome::Failed => "failed",
                ProbeOutcome::Timeout => "timed out",
                ProbeOutcome::Refused => "refused",
                ProbeOutcome::Declined => "declined",
                _ => "unknown",
            },
            r.decline_reason
                .as_deref()
                .map_or_else(String::new, |d| format!(", {}", clean(d))),
            r.code
                .as_ref()
                .map_or_else(String::new, |c| format!(", {c}")),
            r.duration_ms
        )));
        lines.push(plain(format!(
            "  started {}; authorization: {}; containment {}",
            when(app.now(), Some(r.started_at)),
            if r.authorization.is_empty() {
                "none".to_owned()
            } else {
                r.authorization.join(", ")
            },
            name_of(&r.containment)
        )));
        lines.push(plain(format!("  {INVENTORY_HEADING}:")));
        if r.executed_config_commands.is_empty() {
            lines.push(plain("    (none found by the static pass)"));
        }
        for c in &r.executed_config_commands {
            lines.push(plain(format!("    {}:{}", clean(&c.path_display), c.line)));
        }
        if let Some(changed) = r.config_tree_changed {
            lines.push(plain(format!(
                "  configuration tree changed: {}",
                if changed { "yes" } else { "no" }
            )));
            lines.push(plain(
                "    (a comparison of two snapshots; a change reverted before the second is not seen)",
            ));
            for d in &r.config_tree_differences {
                lines.push(plain(format!(
                    "    {} {}",
                    name_of(&d.change),
                    clean(&d.path_display)
                )));
            }
        }
        let excluded: Vec<String> = r.effects_excluded.iter().map(name_of).collect();
        lines.push(plain(format!(
            "  effects excluded: {}",
            if excluded.is_empty() {
                "none (configuration commands may have done anything)".to_owned()
            } else {
                excluded.join(", ")
            }
        )));
    }
    for f in report.findings.iter().filter(|f| f.level == v.level) {
        lines.push(plain(format!(
            "[ !] {}: {}",
            clean(&f.code),
            clean(&f.message)
        )));
    }
    if lines.is_empty() {
        lines.push(plain("No record for this level."));
    }
    lines
}

/// Draw `app` once into a `w`×`h` test backend, as the event loop does before it reads a
/// key: the open confirmation records what the frame showed. The rows, trailing spaces
/// trimmed.
#[cfg(test)]
pub(crate) fn draw_once(app: &App, w: u16, h: u16) -> Vec<String> {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap_or_else(|e| panic!("{e}"));
    terminal
        .draw(|f| render(f, app))
        .unwrap_or_else(|e| panic!("{e}"));
    let buffer = terminal.backend().buffer().clone();
    (0..h)
        .map(|y| {
            (0..w)
                .map(|x| buffer.cell((x, y)).map_or(" ", |c| c.symbol()))
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::tui::keys::Key;
    use crate::tui::model::tests::{now, populated, press, type_text};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Render `app` at `w`×`h`; the buffer's rows with trailing spaces trimmed.
    fn draw(app: &App, w: u16, h: u16) -> (Vec<String>, ratatui::buffer::Buffer) {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| render(f, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let rows = (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buffer.cell((x, y)).map_or(" ", |c| c.symbol()))
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect();
        (rows, buffer)
    }

    /// Compare with the committed snapshot `snapshots/<name>.txt`. With
    /// `HEIMDALL_TUI_UPDATE_SNAPSHOTS=1` the file is written instead (review the diff).
    fn snapshot(name: &str, rows: &[String]) {
        // The repository through HM_REPO_ROOT (ADR-0007 §12.32 item 3).
        let path = heimdall_testkit::repo::repo_path("crates/heimdall/src/tui/snapshots")
            .join(format!("{name}.txt"));
        let text = rows.join("\n") + "\n";
        if std::env::var_os("HEIMDALL_TUI_UPDATE_SNAPSHOTS").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &text).unwrap();
            return;
        }
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("snapshot {name}: {e} (set HEIMDALL_TUI_UPDATE_SNAPSHOTS=1)")
        });
        assert_eq!(text, expected, "snapshot {name} differs");
    }

    fn no_color(app: &App) -> App {
        let mut a = app.clone();
        a.no_color = true;
        a
    }

    /// The screens of the snapshot set: (name, state).
    fn screens() -> Vec<(&'static str, App)> {
        let mut out = Vec::new();
        let base = populated();
        out.push(("overview", base.clone()));
        let mut a = base.clone();
        press(&mut a, &[Key::Char('2')]);
        out.push(("destinations", a.clone()));
        press(&mut a, &[Key::Char('/')]);
        type_text(&mut a, "be");
        out.push(("destinations_search", a.clone()));
        let mut a = base.clone();
        press(&mut a, &[Key::Char('2'), Key::Enter]);
        out.push(("destination_detail", a.clone()));
        let mut a = base.clone();
        press(&mut a, &[Key::Char('3')]);
        out.push(("profiles", a));
        let mut a = base.clone();
        press(&mut a, &[Key::Char('4')]);
        out.push(("activity", a));
        let mut a = base.clone();
        press(&mut a, &[Key::Char('4'), Key::Down, Key::Down, Key::Enter]);
        a.apply(crate::tui::model::Update::Operation {
            id: "op_held1".to_owned(),
            detail: crate::tui::data::OperationDetail {
                operation: None,
                events: vec![crate::tui::data::EventLine {
                    kind: "operation_state_changed".to_owned(),
                    at: Some(crate::tui::model::tests::t("2026-11-03T08:59:10Z")),
                    summary: "state=outcome_unknown code=OUTCOME_UNKNOWN".to_owned(),
                }],
                error: None,
            },
        });
        out.push(("operation_held", a));
        let mut a = base.clone();
        press(&mut a, &[Key::Char('4'), Key::Enter]);
        type_text(&mut a, "ye");
        out.push(("decision_apply", a));
        let mut a = base.clone();
        press(&mut a, &[Key::Char('4'), Key::Down, Key::Enter]);
        out.push(("decision_declare", a));
        let mut a = base.clone();
        press(
            &mut a,
            &[Key::Char('2'), Key::Char('p'), Key::Down, Key::Enter],
        );
        a.apply(crate::tui::model::Update::ProbePrepared {
            alias: "alpha".to_owned(),
            level: ProbeLevel::Evaluate,
            executed: vec!["~/.ssh/config:12".to_owned()],
            not_fully_readable: false,
        });
        out.push(("authorization", a));
        let mut fresh = App::new(now(), false);
        fresh.set_runtime(Runtime::NotRunning);
        out.push(("first_frame", fresh));
        // ⟨M07⟩ The error states (Q4) and the grouped overview (probe P4).
        let mut a = base.clone();
        a.catalog_mut()
            .failures
            .insert("destinations".to_owned(), frame_limit_failure(true));
        press(&mut a, &[Key::Char('2')]);
        out.push(("m07_destinations_failed_stale", a));
        let mut a = base.clone();
        a.catalog_mut().profiles.clear();
        a.catalog_mut()
            .failures
            .insert("profiles".to_owned(), frame_limit_failure(false));
        press(&mut a, &[Key::Char('3')]);
        out.push(("m07_profiles_failed_never_read", a));
        let mut a = base.clone();
        a.catalog_mut()
            .failures
            .insert("decisions".to_owned(), frame_limit_failure(true));
        press(&mut a, &[Key::Char('4')]);
        out.push(("m07_activity_failed", a));
        out.push(("m07_overview_grouped", grouped_app(100)));
        out.extend(m07_screens());
        out.extend(w1_screens());
        out
    }

    /// Every listing the worker reads, by its name in the failure cache.
    const SUBJECTS: [&str; 12] = [
        "destinations",
        "profiles",
        "identities",
        "operations",
        "decisions",
        "projections",
        "enrollments",
        "connections",
        "capabilities",
        "environments",
        "policies",
        "workspace",
    ];

    /// What the worker publishes when the session drops after good reads (M07-W0-R03):
    /// the connection failed, and every listing keeps its last good data, marked failed.
    fn disconnected(app: &App) -> App {
        use crate::tui::model::Update;
        let mut app = app.clone();
        app.apply(Update::Runtime(Runtime::Failed(
            "the runtime closed the connection".to_owned(),
        )));
        let mut stale = app.catalog().clone();
        for name in SUBJECTS {
            stale.failures.insert(
                name.to_owned(),
                crate::tui::data::ListingFailure {
                    code: "SERVICE_UNAVAILABLE".to_owned(),
                    message: "the runtime closed the connection".to_owned(),
                    since: crate::tui::model::tests::t("2026-11-03T09:00:28Z"),
                    stale_from: Some(crate::tui::model::tests::t("2026-11-03T09:00:25Z")),
                },
            );
        }
        app.apply(Update::Catalog(Box::new(stale)));
        app
    }

    /// ⟨M07⟩ The W1 review fixes' screens: the lock detail (R04), the overview after a
    /// dropped session and Settings with a policy list that was never read (R03), and the
    /// Destinations list scoped to a grouped finding (R11).
    fn w1_screens() -> Vec<(&'static str, App)> {
        use crate::tui::m07::{SettingRow, fixtures};
        let base = fixtures::app();
        let mut lock = base.clone();
        press(&mut lock, &[Key::Char('8')]);
        lock.selected[Tab::Settings.index()] = lock
            .setting_rows()
            .iter()
            .position(|r| *r == SettingRow::Lock)
            .unwrap();
        press(&mut lock, &[Key::Enter]);
        lock.status = None;
        let mut unread = base.clone();
        let c = unread.catalog_mut();
        c.m05.policies = None;
        c.m05.default_profiles.clear();
        c.failures
            .insert("policies".to_owned(), frame_limit_failure(false));
        press(&mut unread, &[Key::Char('8')]);
        let mut scoped = grouped_app(100);
        scoped.selected[0] = scoped
            .overview_items()
            .iter()
            .position(|i| matches!(i, Item::Findings { .. }))
            .unwrap();
        press(&mut scoped, &[Key::Enter]);
        vec![
            ("m07_lock", lock),
            ("m07_overview_disconnected", disconnected(&base)),
            ("m07_settings_policies_unread", unread),
            ("m07_destinations_scoped", scoped),
        ]
    }

    /// ⟨M07⟩ U1b's views (m07-plan U1 "Snapshots of the new views"): the overview with
    /// the environment, access, lock and stop lines; Projects, Environments, Identities
    /// and Settings with their details; a Settings change and its confirmation; and the
    /// default surfaces of U2 (first trust, the stop menu and its confirmation, key help).
    fn m07_screens() -> Vec<(&'static str, App)> {
        use crate::tui::m07::fixtures;
        let base = fixtures::app();
        let mut out = vec![("m07_overview", base.clone())];
        let after = |keys: &[Key], text: &str| {
            let mut a = base.clone();
            press(&mut a, keys);
            type_text(&mut a, text);
            a
        };
        out.push(("m07_projects", after(&[Key::Char('5')], "")));
        out.push(("m07_environments", after(&[Key::Char('6')], "")));
        out.push((
            "m07_environment_detail",
            after(&[Key::Char('6'), Key::Down, Key::Enter], ""),
        ));
        out.push(("m07_identities", after(&[Key::Char('7')], "")));
        out.push((
            "m07_identity_detail",
            after(&[Key::Char('7'), Key::Enter], ""),
        ));
        out.push(("m07_settings", after(&[Key::Char('8'), Key::Down], "")));
        out.push((
            "m07_settings_change",
            after(&[Key::Char('8'), Key::Down, Key::Enter], ""),
        ));
        out.push((
            "m07_settings_confirm",
            after(
                &[
                    Key::Char('8'),
                    Key::Down,
                    Key::Enter,
                    Key::Down,
                    Key::Down,
                    Key::Enter,
                ],
                "ye",
            ),
        ));
        let mut trust = after(&[Key::Char('4'), Key::Enter], "");
        crate::tui::model::tests::read(&trust);
        trust.status = None;
        out.push(("m07_first_trust", trust));
        out.push(("m07_stop_menu", after(&[Key::Char('s')], "")));
        let mut stop = after(&[Key::Char('s'), Key::Down, Key::Enter], "job-7");
        press(&mut stop, &[Key::Enter]);
        out.push(("m07_stop_confirm", stop));
        out.push(("m07_help", after(&[Key::Char('?')], "")));
        out
    }

    /// ⟨M07⟩ The failure probe P3b observed past about 7,000 destinations; with
    /// `stale`, an earlier read succeeded.
    fn frame_limit_failure(stale: bool) -> crate::tui::data::ListingFailure {
        crate::tui::data::ListingFailure {
            code: "INTERNAL_ERROR".to_owned(),
            message: "response exceeds the frame limit".to_owned(),
            since: crate::tui::model::tests::t("2026-11-03T09:00:20Z"),
            stale_from: stale.then(|| crate::tui::model::tests::t("2026-11-03T08:57:00Z")),
        }
    }

    /// ⟨M07⟩ `n` observed destinations, each with the same warning (probe P4's fresh
    /// catalog), plus one finding about the configuration; nothing else waits.
    fn grouped_app(n: usize) -> App {
        use crate::tui::model::tests::{destination, finding};
        use heimdall_contract::doctor::FindingSeverity;
        let mut app = populated();
        let catalog = app.catalog_mut();
        catalog.operations.clear();
        catalog.decisions.clear();
        catalog.destinations = (0..n)
            .map(|i| destination(&format!("host-{i:06}"), false))
            .collect();
        let doctor = app.doctor_mut().as_mut().unwrap();
        let mut home = finding("home_mismatch", FindingSeverity::Warning, None);
        home.subject.kind = "configuration".to_owned();
        home.message = "HOME differs from the account's home".to_owned();
        doctor.report.findings = std::iter::once(home)
            .chain((0..n).map(|i| {
                let mut f = finding(
                    "identity_selection_not_exclusive",
                    FindingSeverity::Warning,
                    Some(&format!("host-{i:06}")),
                );
                f.message =
                    "ssh may offer other identities than the adopted key for this alias".to_owned();
                f
            }))
            .collect();
        app
    }

    /// m02-plan U10: `TestBackend` snapshots at 40×12 and 120×40, color and `NO_COLOR`.
    #[test]
    fn testbackend_snapshots_at_40x12_and_120x40() {
        for (name, app) in screens() {
            for (w, h) in [(40, 12), (120, 40)] {
                let (rows, _) = draw(&app, w, h);
                snapshot(&format!("{name}_{w}x{h}"), &rows);
                // NO_COLOR draws the same text: the meaning is in the text.
                let (plain_rows, _) = draw(&no_color(&app), w, h);
                assert_eq!(
                    rows, plain_rows,
                    "{name} {w}x{h}: text differs under NO_COLOR"
                );
            }
        }
    }

    /// m02-plan U10 `NO_COLOR`: no cell carries a color, and every state is still told
    /// by a text marker.
    #[test]
    fn no_color_carries_no_color_and_every_state_has_a_text_marker() {
        for (name, app) in screens() {
            for (w, h) in [(40, 12), (120, 40)] {
                let (_, buffer) = draw(&no_color(&app), w, h);
                for c in buffer.content() {
                    assert_eq!(c.fg, Color::Reset, "{name} {w}x{h}: {c:?}");
                    assert_eq!(c.bg, Color::Reset, "{name} {w}x{h}: {c:?}");
                }
            }
        }
        // The overview's states, in words and markers, with and without color.
        let app = populated();
        for a in [app.clone(), no_color(&app)] {
            let (rows, _) = draw(&a, 120, 40);
            let text = rows.join("\n");
            assert!(text.contains("[!!] Needs attention"), "{text}");
            assert!(text.contains("[!!] held: setup op_held1"), "{text}");
            assert!(
                text.contains("[..] working: access request op_run1"),
                "{text}"
            );
            // ⟨M07⟩ A destination finding is a grouped row: the alias (or the count),
            // then the finding's own words.
            assert!(
                text.contains(
                    "[ !] beta: ssh may offer other identities than the adopted key for this alias"
                ),
                "{text}"
            );
            assert!(text.contains("> [!!]"), "the selection is marked in text");
            assert!(text.contains("[1 Overview]"), "the tab is marked in text");
        }
        let mut ready = populated();
        ready.catalog_mut().operations.clear();
        ready.catalog_mut().decisions.clear();
        let (rows, _) = draw(&no_color(&ready), 120, 40);
        assert!(rows.join("\n").contains("[OK] Ready"));
        let mut working = populated();
        working.catalog_mut().operations.retain(|o| !o.is_held());
        working.catalog_mut().decisions.clear();
        let (rows, _) = draw(&no_color(&working), 40, 12);
        assert!(rows.join("\n").contains("[..] Working"));
        // Destination provenance is in words.
        let mut d = no_color(&populated());
        press(&mut d, &[Key::Char('2'), Key::Enter]);
        let (rows, _) = draw(&d, 120, 40);
        let text = rows.join("\n");
        for class in ["[managed]", "[inherited]", "[undetermined]"] {
            assert!(text.contains(class), "{class}: {text}");
        }
    }

    /// ⟨M07⟩ The new views tell every state in text, with and without color: the
    /// environments' states, the identities' background use, the settings' state, and
    /// the selection (the no-color half is the loop above, over `screens()`).
    #[test]
    fn m07_views_carry_text_markers() {
        let screens = m07_screens();
        let text = |name: &str| {
            let app = &screens.iter().find(|(n, _)| *n == name).unwrap().1;
            draw(&no_color(app), 120, 40).0.join("\n")
        };
        let envs = text("m07_environments");
        for marker in ["> [OK] this computer", "[ !] WSL Ubuntu", "[--] builder"] {
            assert!(envs.contains(marker), "{marker}: {envs}");
        }
        assert!(envs.contains("not running"), "{envs}");
        let ids = text("m07_identities");
        for marker in ["[OK] idn_alpha", "[ !] idn_k2", "[??] idn_k3"] {
            assert!(ids.contains(marker), "{marker}: {ids}");
        }
        let settings = text("m07_settings");
        for marker in [
            "[OK] Default profile: dev · this computer",
            "> [OK] pol-ws1 · profile dev · project · automatic",
            "[!!] pol-per1 · profile dev · personal · paused since",
            "[ i] Saved: continue (personal access)",
            "[ i] alpha: existing sessions may stay connected after the deadline",
        ] {
            assert!(settings.contains(marker), "{marker}: {settings}");
        }
        // Detail panels: each value's provenance and freshness.
        let env = text("m07_environment_detail");
        assert!(
            env.contains("Source: the runtime's environment list (inspect environments), read 09:00:25Z (just now)"),
            "{env}"
        );
        assert!(env.contains("[runtime] state [ !] not running"), "{env}");
        let id = text("m07_identity_detail");
        assert!(
            id.contains("Source: the runtime's identity list (inspect identities), read"),
            "{id}"
        );
        assert!(
            id.contains("[declared] declared 2026-11-01T10:00:00Z"),
            "{id}"
        );
        assert!(id.contains("(checked 09:00:25Z (just now))"), "{id}");
        assert!(
            settings.contains("Source: inspect policies (the runtime's record of pol-ws1), read"),
            "{settings}"
        );
        let projects = text("m07_projects");
        assert!(
            projects
                .contains("Source: inspect workspace (this directory) and inspect policies, read"),
            "{projects}"
        );
        assert!(projects.contains("[OK] trusted"), "{projects}");
    }

    /// The screens `every_footer_and_help_key_is_bound` presses keys on: every screen and
    /// open prompt with a footer, each in a state where its keys have something to act on
    /// (a list's selection in its middle, a detail scrolled one row).
    fn key_screens() -> Vec<(&'static str, App)> {
        use crate::tui::m07::fixtures;
        let base = fixtures::app();
        let on = |keys: &[Key]| {
            let mut a = base.clone();
            press(&mut a, keys);
            a
        };
        let mut out = vec![("overview", on(&[]))];
        for (name, keys) in [
            ("destinations", &[Key::Char('2')][..]),
            ("profiles", &[Key::Char('3')]),
            ("activity", &[Key::Char('4')]),
            ("projects", &[Key::Char('5')]),
            ("environments", &[Key::Char('6')]),
            ("identities", &[Key::Char('7')]),
            ("settings", &[Key::Char('8')]),
        ] {
            let mut a = on(keys);
            a.selected[a.tab.index()] = 1;
            a.scroll = 1;
            out.push((name, a));
        }
        // A second profile, so the Profiles selection can move both ways.
        if let Some((_, a)) = out.iter_mut().find(|(n, _)| *n == "profiles") {
            let mut p = a.catalog().profiles[0].clone();
            p.id = "ops".to_owned();
            let mut q = p.clone();
            q.id = "web".to_owned();
            a.catalog_mut().profiles.extend([p, q]);
        }
        // The Destinations list scoped to a grouped finding (Esc shows all).
        let mut scoped = grouped_app(100);
        scoped.selected[0] = scoped
            .overview_items()
            .iter()
            .position(|i| matches!(i, Item::Findings { .. }))
            .unwrap();
        press(&mut scoped, &[Key::Enter]);
        out.push(("scoped destinations", scoped));
        let mut prompt = on(&[Key::Char('8'), Key::Down, Key::Enter]);
        if let Some(p) = &mut prompt.settings {
            p.selected = 1;
        }
        out.push(("settings change", prompt));
        out.push((
            "settings value",
            on(&[Key::Char('8'), Key::Enter, Key::Enter]),
        ));
        out.push((
            "settings confirm",
            on(&[Key::Char('8'), Key::Down, Key::Enter, Key::Enter]),
        ));
        for (name, keys) in [
            ("destination detail", &[Key::Char('2'), Key::Enter][..]),
            ("profile detail", &[Key::Char('3'), Key::Enter]),
            ("environment detail", &[Key::Char('6'), Key::Enter]),
            ("identity detail", &[Key::Char('7'), Key::Enter]),
            // Settings rows of the fixture: own default, two policies, then the lock row.
            (
                "lock detail",
                &[Key::Char('8'), Key::Down, Key::Down, Key::Down, Key::Enter],
            ),
            ("workspace", &[Key::Char('w')]),
            ("policies", &[Key::Char('h')]),
            // The held operation (r, k) and the running one (x).
            ("held operation", &[Key::Enter]),
        ] {
            let mut a = on(keys);
            a.scroll = 1;
            out.push((name, a));
        }
        let mut running = on(&[]);
        running.selected[0] = running
            .overview_items()
            .iter()
            .position(|i| matches!(i, Item::Working { .. }))
            .unwrap();
        press(&mut running, &[Key::Enter]);
        running.scroll = 1;
        out.push(("running operation", running));
        // An operation that waits on a decision (Enter opens it).
        let mut waiting = on(&[]);
        waiting
            .catalog_mut()
            .decisions
            .push(crate::tui::model::tests::apply_decision());
        waiting.catalog_mut().operations.push(
            crate::tui::data::Operation::of(&serde_json::json!({
                "operation_id": "op_apply1", "kind": "setup.apply", "state": "awaiting_approval",
            }))
            .unwrap(),
        );
        waiting.screen = Screen::Operation("op_apply1".to_owned());
        waiting.scroll = 1;
        out.push(("waiting operation", waiting));
        out
    }

    /// Whether `key` does something on `app`: an effect, or a change of what is shown.
    fn reacts(app: &App, key: Key) -> bool {
        let mut a = app.clone();
        let effects = a.key(key);
        !effects.is_empty()
            || a.screen != app.screen
            || a.tab != app.tab
            || a.modal != app.modal
            || a.selected != app.selected
            || a.scroll != app.scroll
            || a.status != app.status
            || a.settings != app.settings
            || a.scope() != app.scope()
            || a.search(a.tab) != app.search(app.tab)
    }

    /// m07-plan U1 `every_footer_and_help_key_is_bound`: every key a footer names is
    /// handled on that screen (a view number takes you to that view), every key the narrow
    /// footer names is one of the wide footer's, and every key the help (`?`) names is
    /// handled on at least one screen.
    #[test]
    fn every_footer_and_help_key_is_bound() {
        let screens = key_screens();
        for (name, app) in &screens {
            assert!(app.modal.is_none(), "{name}: a screen, not a modal");
            let hints = screen_hints(app);
            assert!(!hints.is_empty(), "{name}: a footer");
            for h in &hints {
                for key in h.keys {
                    if let Key::Char(d @ '1'..='8') = key {
                        let mut a = app.clone();
                        a.key(*key);
                        let want = Tab::ALL[usize::from(*d as u8 - b'1')];
                        assert_eq!(a.screen, Screen::Tab(want), "{name}: {d}");
                        continue;
                    }
                    assert!(
                        reacts(app, *key),
                        "{name}: footer key {key:?} ({}) does nothing",
                        h.wide
                    );
                }
            }
            // Both footers fit their widths, so the hints are readable.
            assert!(
                footer_text(&hints, true).chars().count() <= 40,
                "{name}: {}",
                footer_text(&hints, true)
            );
            assert!(
                footer_text(&hints, false).chars().count() <= 120,
                "{name}: {}",
                footer_text(&hints, false)
            );
        }
        for (keys, text) in HELP_LINES {
            for key in keys {
                assert!(
                    screens.iter().any(|(_, a)| reacts(a, *key)),
                    "help key {key:?} ({text}) does nothing on any screen"
                );
            }
        }
        // The help names every footer key.
        let help: Vec<Key> = HELP_LINES
            .iter()
            .flat_map(|(k, _)| k.iter().copied())
            .collect();
        for (name, app) in &screens {
            if app.settings.is_some() {
                continue;
            }
            for h in screen_hints(app) {
                for key in h.keys {
                    let named = help.contains(key) || matches!(key, Key::Char('1'..='8'));
                    assert!(named, "{name}: footer key {key:?} is not in the help");
                }
            }
        }
    }

    /// The words the default surfaces never use (spec §5.1): they belong to detail views.
    const ADVANCED: [&str; 7] = [
        "grant",
        "lease",
        "certificate",
        "issuer",
        "generation",
        "epoch",
        "principal",
    ];

    /// The advanced words and raw codes in `text`: words starting with one of
    /// [`ADVANCED`], and snake_case or SCREAMING_SNAKE codes (identifiers with digits,
    /// such as `op_held1`, are IDs, not codes).
    fn jargon(text: &str) -> Vec<String> {
        text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .filter(|w| {
                let lower = w.to_lowercase();
                let code = w.contains('_')
                    && !w.starts_with('_')
                    && !w.ends_with('_')
                    && (w.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                        || w.chars().all(|c| c.is_ascii_uppercase() || c == '_'));
                code || ADVANCED.iter().any(|a| lower.starts_with(a))
            })
            .map(str::to_owned)
            .collect()
    }

    /// m07-plan U2 `default_surfaces_use_everyday_vocabulary`: the default surfaces (the
    /// overview in each state, first trust, the stop menu and its confirmation) say grant,
    /// lease, certificate, issuer, generation, epoch and principal nowhere, and show no raw
    /// code. Every snapshot screen is classified: a default surface, or one of the detail
    /// screens listed below, where the advanced words and codes belong.
    #[test]
    fn default_surfaces_use_everyday_vocabulary() {
        const DEFAULT: [&str; 8] = [
            "overview",
            "first_frame",
            "m07_overview_grouped",
            "m07_overview",
            "m07_overview_disconnected",
            "m07_first_trust",
            "m07_stop_menu",
            "m07_stop_confirm",
        ];
        // Detail and list screens: provenance, codes and mechanisms are their content.
        const DETAIL: [&str; 24] = [
            "m07_lock",
            "m07_settings_policies_unread",
            "m07_destinations_scoped",
            "destinations",
            "destinations_search",
            "destination_detail",
            "profiles",
            "activity",
            "operation_held",
            "decision_apply",
            "decision_declare",
            "authorization",
            "m07_destinations_failed_stale",
            "m07_profiles_failed_never_read",
            "m07_activity_failed",
            "m07_projects",
            "m07_environments",
            "m07_environment_detail",
            "m07_identities",
            "m07_identity_detail",
            "m07_settings",
            "m07_settings_change",
            "m07_settings_confirm",
            "m07_help",
        ];
        // On a default surface, only these, each for its reason.
        let allowed: [(&str, &str, &str); 1] = [(
            "m07_first_trust",
            "trust_workspace",
            "the decision modal's title (`Owner decision <id> (<kind>)`) comes from the shared decision-modal dispatch, kept byte-identical for M06",
        )];
        for (name, app) in screens() {
            let default = DEFAULT.contains(&name);
            assert!(
                default != DETAIL.contains(&name),
                "{name}: classify it as a default surface or a detail screen"
            );
            if !default {
                continue;
            }
            for (w, h) in [(120, 40), (40, 12)] {
                let text = draw(&app, w, h).0.join("\n");
                for word in jargon(&text) {
                    // A narrow title cuts the code; the cut code is the same exception.
                    let ok = allowed.iter().any(|(screen, token, _)| {
                        *screen == name && token.starts_with(word.as_str()) && word.len() >= 5
                    });
                    assert!(ok, "{name} {w}x{h}: {word:?} on a default surface:\n{text}");
                }
            }
        }
        // The detector itself.
        assert_eq!(
            jargon(
                "a grant, leases, identity_selection_not_exclusive, INTERNAL_ERROR, op_held1, release"
            ),
            [
                "grant",
                "leases",
                "identity_selection_not_exclusive",
                "INTERNAL_ERROR"
            ]
        );
    }

    /// What the lock wording never says (M07-W0-R04): a categorical outcome, which the
    /// runtime does not attest.
    const CATEGORICAL_LOCK: [&str; 6] = [
        "work continues while your desktop is locked",
        "Work continues while the desktop is locked",
        "work continues",
        "locking your desktop ends managed access",
        "Locking the desktop ends managed access",
        "locking ends access",
    ];

    fn no_categorical_lock_claim(text: &str) {
        for claim in CATEGORICAL_LOCK {
            assert!(!text.contains(claim), "{claim:?} is not attested:\n{text}");
        }
    }

    /// m07-plan U2 `a30_surfaces_answer_the_three_questions` (A30's deterministic part):
    /// from the default surfaces alone, at both sizes, a user can see which environment has
    /// access, what the desktop lock is set to do, and how to pause or stop.
    ///
    /// ⟨M07⟩ M07-W0-R04: the lock answer is checked for its **qualified** wording. The
    /// overview names the saved setting as a saved setting of personal access, says that
    /// project settings and the observed effect are not known there, points at Settings,
    /// and never states an outcome; the lock detail it points at shows the runtime's own
    /// statement.
    #[test]
    fn a30_surfaces_answer_the_three_questions() {
        use crate::tui::m07::fixtures;
        let base = fixtures::app();
        for (w, h) in [(120, 40), (40, 12)] {
            let text = draw(&base, w, h).0.join("\n");
            // 1. Which environment has access.
            if w == 120 {
                assert!(
                    text.contains("Access: this computer uses dev automatically"),
                    "{text}"
                );
                assert!(
                    text.contains("Environment: this computer (native session)"),
                    "{text}"
                );
            } else {
                assert!(text.contains("Here: this computer"), "{text}");
                assert!(text.contains("Access: dev auto"), "{text}");
            }
            // 2. What the desktop lock is set to do: the saved setting, qualified.
            if w == 120 {
                assert!(
                    text.contains(
                        "Desktop lock: saved personal setting \"continue\" · project settings, observed effect: not known here · 8 Settings"
                    ),
                    "{text}"
                );
            } else {
                assert!(text.contains("Lock setting: continue · s stop"), "{text}");
            }
            no_categorical_lock_claim(&text);
            // 3. How to pause or stop.
            assert!(
                text.contains(if w == 120 {
                    "Pause or stop access: press s"
                } else {
                    "s stop"
                }),
                "{text}"
            );
        }
        // The other saved setting, and a paused profile, in the same words.
        let mut locked = base.clone();
        if let Some(l) = &mut locked.catalog_mut().m03.lock {
            l.behavior = "revoke_on_lock".to_owned();
        }
        if let Some(ps) = &mut locked.catalog_mut().m05.policies {
            for p in ps {
                p.paused_since = Some(crate::tui::model::tests::t("2026-11-03T08:00:00Z"));
            }
        }
        let text = draw(&locked, 120, 40).0.join("\n");
        assert!(
            text.contains("Desktop lock: saved personal setting \"revoke on lock\" · project settings, observed effect: not known here"),
            "{text}"
        );
        no_categorical_lock_claim(&text);
        assert!(
            text.contains("Access: this computer has no automatic access now; paused: dev"),
            "{text}"
        );
        let narrow = draw(&locked, 40, 12).0.join("\n");
        assert!(
            narrow.contains("Lock setting: revoke on lock · s stop"),
            "{narrow}"
        );
        no_categorical_lock_claim(&narrow);
        // Without a runtime the way to stop is still named.
        let mut fresh = App::new(now(), false);
        fresh.set_runtime(Runtime::NotRunning);
        for (w, h) in [(120, 40), (40, 12)] {
            let text = draw(&fresh, w, h).0.join("\n");
            assert!(
                text.contains("press s") || text.contains("s: pause or stop"),
                "{text}"
            );
        }
        // `s` opens the stop menu, whose actions say what each does.
        let mut menu = base.clone();
        press(&mut menu, &[Key::Char('s')]);
        let text = draw(&menu, 120, 40).0.join("\n");
        for expected in [
            "1. Pause automatic access",
            "2. Stop this work",
            "3. Stop all for a profile",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        // First trust answers all three in its first lines.
        let mut trust = base.clone();
        press(&mut trust, &[Key::Char('4'), Key::Enter]);
        let text = draw(&trust, 120, 40).0.join("\n");
        for expected in [
            "Use dev access automatically for this project?",
            "Work can continue while your desktop and password manager are locked",
            "You can pause or remove access at any time.",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
    }

    /// The Settings lock row of `app`, selected.
    fn on_lock_row(app: &App) -> App {
        let mut a = app.clone();
        press(&mut a, &[Key::Char('8')]);
        a.selected[Tab::Settings.index()] = a
            .setting_rows()
            .iter()
            .position(|r| *r == crate::tui::m07::SettingRow::Lock)
            .unwrap();
        a
    }

    /// Every row a scrolled screen shows, read frame after frame, squashed.
    fn read_scrolled(app: &App, w: u16, h: u16) -> String {
        let mut a = app.clone();
        let mut all = String::new();
        for _ in 0..40 {
            let rows = draw(&a, w, h).0;
            all.push_str(&squash(&rows[1..rows.len() - 1].join("")));
            a.scroll += h.saturating_sub(3).max(1);
        }
        all
    }

    /// Every content row of the open Settings confirmation, collected the way the owner
    /// reads it (frame after frame, one row further down each time), squashed.
    fn read_setting_confirm(app: &App, w: u16, h: u16) -> String {
        let mut app = app.clone();
        draw(&app, w, h);
        let d = app.settings.as_ref().unwrap().seen.reading.drawn().unwrap();
        let mut all = vec![String::new(); d.total];
        for scroll in 0..=d.total.saturating_sub(d.viewport) {
            app.settings.as_mut().unwrap().seen.reading.scroll = scroll;
            let rows = draw(&app, w, h).0;
            let boxed = rows.iter().filter(|r| r.starts_with('│'));
            for (i, row) in boxed.take(d.viewport).enumerate() {
                if let Some(slot) = all.get_mut(scroll + i) {
                    *slot = squash(row.trim_matches('│'));
                }
            }
        }
        all.concat()
    }

    /// M07-W0-R04: the lock wording states only what the runtime attests.
    ///
    /// * **Mixed personal and project policies** (the fixture has one of each): the saved
    ///   setting is named as the personal one; the project's is said to be unknown here,
    ///   on the overview, in the Settings row, in the project policy's detail and in the
    ///   lock detail, which also says that the strictest applicable setting decides.
    /// * **Unverified continuity, and an unverified lock signal:** the runtime's own
    ///   disclosure (built here by `heimdall_app::lock::disclosure`, never retyped) is
    ///   shown word for word in the lock detail and in the confirmation of a lock change,
    ///   so its "not been verified yet" reaches the owner; with no statement from the
    ///   runtime the surfaces say that continuity is unverified.
    /// * No surface states a categorical outcome, in either setting, at either size.
    #[test]
    fn lock_wording_states_only_what_the_runtime_attests() {
        use crate::tui::m07::fixtures::{self, lock_report};
        use heimdall_app::lock::LockSignal;
        use heimdall_contract::managed::LockBehavior;
        let base = fixtures::app();
        let policies = base.catalog().m05.policies.clone().unwrap();
        assert!(
            policies.iter().any(|p| p.workspace_id.is_some())
                && policies.iter().any(|p| p.workspace_id.is_none()),
            "a project policy and a personal one"
        );
        // Saved, separately from observed.
        let row = on_lock_row(&base);
        let settings = draw(&row, 120, 40).0.join("\n");
        assert!(
            settings.contains(
                "> [ i] Saved: continue (personal access) · projects, observed effect: not known here"
            ),
            "{settings}"
        );
        assert!(
            settings.contains("A saved setting, not an observation of what a lock does"),
            "{settings}"
        );
        let mut project = base.clone();
        press(&mut project, &[Key::Char('8'), Key::Down]);
        let text = draw(&project, 120, 40).0.join("\n");
        assert!(
            text.contains("> [OK] pol-ws1 · profile dev · project"),
            "{text}"
        );
        assert!(
            text.contains(
                "Its own lock and connection settings are not in this listing: not known here."
            ),
            "{text}"
        );
        let mut detail = row.clone();
        press(&mut detail, &[Key::Enter]);
        assert_eq!(detail.screen, Screen::Lock);
        for (w, h) in SIZES {
            let text = read_scrolled(&detail, w, h);
            for expected in [
                "Saved setting",
                "\"continue\": the strictest of your configuration and your personal standing access in this environment.",
                "A project's standing access has its own setting. No listing this view reads reports it: not known here.",
                "For one piece of work, the strictest setting that applies to it decides.",
                "Observed",
                "This view has no report of what a lock did, or will do, to work that is running: not known here.",
                "The runtime's statement (its own words)",
                "heimdall access lock-behavior --policy <policy> continue|revoke-on-lock",
            ] {
                assert!(
                    text.contains(&squash(expected)),
                    "{w}x{h} {expected}:\n{text}"
                );
            }
        }
        // The runtime's qualified statement, word for word, in three states of the world.
        for (floor, signal, qualifier) in [
            (
                LockBehavior::Continue,
                LockSignal::MacosScreenLock,
                "On this computer that has not been verified yet.",
            ),
            (
                LockBehavior::RevokeOnLock,
                LockSignal::LinuxLogind,
                "The screen-lock signal on this computer has not been verified yet.",
            ),
            (
                LockBehavior::Continue,
                LockSignal::None,
                "Revoke on lock is not available on this computer",
            ),
        ] {
            let report = lock_report(floor, signal);
            let statement = report.disclosure.clone().unwrap();
            assert!(statement.contains(qualifier), "{statement}");
            let mut app = base.clone();
            app.catalog_mut().m03.lock = Some(report);
            let mut detail = on_lock_row(&app);
            press(&mut detail, &[Key::Enter]);
            for (w, h) in SIZES {
                let text = read_scrolled(&detail, w, h);
                assert!(
                    text.contains(&squash(&statement)),
                    "{w}x{h}: the runtime's statement, whole:\n{text}"
                );
                no_categorical_lock_claim(&draw(&app, w, h).0.join("\n"));
            }
            // A lock change's confirmation carries it too, with what the setting is.
            for (choice, name) in [(1, "revoke on lock"), (2, "continue")] {
                let mut change = app.clone();
                press(&mut change, &[Key::Char('8'), Key::Down, Key::Enter]);
                for _ in 0..choice {
                    press(&mut change, &[Key::Down]);
                }
                let choices = draw(&change, 120, 40).0.join("\n");
                no_categorical_lock_claim(&choices);
                assert!(
                    choices.contains(&format!("Lock setting: {name}")),
                    "{choices}"
                );
                press(&mut change, &[Key::Enter]);
                for (w, h) in SIZES {
                    let text = read_setting_confirm(&change, w, h);
                    for expected in [
                        format!("Set the saved lock setting of pol-ws1 to \"{name}\""),
                        "This saves a setting of this entry only.".to_owned(),
                        "this view has no report of what a lock does to work that is running"
                            .to_owned(),
                        format!("The runtime's statement now (its own words): {statement}"),
                    ] {
                        assert!(
                            text.contains(&squash(&expected)),
                            "{w}x{h} {name}: {expected}\n{text}"
                        );
                    }
                    for claim in CATEGORICAL_LOCK {
                        assert!(!text.contains(&squash(claim)), "{claim}: {text}");
                    }
                }
            }
        }
        // The runtime sent no statement: continuity is said to be unverified.
        let mut silent = base.clone();
        if let Some(l) = &mut silent.catalog_mut().m03.lock {
            l.disclosure = None;
        }
        let mut detail = on_lock_row(&silent);
        press(&mut detail, &[Key::Enter]);
        let text = read_scrolled(&detail, 120, 40);
        assert!(
            text.contains(&squash(
                "The runtime sent no statement: whether work keeps going at a lock is unverified here."
            )),
            "{text}"
        );
        // No lock report at all: nothing is claimed.
        let mut none = base.clone();
        none.catalog_mut().m03.lock = None;
        let text = draw(&none, 120, 40).0.join("\n");
        assert!(
            text.contains("Desktop lock: not reported by the runtime"),
            "{text}"
        );
        no_categorical_lock_claim(&text);
    }

    /// m02-plan U10 ⟨r2⟩ `decision_modal_shows_restore_column`: an `ApplyProjection`
    /// decision shows the before, after and restore columns of the recorded request,
    /// side by side when wide and one under the other when narrow.
    #[test]
    fn decision_modal_shows_restore_column() {
        let mut app = populated();
        press(&mut app, &[Key::Char('4'), Key::Enter]);
        let (rows, _) = draw(&app, 120, 40);
        let header = rows
            .iter()
            .find(|r| r.contains("Before") && r.contains("After") && r.contains("Restore"))
            .unwrap_or_else(|| panic!("no column header: {rows:#?}"));
        let (b, a, r) = (
            header.find("Before").unwrap(),
            header.find("After").unwrap(),
            header.find("Restore").unwrap(),
        );
        assert!(b < a && a < r, "{header}");
        let text = rows.join("\n");
        // Before: the line the plan removes; after: the line it adds; restore: the
        // item and its behavior digest if its section were removed now.
        let before_row = rows
            .iter()
            .find(|l| l.contains("HostName old.example.invalid"))
            .unwrap();
        let after_row = rows
            .iter()
            .find(|l| l.contains("HostName alpha.example.invalid"))
            .unwrap();
        assert!(before_row.find("old.example").unwrap() < a);
        assert!(after_row.find("alpha.example").unwrap() >= a);
        assert!(text.contains("alias:alpha"), "{text}");
        assert!(text.contains("behavior 3f9c2d7e1b4a5c6d"), "{text}");
        assert!(text.contains("if its section were removed now"), "{text}");
        assert!(text.contains(&"a".repeat(64)), "the plan digest is shown");
        assert!(
            text.contains("Approve? Type yes to confirm [y/N]: _"),
            "{text}"
        );
        // Narrow: the columns stack, each still present.
        let (rows, _) = draw(&app, 40, 12);
        let narrow = app.clone();
        let all: Vec<String> = (0..40usize)
            .flat_map(|s| {
                let mut a = narrow.clone();
                if let Some(Modal::Decision(p)) = &mut a.modal {
                    p.reading.scroll = s;
                }
                draw(&a, 40, 12).0
            })
            .collect();
        let joined = all.join("\n");
        for heading in ["Before:", "After:", "Restore:", "alias:alpha"] {
            assert!(joined.contains(heading), "{heading}: {rows:#?}");
        }
        // The DeclareInteraction modal shows the decision text instead.
        let mut app = populated();
        press(&mut app, &[Key::Char('4'), Key::Down, Key::Enter]);
        let (rows, _) = draw(&app, 120, 40);
        let text = rows.join(" ");
        assert!(
            text.contains("Heimdall will treat this key as needing no confirmation"),
            "{text}"
        );
        assert!(text.contains("SHA256:fixtureAlphaKey"));
        assert!(!text.contains("Restore"));
    }

    /// The rendered decision modal keeps the typed-yes prompt with default No, and its
    /// text says so (the key handling is `model::decision_modal_requires_typed_yes_default_no`).
    #[test]
    fn decision_modal_renders_the_prompt_default_no() {
        let mut app = populated();
        press(&mut app, &[Key::Char('4'), Key::Enter]);
        type_text(&mut app, "ye");
        for (w, h) in [(40, 12), (120, 40)] {
            let (rows, _) = draw(&app, w, h);
            let text = rows.join("");
            assert!(text.contains("[y/N]"), "{w}x{h}: {rows:#?}");
            assert!(text.contains("ye_"), "{w}x{h}: what was typed is shown");
        }
    }

    /// m02-plan U10 ⟨r2⟩/⟨r3⟩: the authorization shows the exact sentence and the
    /// static pass's list, or the none-found text.
    #[test]
    fn authorization_shows_the_sentence_and_the_list() {
        let mut app = populated();
        press(
            &mut app,
            &[Key::Char('2'), Key::Char('p'), Key::Down, Key::Enter],
        );
        let (rows, _) = draw(&app, 120, 40);
        assert!(rows.join(" ").contains("static pass; nothing executes"));
        assert!(
            !rows.join(" ").contains("[y/N]"),
            "no prompt before the list"
        );
        for (found, expect) in [
            (vec!["~/.ssh/config:12".to_owned()], "~/.ssh/config:12"),
            (Vec::new(), NONE_FOUND_TEXT),
        ] {
            let mut a = app.clone();
            a.apply(crate::tui::model::Update::ProbePrepared {
                alias: "alpha".to_owned(),
                level: ProbeLevel::Evaluate,
                executed: found,
                not_fully_readable: false,
            });
            let (rows, _) = draw(&a, 120, 40);
            let text = rows.join(" ");
            assert!(text.contains(AUTHORIZATION_TEXT), "{text}");
            assert!(text.contains(expect), "{text}");
            assert!(text.contains("[y/N]"), "{text}");
        }
    }

    /// ADR-0007 §6 (M2-S04): a probe result labels the command list as found before the
    /// run and never complete.
    #[test]
    fn probe_results_label_the_inventory_as_found_before_the_run() {
        let mut app = populated();
        let mut report = crate::tui::model::tests::report();
        let mut record = heimdall_localenv::probe::declined(
            ProbeLevel::Evaluate,
            "alpha",
            "config_commands_not_authorized",
        );
        record.outcome = ProbeOutcome::Ok;
        record.decline_reason = None;
        record.authorization = vec!["allow_config_commands".to_owned()];
        record.executed_config_commands = vec![heimdall_contract::doctor::ConfigProvenance {
            path_display: "~/.ssh/config".to_owned(),
            line: 12,
        }];
        record.config_tree_changed = Some(false);
        report.probes.push(record);
        app.modal = Some(Modal::Probe(ProbeView {
            alias: "alpha".to_owned(),
            level: ProbeLevel::Evaluate,
            report: Some(Ok(Box::new(report))),
            scroll: 0,
        }));
        let (rows, _) = draw(&app, 120, 40);
        let text = rows.join(" ");
        assert!(
            text.contains(
                "configuration commands found before the run; the run may have executed others"
            ),
            "{text}"
        );
        assert!(text.contains("~/.ssh/config:12"));
        assert!(text.contains("a change reverted before the second is not seen"));
        assert!(!text.to_lowercase().contains("complete list"));
    }

    /// Strings from the runtime are cleaned at the parse boundary, and the status line
    /// again at drawing: no cell ever holds a control character.
    #[test]
    fn hostile_strings_never_reach_a_cell_as_controls() {
        let mut app = populated();
        *app.catalog_mut() = crate::tui::data::Catalog::from_answers(
            &serde_json::json!({"items": [
                {"destination_id": "dst-e", "alias": "evil\u{1b}[2J\u{7}x", "definition": "observed",
                 "label": "l\u{1b}]0;t\u{7}"}
            ]}),
            &serde_json::Value::Null,
            &serde_json::Value::Null,
            &serde_json::Value::Null,
            &serde_json::Value::Null,
            &serde_json::Value::Null,
            now(),
        );
        app.status = Some("bad\u{1b}]0;title\u{7}status".to_owned());
        press(&mut app, &[Key::Char('2')]);
        let (_, buffer) = draw(&app, 120, 40);
        for c in buffer.content() {
            assert!(
                !c.symbol().chars().any(char::is_control),
                "{:?}",
                c.symbol()
            );
        }
    }

    // ---- confirmations are never truncated, scroll, and gate the yes (ADR-0007 §12.31 item 3)

    /// The sizes of the regressions (columns × rows): the roomy screen, and the smallest
    /// the snapshots cover.
    const SIZES: [(u16, u16); 2] = [(120, 40), (40, 12)];

    fn reading(app: &App) -> &Reading {
        match app.modal.as_ref().unwrap() {
            Modal::Decision(p) => &p.reading,
            Modal::Authorization(p) => &p.reading,
            Modal::Repair(p) => &p.reading,
            other => panic!("not a confirmation: {other:?}"),
        }
    }

    fn reading_mut(app: &mut App) -> &mut Reading {
        match app.modal.as_mut().unwrap() {
            Modal::Decision(p) => &mut p.reading,
            Modal::Authorization(p) => &mut p.reading,
            Modal::Repair(p) => &mut p.reading,
            other => panic!("not a confirmation: {other:?}"),
        }
    }

    /// Whitespace removed: wrapping may break a line at a space or inside a word, never
    /// drop a character, so what the owner reads, squashed, is what was recorded.
    fn squash(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// The content rows the open confirmation shows in one frame at `w`×`h`, read off the
    /// screen between the modal's borders.
    fn content_rows(app: &App, w: u16, h: u16) -> Vec<String> {
        let (rows, buffer) = draw(app, w, h);
        let top = u16::try_from(rows.iter().position(|r| r.contains('┌')).unwrap()).unwrap();
        let symbol = |x: u16, y: u16| buffer.cell((x, y)).map_or(" ", |c| c.symbol());
        let left = (0..w).find(|x| symbol(*x, top) == "┌").unwrap();
        let right = (left..w).find(|x| symbol(*x, top) == "┐").unwrap();
        let viewport = u16::try_from(reading(app).drawn().unwrap().viewport).unwrap();
        (top + 1..top + 1 + viewport)
            .map(|y| {
                (left + 1..right)
                    .map(|x| symbol(x, y))
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect()
    }

    /// Every content row of the open confirmation, collected the way the owner reads it:
    /// frame after frame, one row further down each time.
    fn read_everything(app: &App, w: u16, h: u16) -> Vec<String> {
        let mut app = app.clone();
        draw(&app, w, h);
        let d = reading(&app).drawn().unwrap();
        let mut all = vec![String::new(); d.total];
        for scroll in 0..=d.total.saturating_sub(d.viewport) {
            reading_mut(&mut app).scroll = scroll;
            // A frame taller than the content has blank rows below it: not content.
            for (i, row) in content_rows(&app, w, h).into_iter().enumerate() {
                if let Some(slot) = all.get_mut(scroll + i) {
                    *slot = row;
                }
            }
        }
        all
    }

    /// 600 cases, fixed seed unless `PROPTEST_RNG_SEED` is set (reproduces).
    fn wrapping_config() -> proptest::test_runner::Config {
        use proptest::test_runner::{Config, FileFailurePersistence, RngSeed};
        let mut c = Config {
            cases: 600,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..Config::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x5eed_1234_abcd_ef01);
        }
        c
    }

    proptest::proptest! {
        #![proptest_config(wrapping_config())]

        /// The wrapping drops no character and no row is wider than the width, whatever
        /// the text: generated over a small alphabet of the troublesome characters
        /// (spaces, separators, wide and combining characters), with an optional indent.
        #[test]
        fn wrapping_keeps_every_character_within_the_width(
            indent in 0usize..6,
            body in proptest::collection::vec(
                proptest::sample::select("ab c/\\ .-_:日本é\u{301} ~".chars().collect::<Vec<char>>()),
                0..120,
            ),
            width in 3usize..63,
        ) {
            let text: String = " ".repeat(indent) + &body.into_iter().collect::<String>();
            let rows = wrap_text(&text, width);
            proptest::prop_assert!(!rows.is_empty(), "{text:?}");
            proptest::prop_assert_eq!(
                squash(&rows.concat()),
                squash(&text),
                "no character is dropped or added: {:?} at {}", text, width
            );
            for row in &rows {
                proptest::prop_assert!(cells(row) <= width, "{row:?} wider than {width}: {text:?}");
            }
        }
    }

    #[test]
    fn wrapping_breaks_at_spaces_and_paths_and_marks_continuations() {
        assert_eq!(wrap_text("short", 10), ["short"]);
        assert_eq!(
            wrap_text("alpha beta gamma delta", 12),
            ["alpha beta ", "gamma delta"]
        );
        // A path breaks after a separator; an indented line's continuation is indented.
        assert_eq!(
            wrap_text("  Include /srv/heimdall/ssh_config.d/alpha.conf", 28),
            ["  Include /srv/heimdall/", "    ssh_config.d/alpha.conf"]
        );
        // `[y/N]` is not a path: it stays whole.
        assert_eq!(
            wrap_text("Authorize? Type yes to confirm [y/N]: _", 36),
            ["Authorize? Type yes to confirm ", "[y/N]: _"]
        );
        // A word longer than the row is broken inside.
        assert_eq!(wrap_text("abcdefghij", 4), ["abcd", "efgh", "ij"]);
    }

    /// The long-diff fixture: the line a decision applies has its meaningful suffix, and
    /// a second long cell, far beyond any column.
    const LONG_INCLUDE: &str = "Include ~/.config/heimdall/ssh_config.d/generated/production-fleet/final-segment-READABLE-TAIL.conf";
    const LONG_JUMP: &str = "ProxyJump bastion-one.example.invalid,bastion-two.example.invalid,last-hop.example.invalid:2222";

    fn long_diff_app() -> App {
        let mut app = populated();
        let d = app
            .catalog_mut()
            .decisions
            .iter_mut()
            .find(|d| d.id == "dec_apply1")
            .unwrap();
        d.request["diff_text"] = serde_json::json!(format!(
            "--- ~/.ssh/config\n+# >>> heimdall managed include\n+{LONG_INCLUDE}\n--- ~/.config/heimdall/ssh_config\n-Host alpha\n-  HostName old.example.invalid\n+Host alpha\n+  HostName alpha.example.invalid\n+  {LONG_JUMP}\n"
        ));
        press(&mut app, &[Key::Char('4'), Key::Enter]);
        app
    }

    /// ADR-0007 §12.31 item 3 (Q03), at 120×40 and 40×12: a diff whose meaningful suffix
    /// lies beyond the cell width is readable in full. The cells that do not fit side by
    /// side stack, and what is longer than the modal wraps; scrolling reaches every row.
    #[test]
    fn a_decision_diff_with_a_suffix_beyond_the_cell_width_is_readable_in_full() {
        for (w, h) in SIZES {
            let app = long_diff_app();
            let everything = read_everything(&app, w, h);
            let text = squash(&everything.concat());
            for must in [LONG_INCLUDE, LONG_JUMP, "READABLE-TAIL.conf", "2222"] {
                assert!(
                    text.contains(&squash(must)),
                    "{w}x{h}: {must:?} is not readable in full: {everything:#?}"
                );
            }
            // The cells do not fit three across: the columns stack.
            let joined = everything.join("\n");
            for heading in ["Before:", "After:", "Restore:"] {
                assert!(joined.contains(heading), "{w}x{h}: {heading}");
            }
            // The last row is the disclosure that closes every confirmation.
            assert!(
                squash(everything.last().unwrap()).ends_with(&squash("could imitate it.")),
                "{w}x{h}: {everything:#?}"
            );
        }
        // Control: short cells stay side by side at 120 columns (restore column test),
        // and the stacked form needs no scrolling there for the original fixture.
        let mut app = populated();
        press(&mut app, &[Key::Char('4'), Key::Enter]);
        let rows = content_rows(&app, 120, 40);
        assert!(
            rows.iter()
                .any(|r| r.contains("Before") && r.contains("After")),
            "{rows:#?}"
        );
    }

    /// The SHA-256 of a removed file in the fixtures below.
    const OWN_SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A rollback's diff text as the writer builds it (ADR-0007 §12.34 item 7): the
    /// owner's file whole, P and a key file as one summary line each.
    fn rollback_diff() -> String {
        format!(
            "--- ~/.ssh/config\n-# >>> heimdall managed include\n-Include ~/.config/heimdall/ssh_config\n-# <<< heimdall managed include\n--- ~/.config/heimdall/ssh_config\n~ removed ssh_config: 1234 lines, sha256 {OWN_SHA}\n--- ~/.config/heimdall/keys/abc.pub\n~ removed abc.pub: 1 line, sha256 {OWN_SHA}\n"
        )
    }

    /// ADR-0007 §12.34 item 7: the before and after columns of a rollback's diff. The
    /// removal of a file of Heimdall's own is one line under Before, said as a removal
    /// (name, line count, SHA-256); the After column has nothing under it; the owner's file
    /// is whole.
    #[test]
    fn a_removed_file_of_heimdalls_own_is_a_summary_line_under_before() {
        let (before, after) = diff_columns(&rollback_diff());
        assert_eq!(
            before,
            [
                "~/.ssh/config:".to_owned(),
                "  # >>> heimdall managed include".to_owned(),
                "  Include ~/.config/heimdall/ssh_config".to_owned(),
                "  # <<< heimdall managed include".to_owned(),
                "~/.config/heimdall/ssh_config:".to_owned(),
                format!("  removes Heimdall's own file ssh_config: 1234 lines, sha256 {OWN_SHA}"),
                "~/.config/heimdall/keys/abc.pub:".to_owned(),
                format!("  removes Heimdall's own file abc.pub: 1 line, sha256 {OWN_SHA}"),
            ]
        );
        assert!(
            after.iter().all(|l| l.is_empty() || l.ends_with(':')),
            "nothing is added: {after:?}"
        );
    }

    /// The same diff in the decision modal, at 120×40 and 40×12: every summary line is
    /// readable in full (never cut) and is not the writer's raw mark.
    #[test]
    fn a_rollback_decision_shows_the_summary_lines_in_full() {
        for (w, h) in SIZES {
            let mut app = populated();
            let d = app
                .catalog_mut()
                .decisions
                .iter_mut()
                .find(|d| d.id == "dec_apply1")
                .unwrap();
            d.request["diff_text"] = serde_json::json!(rollback_diff());
            press(&mut app, &[Key::Char('4'), Key::Enter]);
            let everything = read_everything(&app, w, h);
            let text = squash(&everything.concat());
            for must in [
                format!("removes Heimdall's own file ssh_config: 1234 lines, sha256 {OWN_SHA}"),
                format!("removes Heimdall's own file abc.pub: 1 line, sha256 {OWN_SHA}"),
                "Include ~/.config/heimdall/ssh_config".to_owned(),
            ] {
                assert!(
                    text.contains(&squash(&must)),
                    "{w}x{h}: {must:?} is not readable in full: {everything:#?}"
                );
            }
            assert!(
                !text.contains(&squash("~ removed")),
                "{w}x{h}: the raw mark is not shown"
            );
        }
    }

    fn inventory(n: usize) -> Vec<String> {
        (1..=n)
            .map(|i| format!("~/.ssh/config:{}", i * 2))
            .collect()
    }

    fn authorization_with(entries: &[String]) -> App {
        let mut app = populated();
        press(
            &mut app,
            &[Key::Char('2'), Key::Char('p'), Key::Down, Key::Enter],
        );
        app.apply(crate::tui::model::Update::ProbePrepared {
            alias: "alpha".to_owned(),
            level: ProbeLevel::Evaluate,
            executed: entries.to_vec(),
            not_fully_readable: false,
        });
        app
    }

    /// ADR-0007 §12.31 item 3 (Q04), at 120×40 and 40×12: the last entry of a
    /// 15-construct inventory is reached by keyboard alone, no row is skipped on the way,
    /// and the modal says how much is left below.
    #[test]
    fn the_last_entry_of_a_15_construct_inventory_is_reachable_by_keyboard() {
        let entries = inventory(15);
        let last = "~/.ssh/config:30";
        for (w, h) in SIZES {
            let mut app = authorization_with(&entries);
            let first = draw(&app, w, h).0.join("\n");
            let tall = h >= 40;
            assert_eq!(
                first.contains(last),
                tall,
                "{w}x{h}: only the tall screen shows the whole inventory at once\n{first}"
            );
            if !tall {
                assert!(
                    first.contains("more rows below (PgDn, End)"),
                    "the modal says what remains\n{first}"
                );
            }
            // PgDn only: every entry crosses the screen on the way down.
            let mut seen = std::collections::BTreeSet::new();
            let mut presses = 0;
            loop {
                let screen = draw(&app, w, h).0.join("\n");
                for e in &entries {
                    if screen.contains(e.as_str()) {
                        seen.insert(e.clone());
                    }
                }
                if screen.contains(last) {
                    break;
                }
                presses += 1;
                assert!(
                    presses < 30,
                    "{w}x{h}: never reached the last entry\n{screen}"
                );
                press(&mut app, &[Key::PageDown]);
            }
            assert_eq!(
                seen.len(),
                entries.len(),
                "{w}x{h}: no entry skipped: {seen:?}"
            );
            // At the end the modal says so, and the keys go back up (Home, Up, PgUp).
            if !tall {
                press(&mut app, &[Key::End]);
                let end = draw(&app, w, h).0.join("\n");
                assert!(end.contains("end of the content"), "{end}");
                assert!(end.contains("Without a typed yes"), "{end}");
                press(&mut app, &[Key::Home]);
                assert!(!draw(&app, w, h).0.join("\n").contains(last));
                press(&mut app, &[Key::End, Key::Up, Key::PageUp]);
                assert!(reading(&app).scroll < reading(&app).drawn().unwrap().total);
            }
            // Down alone gets there too.
            let mut app = authorization_with(&entries);
            for _ in 0..40 {
                press(&mut app, &[Key::Down]);
                draw(&app, w, h);
            }
            assert!(draw(&app, w, h).0.join("\n").contains(last), "{w}x{h}");
        }
    }

    /// The three confirmations at 40×12, each with content taller than the screen.
    fn tall_confirmations() -> Vec<(&'static str, App)> {
        let mut decision = populated();
        press(&mut decision, &[Key::Char('4'), Key::Down, Key::Enter]);
        let auth = authorization_with(&inventory(15));
        let mut repair = populated();
        press(
            &mut repair,
            &[
                Key::Char('4'),
                Key::Down,
                Key::Down,
                Key::Enter,
                Key::Char('k'),
            ],
        );
        repair.apply(crate::tui::model::Update::RepairPlan {
            operation: "op_held1".to_owned(),
            repair: crate::tui::model::HeldRepair::Keep,
            plan: Ok(crate::tui::model::RepairPlan {
                digest: "d".repeat(64),
                lines: (1..=15)
                    .map(|i| format!("stays in place: ~/.ssh/file{i}"))
                    .collect(),
            }),
        });
        vec![
            ("decision", decision),
            ("authorization", auth),
            ("repair", repair),
        ]
    }

    /// ADR-0007 §12.31 item 3: a typed yes is accepted only once a frame has drawn the
    /// last row of the content; before that the answer is refused, discarded, and the
    /// modal says so.
    #[test]
    fn yes_is_refused_until_the_end_has_been_shown() {
        let sent = |effects: &[crate::tui::model::Effect]| !effects.is_empty();
        for (kind, app) in tall_confirmations() {
            let (w, h) = (40, 12);
            let mut app = app;
            // Nothing drawn yet: nothing was shown, so nothing is accepted.
            type_text(&mut app, "yes");
            assert!(
                !sent(&press(&mut app, &[Key::Enter])),
                "{kind}: before any frame"
            );
            // A frame that shows the start only.
            draw(&app, w, h);
            assert!(
                reading(&app).scrollable() && !reading(&app).end_shown(),
                "{kind}"
            );
            type_text(&mut app, "yes");
            assert!(
                !sent(&press(&mut app, &[Key::Enter])),
                "{kind}: end not shown"
            );
            assert!(reading(&app).refused, "{kind}");
            let rows = draw(&app, w, h).0;
            let screen = rows.join("\n");
            assert!(
                screen.contains("yes refused"),
                "{kind}: the modal says so\n{screen}"
            );
            assert!(
                screen.contains("Read to the end first"),
                "{kind}: the footer too\n{screen}"
            );
            assert!(
                screen.contains("[y/N]"),
                "{kind}: the prompt stays\n{screen}"
            );
            // The refused answer was discarded: Enter alone is the default No.
            let Some(input) = (match app.modal.as_ref() {
                Some(Modal::Decision(p)) => Some(&p.input),
                Some(Modal::Authorization(p)) => Some(&p.input),
                Some(Modal::Repair(p)) => Some(&p.input),
                _ => None,
            }) else {
                panic!("{kind}: the modal stays open");
            };
            assert!(input.is_empty(), "{kind}: {input:?}");
            // Scrolling to the end without a frame in between shows nothing: the keys
            // that follow (queued behind it) are still refused.
            press(&mut app, &[Key::End, Key::Home]);
            type_text(&mut app, "yes");
            assert!(
                !sent(&press(&mut app, &[Key::Enter])),
                "{kind}: End then Home, no frame"
            );
            press(&mut app, &[Key::End]);
            type_text(&mut app, "yes");
            assert!(
                !sent(&press(&mut app, &[Key::Enter])),
                "{kind}: End, no frame"
            );
            // PgDn frame by frame reaches the end, and then the yes is accepted.
            let mut guard = 0;
            while !reading(&app).end_shown() {
                press(&mut app, &[Key::PageDown]);
                draw(&app, w, h);
                guard += 1;
                assert!(guard < 30, "{kind}");
            }
            let screen = draw(&app, w, h).0.join("\n");
            assert!(screen.contains("end of the content"), "{kind}\n{screen}");
            type_text(&mut app, "yes");
            assert!(
                sent(&press(&mut app, &[Key::Enter])),
                "{kind}: the end was shown"
            );
        }
    }

    /// Once the end has been on screen it stays shown for the same content, wherever the
    /// owner scrolls back to; a content that changes must be read to its end again; and a
    /// screen tall enough for everything needs no scrolling at all.
    #[test]
    fn the_end_stays_shown_for_the_same_content_and_not_for_changed_content() {
        let sent = |effects: &[crate::tui::model::Effect]| !effects.is_empty();
        // Same content: End (framed), Home (framed), then yes.
        let mut app = authorization_with(&inventory(15));
        draw(&app, 40, 12);
        press(&mut app, &[Key::End]);
        draw(&app, 40, 12);
        press(&mut app, &[Key::Home]);
        draw(&app, 40, 12);
        assert!(reading(&app).end_shown());
        type_text(&mut app, "yes");
        assert!(sent(&press(&mut app, &[Key::Enter])));
        // Changed content: a decision of another kind grows below the row being shown.
        let mut app = populated();
        let other = |extra: usize| crate::tui::data::Decision {
            id: "dec_other".to_owned(),
            kind: "other_kind".to_owned(),
            created_at: Some(crate::tui::model::tests::t("2026-11-03T09:00:00Z")),
            expires_at: Some(crate::tui::model::tests::t("2026-11-03T09:15:00Z")),
            expired: false,
            policies: Vec::new(),
            scope: None,
            request: serde_json::Value::Object(
                (0..4 + extra)
                    .map(|i| (format!("field{i:02}"), serde_json::json!(i)))
                    .collect(),
            ),
        };
        app.catalog_mut().decisions.push(other(0));
        app.modal = Some(Modal::Decision(crate::tui::model::DecisionPrompt {
            id: "dec_other".to_owned(),
            verdict: heimdall_contract::request::Verdict::Approve,
            input: String::new(),
            reading: Reading::default(),
        }));
        press(&mut app, &[Key::End]);
        draw(&app, 40, 12);
        press(&mut app, &[Key::End]);
        draw(&app, 40, 12);
        assert!(reading(&app).end_shown());
        app.catalog_mut().decisions.retain(|d| d.id != "dec_other");
        app.catalog_mut().decisions.push(other(12));
        draw(&app, 40, 12);
        assert!(
            !reading(&app).end_shown(),
            "the replaced record's end was not shown"
        );
        type_text(&mut app, "yes");
        assert!(!sent(&press(&mut app, &[Key::Enter])));
        press(&mut app, &[Key::End]);
        draw(&app, 40, 12);
        type_text(&mut app, "yes");
        assert!(sent(&press(&mut app, &[Key::Enter])));
        // A tall screen shows everything at once: the first frame is enough.
        let mut app = authorization_with(&inventory(15));
        draw(&app, 120, 40);
        assert!(!reading(&app).scrollable() && reading(&app).end_shown());
        type_text(&mut app, "yes");
        assert!(sent(&press(&mut app, &[Key::Enter])));
    }

    /// A terminal too small to show any content cannot confirm: nothing is accepted, and
    /// nothing panics at any size.
    #[test]
    fn a_terminal_too_small_to_show_the_content_confirms_nothing() {
        for (kind, app) in tall_confirmations() {
            for (w, h) in [(9, 3), (10, 3), (10, 4), (12, 5), (20, 6), (40, 8)] {
                let mut app = app.clone();
                draw(&app, w, h);
                type_text(&mut app, "yes");
                let effects = press(&mut app, &[Key::Enter]);
                assert!(
                    effects.is_empty(),
                    "{kind} {w}x{h}: the end of a tall content is not on a tiny screen"
                );
            }
        }
    }

    /// The refused state, deliberately recorded (40×12): the answer is gone, the prompt
    /// stays fixed under the content, and the border says what remains.
    #[test]
    fn the_refusal_is_visible_in_the_modal() {
        let mut app = populated();
        press(&mut app, &[Key::Char('4'), Key::Enter]);
        draw(&app, 40, 12);
        type_text(&mut app, "yes");
        press(&mut app, &[Key::Enter]);
        let (rows, _) = draw(&app, 40, 12);
        snapshot("decision_apply_refused_40x12", &rows);
        let (plain_rows, _) = draw(&no_color(&app), 40, 12);
        assert_eq!(rows, plain_rows, "the refusal is told in text");
    }

    #[test]
    fn ages_read_naturally() {
        let n = now();
        let t = crate::tui::model::tests::t;
        // ⟨M07⟩ Minute granularity: nothing under a minute moves (probe P1).
        assert_eq!(age(n, t("2026-11-03T09:00:25Z")), "just now");
        assert_eq!(age(n, t("2026-11-03T08:59:31Z")), "just now");
        assert_eq!(age(n, t("2026-11-03T08:59:30Z")), "1 min ago");
        assert_eq!(age(n, t("2026-11-03T09:00:50Z")), "in under a minute");
        assert_eq!(age(n, t("2026-11-03T08:58:30Z")), "2 min ago");
        assert_eq!(age(n, t("2026-11-03T09:15:00Z")), "in 14 min");
        assert_eq!(age(n, t("2026-11-03T06:00:00Z")), "3 h ago");
        assert_eq!(age(n, t("2026-11-03T12:00:30Z")), "in 3 h");
        assert_eq!(age(n, t("2026-11-01T09:00:30Z")), "2 d ago");
        assert_eq!(age(n, t("2026-11-05T09:00:30Z")), "in 2 d");
        assert_eq!(hms(t("2026-11-03T09:00:25.123Z")), "09:00:25Z");
    }

    // ---- ⟨M07⟩ U1: the error state and the grouped overview ---------------------------

    /// Ruling Q4 for the TUI: a failed listing is never shown as empty. A destinations
    /// read that fails after a good one shows the error and the stale rows; one that
    /// fails with no earlier data shows the error, never "No catalog destinations.". The
    /// same for the profiles and the pending decisions; only a successful empty read
    /// shows the empty-state text.
    #[test]
    fn listing_failure_is_shown_not_empty() {
        use crate::tui::model::Update;
        let flat = |rows: &[String]| rows.join("\n");
        // A good read, then a failed one: the worker keeps the last good rows.
        let mut app = populated();
        let good = app.catalog().clone();
        let mut failed = good.clone();
        failed
            .failures
            .insert("destinations".to_owned(), frame_limit_failure(true));
        app.apply(Update::Catalog(Box::new(failed)));
        assert!(app.take_changed(), "a new failure is a change");
        press(&mut app, &[Key::Char('2')]);
        for (w, h) in [(120, 40), (40, 12)] {
            let text = flat(&draw(&app, w, h).0);
            assert!(
                text.contains("[!!] destination listing failed: INTERNAL_ERROR")
                    || text.contains("[!!] destination listing failed\n  INTERNAL_ERROR"),
                "{w}x{h}: {text}"
            );
            assert!(text.contains("response exceeds the frame limit"), "{text}");
            assert!(text.contains("stale"), "{w}x{h}: {text}");
            assert!(text.contains("2 (stale) total"), "{w}x{h}: {text}");
            assert!(text.contains("alpha"), "the stale rows stay: {text}");
            assert!(!text.contains("No catalog destinations."), "{text}");
        }
        // The overview names it; the health rules are unchanged (not a problem).
        let mut overview = app.clone();
        press(&mut overview, &[Key::Char('1')]);
        let text = flat(&draw(&overview, 120, 40).0);
        // ⟨M07⟩ U2: in words on the overview; the code is in the tab's error state.
        assert!(
            text.contains("[ !] the destination list could not be read (Enter for why"),
            "{text}"
        );
        assert!(!text.contains("INTERNAL_ERROR"), "{text}");
        // ⟨M07⟩ M07-W0-R03: with nothing else waiting it is not Ready either: what the
        // failed list would say is not known.
        let mut quiet = overview.clone();
        quiet.catalog_mut().operations.clear();
        quiet.catalog_mut().decisions.clear();
        assert_eq!(quiet.health(), crate::tui::model::Health::Unknown);
        let text = flat(&draw(&quiet, 120, 40).0);
        assert!(text.contains("[??] Not known"), "{text}");
        assert!(!text.contains("[OK] Ready"), "{text}");
        // A failure with no earlier data: the error, never the empty-state text.
        let mut fresh = App::new(now(), false);
        fresh.apply(Update::Runtime(Runtime::Connected));
        let mut never = crate::tui::data::Catalog::default();
        never
            .failures
            .insert("destinations".to_owned(), frame_limit_failure(false));
        never
            .failures
            .insert("profiles".to_owned(), frame_limit_failure(false));
        never
            .failures
            .insert("decisions".to_owned(), frame_limit_failure(false));
        fresh.apply(Update::Catalog(Box::new(never)));
        for (tab, empty, what) in [
            ('2', "No catalog destinations.", "destination"),
            ('3', "No profiles.", "profile"),
        ] {
            let mut a = fresh.clone();
            press(&mut a, &[Key::Char(tab)]);
            for (w, h) in [(120, 40), (40, 12)] {
                let text = flat(&draw(&a, w, h).0);
                assert!(
                    text.contains(&format!("[!!] {what} listing failed: INTERNAL_ERROR"))
                        || text.contains(&format!("[!!] {what} listing failed\n  INTERNAL_ERROR")),
                    "{w}x{h}: {text}"
                );
                assert!(text.contains("nothing listed yet"), "{w}x{h}: {text}");
                assert!(!text.contains(empty), "{w}x{h}: {text}");
            }
        }
        let mut a = fresh.clone();
        press(&mut a, &[Key::Char('4')]);
        let text = flat(&draw(&a, 120, 40).0);
        assert!(
            text.contains("Pending decisions\n[!!] decision listing failed: INTERNAL_ERROR"),
            "{text}"
        );
        assert!(!text.contains("Pending decisions\n  none"), "{text}");
        // A successful read that returned nothing: the empty-state text.
        let mut empty = fresh.clone();
        empty.apply(Update::Catalog(Box::default()));
        press(&mut empty, &[Key::Char('2')]);
        let text = flat(&draw(&empty, 120, 40).0);
        assert!(text.contains("No catalog destinations."), "{text}");
        assert!(!text.contains("listing failed"), "{text}");
    }

    /// M07-W0-R03: a failed or stale read never looks current or healthy.
    ///
    /// * **A transport failure** that drops the session after good reads: the overview is
    ///   not Ready, a row under the header says the runtime is not connected and when what
    ///   is shown was read, on every screen, and no line claims that nothing runs.
    /// * **A first-read failure** (nothing was ever read): not Ready; the lines that would
    ///   state a value say it is not known.
    /// * **A list scrolled after a failure** (40×12): the listing's own error has scrolled
    ///   away, the indicator has not.
    /// * **A failed default-profile read** never shows "none set".
    #[test]
    fn a_failed_or_stale_read_never_looks_current_or_healthy() {
        use crate::tui::data::{Catalog, ListingFailure};
        use crate::tui::m07::fixtures;
        use crate::tui::model::{Health, Update};
        let t = crate::tui::model::tests::t;
        let flat = |rows: &[String]| rows.join("\n");
        let reassuring = [
            "[OK] Ready",
            "no work running",
            "Nothing needs you",
            "none set",
        ];
        // ---- a transport failure --------------------------------------------------------
        let mut quiet = fixtures::app();
        quiet.catalog_mut().operations.clear();
        quiet.catalog_mut().decisions.clear();
        assert_eq!(quiet.health(), Health::Ready, "before the failure");
        let lost = disconnected(&quiet);
        assert_eq!(lost.health(), Health::Unknown);
        for keys in [
            &[][..],
            &[Key::Char('2')],
            &[Key::Char('4')],
            &[Key::Char('8')],
            &[Key::Char('2'), Key::Enter],
        ] {
            let mut a = lost.clone();
            press(&mut a, keys);
            let wide = draw(&a, 120, 40).0;
            assert_eq!(
                wide[1],
                "[!!] Not connected: what is shown was read 09:00:25Z (just now) and may have changed · S reconnects",
                "{keys:?}"
            );
            assert!(wide[0].contains("[??]"), "{}", wide[0]);
            let narrow = draw(&a, 40, 12).0;
            assert_eq!(narrow[1], "[!!] not connected · read just now", "{keys:?}");
            assert!(narrow[0].ends_with("[??] Not known"), "{}", narrow[0]);
            for claim in reassuring {
                assert!(!flat(&wide).contains(claim), "{keys:?} {claim}: {wide:#?}");
                assert!(
                    !flat(&narrow).contains(claim),
                    "{keys:?} {claim}: {narrow:#?}"
                );
            }
        }
        let text = flat(&draw(&lost, 120, 40).0);
        assert!(text.contains("[??] Not known"), "{text}");
        assert!(
            text.contains("Runtime: unavailable: the runtime closed the connection"),
            "{text}"
        );
        // The runtime stopped (the next refresh finds none): the same, in its words.
        let mut stopped = lost.clone();
        stopped.apply(Update::Runtime(Runtime::NotRunning));
        assert_eq!(stopped.health(), Health::Unknown);
        let rows = draw(&stopped, 120, 40).0;
        assert!(
            rows[1].starts_with("[!!] The runtime stopped: what is shown was read 09:00:25Z"),
            "{}",
            rows[1]
        );
        // Reconnected and read again: current, and Ready again.
        let mut back = lost.clone();
        back.apply(Update::Runtime(Runtime::Connected));
        let mut fresh = back.catalog().clone();
        fresh.failures.clear();
        back.apply(Update::Catalog(Box::new(fresh)));
        assert_eq!(back.health(), Health::Ready);
        assert!(!draw(&back, 120, 40).0[1].starts_with("[!!]"));

        // ---- a first-read failure -------------------------------------------------------
        let never = |code: &str| ListingFailure {
            code: code.to_owned(),
            message: "the store could not be read".to_owned(),
            since: t("2026-11-03T09:00:20Z"),
            stale_from: None,
        };
        let mut first = App::new(now(), false);
        first.apply(Update::Runtime(Runtime::Connected));
        *first.doctor_mut() = Some(crate::tui::data::Doctor {
            report: heimdall_contract::doctor::DoctorReport {
                findings: Vec::new(),
                ..crate::tui::model::tests::report()
            },
            taken_at: now(),
        });
        let mut unread = Catalog {
            read_at: Some(t("2026-11-03T09:00:25Z")),
            ..Catalog::default()
        };
        for name in SUBJECTS {
            unread
                .failures
                .insert(name.to_owned(), never("INTERNAL_ERROR"));
        }
        first.apply(Update::Catalog(Box::new(unread)));
        assert_eq!(
            first.health(),
            Health::Unknown,
            "a never-read failure is not Ready"
        );
        for (w, h) in [(120, 40), (40, 12)] {
            let rows = draw(&first, w, h).0;
            let text = flat(&rows);
            assert!(text.contains("[??] Not known"), "{w}x{h}: {text}");
            assert!(rows[1].starts_with("[!!] 12 lists"), "{w}x{h}: {}", rows[1]);
            for claim in reassuring {
                assert!(!text.contains(claim), "{w}x{h} {claim}: {text}");
            }
        }
        let text = flat(&draw(&first, 120, 60).0);
        for expected in [
            "Environment: this environment · what is running is not known (the lists could not be read)",
            "Access: this environment's standing access is not known (it could not be read)",
            "Desktop lock: not known (the lock setting could not be read)",
            "[ !] the operation list could not be read (Enter for why; nothing was read from it yet)",
        ] {
            assert!(text.contains(expected), "{expected}:\n{text}");
        }
        // One list never read: the indicator names it.
        let mut one = fixtures::app();
        one.catalog_mut().operations.clear();
        one.catalog_mut().decisions.clear();
        one.catalog_mut()
            .failures
            .insert("operations".to_owned(), never("INTERNAL_ERROR"));
        assert_eq!(one.health(), Health::Unknown);
        let rows = draw(&one, 120, 40).0;
        assert_eq!(
            rows[1],
            "[!!] Not read: the operation list could not be read; nothing is known from it"
        );
        assert_eq!(draw(&one, 40, 12).0[1], "[!!] not read: operation list");
        // The connection never made: nothing was read at all.
        let mut refused = App::new(now(), false);
        refused.apply(Update::Runtime(Runtime::Failed(
            "permission denied".to_owned(),
        )));
        *refused.doctor_mut() = first.doctor().cloned();
        assert_eq!(refused.health(), Health::Unknown);
        let rows = draw(&refused, 120, 40).0;
        assert_eq!(
            rows[1],
            "[!!] Not connected: nothing has been read from the runtime · S reconnects"
        );
        assert!(
            flat(&rows)
                .contains("What needs you is not known: the runtime's lists could not be read."),
            "{rows:#?}"
        );
        // No runtime at all is the ordinary first frame: no alarm, and no claim either.
        let mut absent = App::new(now(), false);
        absent.apply(Update::Runtime(Runtime::NotRunning));
        *absent.doctor_mut() = first.doctor().cloned();
        let text = flat(&draw(&absent, 120, 40).0);
        assert!(!text.contains("[!!]"), "{text}");
        assert!(
            text.contains(
                "Nothing is read from the runtime yet: what needs you there is not known."
            ),
            "{text}"
        );

        // ---- a list scrolled after a failure, at 40×12 ----------------------------------
        let mut list = grouped_app(100);
        list.catalog_mut()
            .failures
            .insert("destinations".to_owned(), frame_limit_failure(true));
        press(&mut list, &[Key::Char('2')]);
        let top = draw(&list, 40, 12).0;
        assert_eq!(top[1], "[!!] stale: destination list");
        assert!(
            flat(&top).contains("destination listing failed"),
            "{top:#?}"
        );
        press(&mut list, &[Key::PageDown; 5]);
        let rows = draw(&list, 40, 12).0;
        let text = flat(&rows);
        assert!(text.contains("> [ !] host-000050"), "{text}");
        assert!(
            !text.contains("listing failed") && !text.contains("(stale) total"),
            "the list's own error has scrolled away: {text}"
        );
        assert_eq!(
            rows[1], "[!!] stale: destination list",
            "the indicator has not"
        );
        assert!(rows[0].ends_with("[??] Not known"), "{}", rows[0]);
        let wide = draw(&list, 120, 14).0;
        assert_eq!(
            wide[1],
            "[!!] Stale: the destination list could not be read; it is shown as read 08:57:00Z (3 min ago)"
        );

        // ---- a failed default-profile read ----------------------------------------------
        let mut settings = fixtures::app();
        let c = settings.catalog_mut();
        c.m05.policies = None;
        c.m05.default_profiles.clear();
        c.failures
            .insert("policies".to_owned(), never("INTERNAL_ERROR"));
        press(&mut settings, &[Key::Char('8')]);
        for (w, h) in [(120, 40), (40, 12)] {
            let text = flat(&draw(&settings, w, h).0);
            assert!(!text.contains("none set"), "{w}x{h}: {text}");
            assert!(
                text.contains("> [??] Default profile: not known"),
                "{w}x{h}: {text}"
            );
        }
        let text = flat(&draw(&settings, 120, 40).0);
        for expected in [
            "> [??] Default profile: not known (not read) · this computer",
            "  not known: the standing access list could not be read (INTERNAL_ERROR)",
            "[!!] The standing access list could not be read (INTERNAL_ERROR): nothing is known about it yet",
        ] {
            assert!(text.contains(expected), "{expected}:\n{text}");
        }
        // Read before, failing now: the last value, marked stale.
        let mut stale = fixtures::app();
        stale
            .catalog_mut()
            .failures
            .insert("policies".to_owned(), frame_limit_failure(true));
        press(&mut stale, &[Key::Char('8')]);
        let text = flat(&draw(&stale, 120, 40).0);
        assert!(
            text.contains("> [??] Default profile: dev (stale) · this computer"),
            "{text}"
        );
        assert!(
            text.contains("pol-ws1 · profile dev · project · automatic (stale)"),
            "{text}"
        );
        // A successful read with no default set is the only "none set".
        let mut unset = fixtures::app();
        unset.catalog_mut().m05.default_profiles.clear();
        press(&mut unset, &[Key::Char('8')]);
        let text = flat(&draw(&unset, 120, 40).0);
        assert!(
            text.contains("> [ i] Default profile: none set · this computer"),
            "{text}"
        );
    }

    /// M07-W0-R11: Enter on a grouped finding shows that group's destinations, whatever
    /// search the Destinations list had: the search is cleared and the list is scoped to
    /// exactly the destinations the finding concerns, named in its first row; Esc (or
    /// going to a view by its key) shows every destination again. A group whose findings
    /// do not all say the same thing is worded for the group, never with the first one's
    /// message.
    #[test]
    fn a_grouped_finding_shows_its_destinations_whatever_the_search() {
        use crate::tui::model::tests::destination;
        let mut app = grouped_app(100);
        app.catalog_mut()
            .destinations
            .insert(0, destination("other", false));
        // An unrelated search is active on Destinations: it matches one destination,
        // which the finding does not concern.
        press(&mut app, &[Key::Char('2'), Key::Char('/')]);
        type_text(&mut app, "other");
        press(&mut app, &[Key::Enter]);
        assert_eq!(app.shown(Tab::Destinations), 1);
        // The group, from the overview.
        press(&mut app, &[Key::Char('1')]);
        app.selected[0] = app
            .overview_items()
            .iter()
            .position(|i| matches!(i, Item::Findings { .. }))
            .unwrap();
        let text = draw(&app, 120, 40).0.join("\n");
        assert!(
            text.contains("> [ !] 100 destinations: ssh may offer other identities than the adopted key for this alias (Enter: which ones)"),
            "{text}"
        );
        press(&mut app, &[Key::Enter]);
        assert_eq!(app.screen, Screen::Tab(Tab::Destinations));
        assert_eq!(
            app.search(Tab::Destinations).unwrap().text,
            "",
            "the search is cleared"
        );
        let shown: Vec<String> = app
            .visible_destinations()
            .iter()
            .map(|d| d.alias.clone())
            .collect();
        let affected: Vec<String> = (0..100).map(|i| format!("host-{i:06}")).collect();
        assert_eq!(
            shown, affected,
            "exactly the group's destinations, none hidden"
        );
        let rows = draw(&app, 120, 40).0;
        assert_eq!(
            rows[1],
            "Finding: 100 of 101 · Esc all · ssh may offer other identities than the adopted key for this alias"
        );
        assert_eq!(
            rows[2],
            "> [ !] host-000000  observed (defined in your configuration)"
        );
        assert!(rows.last().unwrap().contains("Esc all"), "{rows:#?}");
        let narrow = draw(&app, 40, 12).0;
        assert!(
            narrow[1].starts_with("Finding: 100 of 101 · Esc all"),
            "{}",
            narrow[1]
        );
        assert!(!narrow.join("\n").contains("other"), "{narrow:#?}");
        // Esc: every destination again.
        press(&mut app, &[Key::Esc]);
        assert_eq!(app.screen, Screen::Tab(Tab::Destinations));
        assert_eq!(app.shown(Tab::Destinations), 101);
        assert!(app.scope().is_none());
        // Going to the view by its key does not keep an earlier scope.
        press(&mut app, &[Key::Char('1'), Key::Enter]);
        assert_eq!(app.shown(Tab::Destinations), 100);
        press(&mut app, &[Key::Char('2')]);
        assert_eq!(app.shown(Tab::Destinations), 101);
        // Findings of one code that say different things: group-level words.
        let mut mixed = grouped_app(3);
        let first = "ssh may offer other identities than the adopted key for this alias";
        for (i, f) in mixed
            .doctor_mut()
            .as_mut()
            .unwrap()
            .report
            .findings
            .iter_mut()
            .filter(|f| f.code == "identity_selection_not_exclusive")
            .enumerate()
        {
            if i == 2 {
                f.message = "IdentitiesOnly is not set for this alias".to_owned();
            }
        }
        let text = draw(&mixed, 120, 40).0.join("\n");
        assert!(
            text.contains("[ !] 3 destinations: identity selection not exclusive (the details differ for each) (Enter: which ones)"),
            "{text}"
        );
        assert!(!text.contains(first), "not the first one's message: {text}");
        mixed.selected[0] = mixed
            .overview_items()
            .iter()
            .position(|i| matches!(i, Item::Findings { .. }))
            .unwrap();
        press(&mut mixed, &[Key::Enter]);
        let rows = draw(&mixed, 120, 40).0;
        assert_eq!(
            rows[1],
            "Finding: 3 of 3 · Esc all · identity selection not exclusive (the details differ for each)"
        );
    }

    /// Probe P4: 100 destinations with the same warning are one overview row with the
    /// count, in the finding's own words and with its marker; Enter on it opens the
    /// Destinations tab (one destination: its detail); a problem group still means Needs
    /// attention. At 40×12 no two visible rows are the same text.
    #[test]
    fn overview_groups_findings_and_keeps_rows_distinct() {
        use crate::tui::model::{Health, Item};
        let app = grouped_app(100);
        let items = app.overview_items();
        let groups: Vec<_> = items
            .iter()
            .filter(|i| matches!(i, Item::Findings { .. }))
            .collect();
        assert_eq!(groups.len(), 1, "{items:?}");
        let Item::Findings {
            problem,
            code,
            aliases,
            ..
        } = groups[0]
        else {
            unreachable!()
        };
        assert!(!problem);
        assert_eq!(code, "identity_selection_not_exclusive");
        assert_eq!(aliases.len(), 100);
        assert_eq!(
            items.len(),
            2,
            "the grouped row and home_mismatch: {items:?}"
        );
        assert_eq!(app.health(), Health::Ready, "warnings are never alarms");
        let text = draw(&app, 120, 40).0.join("\n");
        assert!(
            text.contains(
                "[ !] 100 destinations: ssh may offer other identities than the adopted key for this alias"
            ),
            "{text}"
        );
        assert_eq!(
            text.matches("ssh may offer").count(),
            1,
            "one row, not one per destination: {text}"
        );
        // No two visible rows are the same text at 40×12 (nor at 120×40), also with two
        // pending decisions of one kind.
        let mut two = populated();
        let mut second = crate::tui::model::tests::apply_decision();
        second.id = "dec_apply2".to_owned();
        two.catalog_mut().decisions.push(second);
        for (w, h, app) in [
            (40, 12, &app),
            (120, 40, &app),
            (40, 12, &two),
            (40, 12, &m03::m03_app()),
        ] {
            let rows = draw(app, w, h).0;
            let mut seen = std::collections::HashSet::new();
            for r in rows.iter().filter(|r| !r.trim().is_empty()) {
                assert!(seen.insert(r.clone()), "{w}x{h}: {r:?} repeats: {rows:#?}");
            }
        }
        // The destination rows carry the marker; Enter on the group opens them.
        let mut a = app.clone();
        let at = a
            .overview_items()
            .iter()
            .position(|i| matches!(i, Item::Findings { .. }))
            .unwrap();
        a.selected[0] = at;
        press(&mut a, &[Key::Enter]);
        assert_eq!(a.screen, Screen::Tab(Tab::Destinations));
        let text = draw(&a, 120, 40).0.join("\n");
        assert!(text.contains("[ !] host-000000"), "{text}");
        // One destination: Enter opens its detail.
        let mut one = grouped_app(1);
        let at = one
            .overview_items()
            .iter()
            .position(|i| matches!(i, Item::Findings { .. }))
            .unwrap();
        one.selected[0] = at;
        press(&mut one, &[Key::Enter]);
        assert_eq!(one.screen, Screen::Destination("host-000000".to_owned()));
        // A problem group is Needs attention, still one row.
        let mut p = grouped_app(50);
        for f in &mut p.doctor_mut().as_mut().unwrap().report.findings {
            f.severity = heimdall_contract::doctor::FindingSeverity::Problem;
        }
        assert_eq!(p.health(), Health::Attention);
        assert_eq!(
            p.overview_items()
                .iter()
                .filter(|i| matches!(i, Item::Findings { problem: true, .. }))
                .count(),
            1
        );
        // A finding naming a destination by ID groups under its alias.
        let mut by_id = grouped_app(3);
        for f in &mut by_id.doctor_mut().as_mut().unwrap().report.findings {
            if let Some(id) = f.subject.id.as_mut() {
                *id = format!("dst-{id}");
            }
        }
        let Some(Item::Findings { aliases, .. }) = by_id
            .overview_items()
            .iter()
            .find(|i| matches!(i, Item::Findings { .. }))
        else {
            panic!("a grouped row")
        };
        assert_eq!(aliases[0], "host-000000");
        assert_eq!(by_id.alias_findings("host-000001"), (0, 1));
    }

    // ---- ⟨M03⟩ U12: the M03 views (m03-plan U12 "Tests", TUI) ------------------------

    mod m03 {
        use super::*;
        use crate::tui::m03::fixtures::{
            enroll_decision, enrollment, register_decision, remove_decision, retire_decision,
            system_form_decision, target_change_decision,
        };
        use crate::tui::m03::{Listings, LockReport, Preference, Projection};
        use crate::tui::model::{Command, DecisionPrompt, Effect};
        use heimdall_contract::enrollment::DisclosureKind;
        use heimdall_contract::managed::{
            ConnectionPolicy, ConnectionPolicyReport, ExistingConnectionsMode, MultiplexingMode,
        };
        use heimdall_localenv::projection::plan::{
            DEADLINE_GRACEFUL_EXCLUSIVE, DEADLINE_GRACEFUL_NOT_EXCLUSIVE,
            DEADLINE_STRICT_EXCLUSIVE, DEADLINE_STRICT_NOT_EXCLUSIVE, slot_free_command,
            slot_free_disclosure,
        };

        const TIME_MESSAGE: &str = "safe time cannot be established; activation is stopped";

        fn pending() -> Preference {
            Preference {
                mechanism: "managed_certificate".to_owned(),
                projection: Some(Projection::Pending),
                policy: None,
            }
        }

        /// The populated state with M03 records: `alpha` is a managed-certificate pair
        /// whose projection is pending and whose slot is free; three enrollments (held
        /// after a host-key change, withdrawn with the `late_write` residual, verified);
        /// the time chore; an enrollment and a target-change decision.
        pub(super) fn m03_app() -> App {
            let mut app = populated();
            app.catalog_mut().destinations[0].preference = Some(pending());
            app.catalog_mut().m03 = Listings::of(
                &serde_json::json!({"enrollments": [
                    enrollment(1, "held", false, Some("host_key_changed")),
                    enrollment(2, "withdrawn", true, None),
                    enrollment(3, "verified", false, None),
                ]}),
                &serde_json::Value::Null,
                &serde_json::Value::Null,
                &[heimdall_contract::envelope::Warning {
                    code: crate::tui::m03::TIME_UNCERTAIN.to_owned(),
                    message: TIME_MESSAGE.to_owned(),
                    reason: Some(crate::tui::m03::TIME_CHORE.to_owned()),
                }],
            );
            app.catalog_mut().decisions = vec![
                enroll_decision(
                    "dec_enroll1",
                    vec![
                        DisclosureKind::CaTrustBlastRadius,
                        DisclosureKind::LockContinuityOnce,
                    ],
                ),
                target_change_decision(),
            ];
            let dst = heimdall_contract::ids::DestinationId::parse("dst-alpha").unwrap();
            if let Some(d) = app.doctor_mut() {
                d.report.findings.push(slot_free_disclosure("alpha", &dst));
            }
            app
        }

        fn detail(app: &App) -> App {
            let mut a = app.clone();
            press(&mut a, &[Key::Char('2'), Key::Enter]);
            assert_eq!(a.screen, Screen::Destination("alpha".to_owned()));
            a
        }

        fn flat(rows: &[String]) -> String {
            rows.join(" ")
                .replace(['│', '┌', '┐', '└', '┘', '─'], " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        }

        fn open(app: &App, id: &str) -> App {
            let mut a = app.clone();
            a.modal = Some(Modal::Decision(DecisionPrompt {
                id: id.to_owned(),
                verdict: Verdict::Approve,
                input: String::new(),
                reading: Reading::default(),
            }));
            a
        }

        fn decides(effects: &[Effect]) -> Vec<(String, Verdict)> {
            effects
                .iter()
                .filter_map(|e| match e {
                    Effect::Worker(Command::Decide { id, verdict }) => Some((id.clone(), *verdict)),
                    _ => None,
                })
                .collect()
        }

        /// The M03 screens of the snapshot set (`m03_*`; the M02 set is unchanged).
        fn m03_screens() -> Vec<(&'static str, App)> {
            let base = m03_app();
            let mut out = vec![("m03_overview", base.clone())];
            out.push(("m03_destination_detail", detail(&base)));
            let mut a = base.clone();
            press(&mut a, &[Key::Char('4')]);
            out.push(("m03_activity", a.clone()));
            let held = (0..a.shown(Tab::Activity))
                .position(|i| matches!(a.activity_row(i), Some(ActivityRow::Enrollment(_))))
                .unwrap();
            for _ in 0..held {
                press(&mut a, &[Key::Down]);
            }
            press(&mut a, &[Key::Enter]);
            out.push(("m03_enrollment_held", a));
            out.push(("m03_decision_enroll", open(&base, "dec_enroll1")));
            out.push(("m03_decision_target_change", open(&base, "dec_target1")));
            out
        }

        /// ⟨M03⟩ TestBackend snapshots of the M03 views at 40×12 and 120×40; `NO_COLOR`
        /// draws the same text and no cell carries a color.
        #[test]
        fn m03_testbackend_snapshots_at_40x12_and_120x40() {
            for (name, app) in m03_screens() {
                for (w, h) in [(40, 12), (120, 40)] {
                    let (rows, _) = draw(&app, w, h);
                    snapshot(&format!("{name}_{w}x{h}"), &rows);
                    let (plain_rows, buffer) = draw(&no_color(&app), w, h);
                    assert_eq!(rows, plain_rows, "{name} {w}x{h}: text differs");
                    for c in buffer.content() {
                        assert_eq!(c.fg, Color::Reset, "{name} {w}x{h}: {c:?}");
                        assert_eq!(c.bg, Color::Reset, "{name} {w}x{h}: {c:?}");
                    }
                }
            }
        }

        /// m03-plan U12 `managed_readiness_detail_exact_deadline_strings` (F15; ADR-0008
        /// D8 items 3 and 6; §17.25 items 19, 20): the managed detail shows the runtime's
        /// own deadline wording from `inspect destinations` `preference.connection_policy`
        /// verbatim: the four D8 texts (graceful and strict, each exclusive and not
        /// exclusive), built by the runtime's `connection_wording` and compared with U8's
        /// constants (never retyped); an undetermined selection gets the qualified text;
        /// owned masters carry D8 item 3's sentence inside the runtime's wording. Modes
        /// without wording, or no policy, read unknown: none of the texts is derived here,
        /// and no "[??]" placeholder is drawn. (Unit level: the `preference` is the serde
        /// form of `ConnectionPolicyReport`, R0 item 19; the e2e half waits on R2's fill.)
        #[test]
        fn managed_readiness_detail_exact_deadline_strings() {
            use heimdall_adapters::managed::report::{
                OWNED_MASTERS_DISCLOSURE, SelectionClass, connection_wording,
            };
            let linux = heimdall_domain::claims::Platform {
                os: "linux",
                arch: "x86_64",
            };
            // The detail for a pair whose `inspect destinations` item carries `policy`.
            let with = |policy: Option<serde_json::Value>| {
                let mut pref = serde_json::json!({"mechanism": "managed_certificate",
                    "projection": {"state": "pending"}});
                if let Some(p) = policy {
                    pref["connection_policy"] = p;
                }
                let mut app = m03_app();
                app.catalog_mut().destinations[0].preference = Preference::of(&pref);
                let app = detail(&app);
                let lines: Vec<String> =
                    crate::tui::m03::managed_lines(app.catalog(), &app.catalog().destinations[0])
                        .iter()
                        .map(|l| l.to_string())
                        .collect();
                (lines, flat(&draw(&app, 120, 60).0))
            };
            let report = |selection, existing, multiplexing| {
                let policy = ConnectionPolicy {
                    existing,
                    multiplexing,
                };
                serde_json::to_value(ConnectionPolicyReport {
                    existing,
                    multiplexing,
                    wording: connection_wording(selection, &policy, &linux),
                })
                .unwrap()
            };
            let all = [
                DEADLINE_GRACEFUL_EXCLUSIVE,
                DEADLINE_GRACEFUL_NOT_EXCLUSIVE,
                DEADLINE_STRICT_EXCLUSIVE,
                DEADLINE_STRICT_NOT_EXCLUSIVE,
            ];
            for (selection, existing, expected) in [
                (
                    SelectionClass::Exclusive,
                    ExistingConnectionsMode::Graceful,
                    DEADLINE_GRACEFUL_EXCLUSIVE,
                ),
                (
                    SelectionClass::NotExclusive,
                    ExistingConnectionsMode::Graceful,
                    DEADLINE_GRACEFUL_NOT_EXCLUSIVE,
                ),
                (
                    SelectionClass::Exclusive,
                    ExistingConnectionsMode::Strict,
                    DEADLINE_STRICT_EXCLUSIVE,
                ),
                (
                    SelectionClass::NotExclusive,
                    ExistingConnectionsMode::Strict,
                    DEADLINE_STRICT_NOT_EXCLUSIVE,
                ),
                // Undetermined: D8 item 6's qualified text.
                (
                    SelectionClass::Undetermined,
                    ExistingConnectionsMode::Graceful,
                    DEADLINE_GRACEFUL_NOT_EXCLUSIVE,
                ),
            ] {
                let (lines, screen) = with(Some(report(
                    selection,
                    existing,
                    MultiplexingMode::Disabled,
                )));
                let wording: Vec<&String> = lines
                    .iter()
                    .filter(|l| all.iter().any(|w| l.trim() == *w))
                    .collect();
                assert_eq!(
                    wording,
                    [&format!("    {expected}")],
                    "{selection:?} {existing:?}: {lines:#?}"
                );
                assert!(
                    screen.contains(expected),
                    "{selection:?} {existing:?}: {screen}"
                );
            }
            // Owned masters: the runtime's wording, D8 item 3's sentence included,
            // verbatim.
            let theirs = format!("{DEADLINE_STRICT_EXCLUSIVE} {OWNED_MASTERS_DISCLOSURE}");
            let (lines, screen) = with(Some(report(
                SelectionClass::Exclusive,
                ExistingConnectionsMode::Strict,
                MultiplexingMode::OwnedMasters,
            )));
            assert!(lines.iter().any(|l| l.trim() == theirs), "{lines:#?}");
            assert!(screen.contains(&theirs), "{screen}");
            // Modes without wording, and no policy at all: unknown, none of the texts,
            // no placeholder.
            for policy in [
                Some(serde_json::json!({"existing": "graceful", "multiplexing": "owned_masters"})),
                None,
            ] {
                let (lines, screen) = with(policy.clone());
                assert!(
                    lines.iter().any(|l| l.trim()
                        == "unknown: the runtime reports no connection policy for this pair"),
                    "{policy:?}: {lines:#?}"
                );
                for w in all {
                    assert!(!screen.contains(w), "{policy:?} {w}: {screen}");
                }
                assert!(!screen.contains("[??]"), "{policy:?}: {screen}");
                assert!(!screen.contains(OWNED_MASTERS_DISCLOSURE), "{screen}");
            }
            // §17.25 item 17: the ordinary-ssh sentence is the CLI's one constant.
            let (_, screen) = with(None);
            assert!(
                screen.contains(&format!(
                    "Note: {}",
                    crate::output::ORDINARY_CONNECTIONS_NOTE
                )),
                "{screen}"
            );
        }

        /// m03-plan U12 `projection_pending_warning_and_setup_apply_hint` (F04): a
        /// managed-certificate pair whose projection is pending is an overview warning
        /// and a detail line, both naming `heimdall setup apply`; a warning, not Needs
        /// attention; an applied projection shows neither. The preference is read from
        /// `inspect destinations`' own shape.
        #[test]
        fn projection_pending_warning_and_setup_apply_hint() {
            let c = crate::tui::data::Catalog::from_answers(
                &serde_json::json!({"items": [
                    {"destination_id": "dst-alpha", "alias": "alpha", "definition": "managed",
                     "preference": {"mechanism": "managed_certificate",
                                    "projection": {"state": "pending"}}},
                    {"destination_id": "dst-b", "alias": "b", "definition": "managed",
                     "preference": {"mechanism": "managed_certificate",
                                    "projection": {"state": "applied", "generation": 4}}},
                ]}),
                &serde_json::Value::Null,
                &serde_json::Value::Null,
                &serde_json::Value::Null,
                &serde_json::Value::Null,
                &serde_json::Value::Null,
                now(),
            );
            assert_eq!(c.destinations[0].preference, Some(pending()));
            assert_eq!(
                c.destinations[1]
                    .preference
                    .as_ref()
                    .and_then(|p| p.projection.clone()),
                Some(Projection::Applied(Some(4)))
            );
            // ⟨M07⟩ U2: the alias and the command in words; the code stays in the detail.
            let hint = "alpha: run `heimdall setup apply` (its managed setup is not applied yet)";
            let mut app = App::new(now(), false);
            app.set_runtime(Runtime::Connected);
            *app.catalog_mut() = c;
            *app.doctor_mut() = Some(crate::tui::data::Doctor {
                report: crate::tui::model::tests::report(),
                taken_at: now(),
            });
            if let Some(d) = app.doctor_mut() {
                d.report.findings.clear();
            }
            let overview = flat(&draw(&app, 120, 40).0);
            assert!(overview.contains(&format!("[ !] {hint}")), "{overview}");
            assert_eq!(
                overview.matches("managed setup is not applied yet").count(),
                1,
                "only the pending pair: {overview}"
            );
            assert!(
                !overview.contains("managed_projection_pending"),
                "{overview}"
            );
            assert_eq!(app.health(), crate::tui::model::Health::Ready, "a warning");
            let screen = flat(&draw(&detail(&app), 120, 40).0);
            assert!(
                screen.contains(
                    "[ !] managed_projection_pending: the managed projection for this pair is not applied yet; run `heimdall setup apply`"
                ),
                "{screen}"
            );
            assert!(screen.contains("projection pending"), "{screen}");
            // Applied: no warning anywhere.
            app.catalog_mut().destinations[0].preference = Some(Preference {
                projection: Some(Projection::Applied(Some(5))),
                ..pending()
            });
            for a in [app.clone(), detail(&app)] {
                let text = flat(&draw(&a, 120, 40).0);
                assert!(!text.contains("managed_projection_pending"), "{text}");
            }
        }

        /// m03-plan U12 ⟨r3⟩ `tui_shows_slot_free_with_command` (ADR-0008 D10 item 2,
        /// §17.4 item 12): the doctor's `slot_free` finding is on the overview (shown,
        /// not Needs attention) and in the destination detail, each with the command
        /// that holds a slot, the doctor's own `slot_free_command`; `heimdall bind
        /// materialize` is never offered.
        #[test]
        fn tui_shows_slot_free_with_command() {
            let mut app = populated();
            let dst = heimdall_contract::ids::DestinationId::parse("dst-alpha").unwrap();
            if let Some(d) = app.doctor_mut() {
                d.report.findings = vec![slot_free_disclosure("alpha", &dst)];
            }
            app.catalog_mut().operations.clear();
            app.catalog_mut().decisions.clear();
            let command = slot_free_command("alpha");
            assert_eq!(command, "heimdall run --profile <profile> -- ssh alpha");
            // An overview row is one terminal row: the command comes first, whole.
            let overview = flat(&draw(&app, 120, 40).0);
            assert!(
                overview.contains(&format!("[ i] alpha: hold the slot with `{command}`")),
                "{overview}"
            );
            let items = app.overview_items();
            assert_eq!(
                item_text(&items[0]),
                format!(
                    "alpha: hold the slot with `{command}` (ordinary `ssh alpha` needs a held slot)"
                )
            );
            assert_eq!(app.health(), crate::tui::model::Health::Ready);
            // Enter on it opens the destination.
            let mut a = app.clone();
            press(&mut a, &[Key::Enter]);
            assert_eq!(a.screen, Screen::Destination("alpha".to_owned()));
            let screen = flat(&draw(&a, 120, 40).0);
            // The detail shows the doctor's own finding, which names the same command.
            let message = flat(&[slot_free_disclosure("alpha", &dst).message]);
            assert!(message.contains(&format!("`{command}`")), "{message}");
            assert!(
                screen.contains(&format!("[ i] slot_free: {message}")),
                "{screen}"
            );
            for text in [&overview, &screen] {
                assert!(!text.contains("bind materialize"), "{text}");
            }
        }

        /// m03-plan U12 `lock_disclosure_once` (ADR-0008 D9 item 1, R-UX-03; §17.25 item
        /// 21): the behaviour, the disclosure and its acknowledgement come from `inspect
        /// capabilities` `lock`. The disclosure is shown, the runtime's text verbatim, in
        /// a decision whose record carries it while `acknowledged_at` is absent, and not
        /// in one that does not; once acknowledged it is not shown again (the modal and
        /// the detail say when it was acknowledged). With no lock report it is never
        /// shown as text and the behaviour reads unknown. The decisions that carry it
        /// (`enroll_account`, `register_issuer`) are decided only in the CLI: a typed
        /// `yes` sends nothing. (Unit level: the `lock` object is R0 item 21's documented
        /// shape; the e2e half waits on R2's fill.)
        #[test]
        fn lock_disclosure_once() {
            let said = "Approved work is designed to keep working while your screen or password manager is locked, until its end time.";
            let capabilities = |ack: Option<&str>| {
                let mut lock = serde_json::json!({"behavior": "continue", "disclosure": said});
                if let Some(at) = ack {
                    lock["acknowledged_at"] = serde_json::Value::String(at.to_owned());
                }
                serde_json::json!({"capabilities": [], "lock": lock})
            };
            let mut app = m03_app();
            app.catalog_mut().decisions = vec![
                enroll_decision("dec_first", vec![DisclosureKind::LockContinuityOnce]),
                enroll_decision("dec_second", vec![]),
                register_decision("dec_register", false, false),
            ];
            app.catalog_mut().m03.time_uncertain = None;
            let heading = "Lock disclosure (shown once; recorded when the decision is approved):";
            // Not acknowledged: the runtime's text, verbatim, where the record carries it.
            app.catalog_mut().m03.lock = Listings::of(
                &serde_json::Value::Null,
                &serde_json::Value::Null,
                &capabilities(None),
                &[],
            )
            .lock;
            assert_eq!(
                app.catalog().m03.lock,
                Some(LockReport {
                    behavior: "continue".to_owned(),
                    disclosure: Some(said.to_owned()),
                    acknowledged_at: None,
                })
            );
            for id in ["dec_first", "dec_register"] {
                let text = flat(&read_everything(&open(&app, id), 120, 40));
                assert!(text.contains(&format!("{heading} {said}")), "{id}: {text}");
                let mut a = open(&app, id);
                draw(&a, 120, 40);
                type_text(&mut a, "yes");
                let effects = press(&mut a, &[Key::Enter]);
                // §17.26: approved only in the CLI; a typed yes here is a Deny.
                assert_eq!(
                    decides(&effects),
                    [(id.to_owned(), Verdict::Deny)],
                    "{id}: {effects:?}"
                );
            }
            let text = flat(&read_everything(&open(&app, "dec_second"), 120, 40));
            assert!(!text.contains("Lock disclosure"), "{text}");
            assert!(text.contains("Disclosures: none"), "{text}");
            let screen = flat(&draw(&detail(&app), 120, 60).0);
            assert!(screen.contains("Lock behaviour: continue"), "{screen}");
            assert!(
                screen.contains(&format!("Lock disclosure (not yet acknowledged): {said}")),
                "{screen}"
            );
            // Acknowledged: shown once, so not again; the detail says when.
            app.catalog_mut().m03.lock = Listings::of(
                &serde_json::Value::Null,
                &serde_json::Value::Null,
                &capabilities(Some("2026-11-03T08:30:00Z")),
                &[],
            )
            .lock;
            for id in ["dec_first", "dec_register"] {
                let text = flat(&read_everything(&open(&app, id), 120, 40));
                assert!(!text.contains(said), "{id}: {text}");
                assert!(!text.contains(heading), "{id}: {text}");
                assert!(
                    text.contains(
                        "Lock disclosure: acknowledged 2026-11-03T08:30:00Z; not shown again"
                    ),
                    "{id}: {text}"
                );
            }
            let screen = flat(&draw(&detail(&app), 120, 60).0);
            assert!(screen.contains("Lock behaviour: continue"), "{screen}");
            assert!(
                screen.contains("Lock disclosure acknowledged 2026-11-03T08:30:00Z"),
                "{screen}"
            );
            assert!(!screen.contains(said), "{screen}");
            // No lock report: the shared text's general sentence (IS2's
            // `disclosure_text` without the runtime's text), never the runtime's; the
            // behaviour reads unknown.
            app.catalog_mut().m03.lock = None;
            let general = heimdall_issuer::ceremony::disclosure_text(
                DisclosureKind::LockContinuityOnce,
                &heimdall_issuer::ceremony::DisclosureContext::default(),
            );
            let text = flat(&read_everything(&open(&app, "dec_first"), 120, 40));
            assert!(text.contains(&format!("{heading} {general}")), "{text}");
            assert!(!text.contains(said), "{text}");
            let screen = flat(&draw(&detail(&app), 120, 60).0);
            assert!(
                screen.contains("Lock behaviour: unknown (not reported by the runtime)"),
                "{screen}"
            );
        }

        /// ⟨M03⟩ §17.25 item 10, §17.26 (Q-T2-1, Q-T2-2): the decision kinds whose
        /// follow-through needs the owner at a CLI terminal (`enroll_account`,
        /// `enroll_system_form`, `register_issuer` for an init, a rotation and a restore,
        /// `retire_issuer`, `remove_enrollment` own and foreign) are shown read-only with
        /// their CLI command. Approve is never offered or sent, and nothing toggles to
        /// it; Deny is the one verdict, sent once after a typed `yes`; Esc, Ctrl-C, an
        /// end-of-input byte (Ctrl-D) and anything but `yes` send nothing.
        /// `approve_target_change` (the runtime runs its verification) still offers both.
        #[test]
        fn cli_decided_kinds_never_offer_approve_and_show_their_command() {
            let mut app = m03_app();
            let enr = heimdall_contract::ids::EnrollmentId::from_random_bytes([5; 16]);
            let mut foreign = remove_decision("dec_foreign", 6);
            foreign.request["target"] = serde_json::json!({"kind": "foreign",
                "local_alias": "alpha", "bundle_destination_id": "dst-old",
                "bundle_hostname": "alpha.example.invalid", "bundle_port": 22,
                "account": "fixture", "marker": "heimdall:enr_x", "ca_public_key": "k",
                "line_sha256": "ab".repeat(32),
                "registry": {"path": null, "resolved_by": "remote_home"}, "form": "account"});
            app.catalog_mut().decisions = vec![
                enroll_decision("dec_enroll", vec![DisclosureKind::CaTrustBlastRadius]),
                system_form_decision("dec_system"),
                register_decision("dec_init", false, false),
                register_decision("dec_rotate", true, false),
                register_decision("dec_restore", false, true),
                retire_decision("dec_retire"),
                remove_decision("dec_remove", 5),
                foreign,
                target_change_decision(),
            ];
            let ca = crate::tui::m03::fixtures::ca();
            for (id, command) in [
                ("dec_enroll", "heimdall enroll alpha".to_owned()),
                ("dec_system", "heimdall enroll alpha --form system".to_owned()),
                ("dec_init", "heimdall issuer init --backup-out <path>".to_owned()),
                (
                    "dec_rotate",
                    "heimdall issuer rotate begin --backup-out <path>".to_owned(),
                ),
                ("dec_restore", "heimdall issuer restore --backup <file>".to_owned()),
                ("dec_retire", format!("heimdall issuer retire {ca}")),
                ("dec_remove", format!("heimdall enroll remove {enr}")),
                (
                    "dec_foreign",
                    "heimdall enroll remove --from-bundle <file> --marker heimdall:enr_x --alias alpha"
                        .to_owned(),
                ),
            ] {
                let a = open(&app, id);
                let text = flat(&read_everything(&a, 120, 40));
                assert!(
                    text.contains(&format!(
                        "approved only in the CLI, on the terminal that runs `{command}` (its follow-through needs you there). Approve is not offered here; you can deny it here with a typed yes."
                    )),
                    "{id}: {text}"
                );
                let prompt = flat(&draw(&a, 120, 40).0);
                assert!(
                    prompt.contains(&format!("Approve in the CLI: run `{command}`")),
                    "{id}: {prompt}"
                );
                assert!(prompt.contains("Deny? Type yes to confirm"), "{id}: {prompt}");
                assert!(!prompt.contains("Approve? Type yes"), "{id}: {prompt}");
                // Typed yes, as opened and after any number of Tabs: Deny, sent once;
                // never Approve, and Tab never toggles to Approve.
                for tabs in 0..3 {
                    let mut b = a.clone();
                    for _ in 0..tabs {
                        press(&mut b, &[Key::Tab]);
                        let Some(Modal::Decision(p)) = &b.modal else {
                            panic!("{id}: the modal closed on Tab")
                        };
                        assert_eq!(p.verdict, Verdict::Deny, "{id}: Tab x{tabs}");
                        let prompt = flat(&draw(&b, 120, 40).0);
                        assert!(!prompt.contains("Approve? Type yes"), "{id}: {prompt}");
                    }
                    draw(&b, 120, 40);
                    type_text(&mut b, "yes");
                    let effects = press(&mut b, &[Key::Enter]);
                    assert_eq!(
                        decides(&effects),
                        [(id.to_owned(), Verdict::Deny)],
                        "{id} tabs={tabs}"
                    );
                    assert!(b.modal.is_none(), "{id}: closed after sending");
                }
                // Nothing is sent without the typed yes: Esc, Ctrl-C, an end-of-input
                // byte then Enter, an empty Enter, `no`.
                for keys in [
                    vec![Key::Esc],
                    vec![Key::CtrlC],
                    vec![Key::Other, Key::Enter],
                    vec![Key::Enter],
                ] {
                    let mut b = a.clone();
                    draw(&b, 120, 40);
                    type_text(&mut b, "ye");
                    let effects = press(&mut b, &keys);
                    assert!(decides(&effects).is_empty(), "{id} {keys:?}: {effects:?}");
                }
                for typed in ["no", "nope", ""] {
                    let mut b = a.clone();
                    draw(&b, 120, 40);
                    type_text(&mut b, typed);
                    let effects = press(&mut b, &[Key::Enter]);
                    assert!(decides(&effects).is_empty(), "{id} {typed:?}: {effects:?}");
                    assert!(
                        b.status.as_deref().unwrap_or_default().contains("nothing was sent"),
                        "{id} {typed:?}: {:?}",
                        b.status
                    );
                }
            }
            // The target change still offers both verdicts.
            let mut a = open(&app, "dec_target1");
            draw(&a, 120, 40);
            type_text(&mut a, "yes");
            assert_eq!(
                decides(&press(&mut a, &[Key::Enter])),
                [("dec_target1".to_owned(), Verdict::Approve)]
            );
            let mut a = open(&app, "dec_target1");
            press(&mut a, &[Key::Tab]);
            draw(&a, 120, 40);
            type_text(&mut a, "yes");
            assert_eq!(
                decides(&press(&mut a, &[Key::Enter])),
                [("dec_target1".to_owned(), Verdict::Deny)]
            );
        }

        /// ⟨M03⟩ The target-change decision shows the key diff (approved `-`, proposed
        /// `+`, the full keys) behind the typed yes; the enrollment decision its plan
        /// line, registry, line digest and disclosures.
        #[test]
        fn m03_decisions_render_the_recorded_request_readably() {
            let app = m03_app();
            let text = flat(&read_everything(&open(&app, "dec_target1"), 120, 40));
            for want in [
                "- host key fingerprint SHA256:hostOld",
                "+ host key fingerprint SHA256:hostNew",
                "- host key AAAAC3NzaC1lZDI1NTE5AAAAIhostOld",
                "+ host key AAAAC3NzaC1lZDI1NTE5AAAAIhostNew",
                "HostName alpha.example.invalid",
            ] {
                assert!(text.contains(want), "{want}: {text}");
            }
            assert!(
                !text.contains("- HostName"),
                "unchanged fields once: {text}"
            );
            let prompt = flat(&draw(&open(&app, "dec_target1"), 120, 40).0);
            assert!(
                prompt.contains("Approve? Type yes to confirm [y/N]"),
                "{prompt}"
            );
            let mut a = open(&app, "dec_target1");
            draw(&a, 120, 40);
            type_text(&mut a, "yes");
            assert_eq!(
                decides(&press(&mut a, &[Key::Enter])),
                [("dec_target1".to_owned(), Verdict::Approve)]
            );
            let text = flat(&read_everything(&open(&app, "dec_enroll1"), 120, 40));
            // §17.25 item 10: each disclosure is the one shared text, never retyped.
            let blast = heimdall_issuer::ceremony::disclosure_text(
                DisclosureKind::CaTrustBlastRadius,
                &heimdall_issuer::ceremony::DisclosureContext {
                    alias: Some("alpha"),
                    lock: None,
                },
            );
            for want in [
                "Plan: enroll fixture at alpha (dst-alpha), account form, under CA SHA256:",
                "Registry ~/.ssh/authorized_keys (resolved by remote_home)",
                &format!("line SHA-256 {}", "ab".repeat(32)),
                "Existing access: ssh alpha",
                &format!("* ca_trust_blast_radius: {blast}"),
                "Lock disclosure (shown once",
            ] {
                assert!(text.contains(want), "{want}: {text}");
            }
            // A disclosure kind this build does not know: the shared unknown text.
            let mut b = app.clone();
            b.catalog_mut().decisions[0].request["summary"]["disclosures"] =
                serde_json::json!(["a_newer_disclosure"]);
            let text = flat(&read_everything(&open(&b, "dec_enroll1"), 120, 40));
            assert!(
                text.contains(&format!(
                    "* a_newer_disclosure: {}",
                    heimdall_issuer::ceremony::UNKNOWN_DISCLOSURE
                )),
                "{text}"
            );
            // An enrollment decision's operation is linked from its record.
            assert_eq!(
                app.catalog().decisions[0].operation().as_deref(),
                Some("op_enroll1")
            );
        }

        /// The enrollment detail: a held record's reason and next step, the
        /// `late_write` residual with its command, and a held record with no reason
        /// reported reads unknown (Q-T1).
        #[test]
        fn m03_enrollment_detail_shows_reason_next_step_and_late_write() {
            let app = m03_app();
            let ids: Vec<String> = app
                .catalog()
                .m03
                .enrollments
                .iter()
                .map(|e| e.id.clone())
                .collect();
            let mut a = app.clone();
            a.screen = Screen::Enrollment(ids[0].clone());
            let text = flat(&draw(&a, 120, 40).0);
            assert!(text.contains("[!!] Held: host_key_changed"), "{text}");
            assert!(
                text.contains(&format!(
                    "next: - `heimdall enroll verify {0} --approve-target-change` - `heimdall enroll remove {0}`",
                    ids[0]
                )),
                "{text}"
            );
            // §17.25 item 4: the runtime's `next` only; with none named nothing is
            // derived here, whatever the reason.
            let mut c = app.clone();
            c.catalog_mut().m03.enrollments[0].hold = Some(crate::tui::m03::Hold {
                reason: "host_key_changed".to_owned(),
                next: Vec::new(),
            });
            c.screen = Screen::Enrollment(ids[0].clone());
            let text = flat(&draw(&c, 120, 40).0);
            assert!(
                text.contains("[!!] Held: host_key_changed next: none named by the runtime"),
                "{text}"
            );
            assert!(!text.contains("--approve-target-change"), "{text}");
            a.screen = Screen::Enrollment(ids[1].clone());
            let text = flat(&draw(&a, 120, 40).0);
            assert!(
                text.contains("Possible late write (the late_write residual)"),
                "{text}"
            );
            assert!(
                text.contains(&format!("`heimdall enroll verify {} --absence`", ids[1])),
                "{text}"
            );
            let mut b = app.clone();
            b.catalog_mut().m03.enrollments[0].hold = None;
            b.screen = Screen::Enrollment(ids[0].clone());
            let text = flat(&draw(&b, 120, 40).0);
            assert!(
                text.contains("Held: reason unknown (not reported by the runtime) next: unknown"),
                "{text}"
            );
            // The overview: the held record needs attention, the residual is a warning.
            let overview = flat(&draw(&app, 120, 40).0);
            assert!(
                overview.contains(&format!("[!!] enrollment {} is held", ids[0])),
                "{overview}"
            );
            assert!(
                overview.contains(&format!(
                    "[ !] enrollment {} may have a late write (Enter for the residual and its command)",
                    ids[1]
                )),
                "{overview}"
            );
            assert!(!overview.contains(&format!("enrollment {} is", ids[2])));
        }

        /// The time chore on the overview (the pty half is `tui_m03`'s
        /// `time_confirmation_chore_shown_after_reboot`): first, Needs attention, with
        /// its one command.
        #[test]
        fn m03_time_chore_is_first_with_its_command() {
            let app = m03_app();
            let items = app.overview_items();
            assert!(matches!(items[0], crate::tui::model::Item::Chore { .. }));
            assert_eq!(app.health(), crate::tui::model::Health::Attention);
            assert_eq!(
                item_text(&items[0]),
                format!(
                    "time_confirmation_after_reboot: run `heimdall time confirm` ({TIME_MESSAGE}; after a reboot it needs one attended confirmation)"
                )
            );
            // An overview row is one terminal row: the command comes first, whole.
            let text = flat(&draw(&app, 120, 40).0);
            assert!(
                text.contains(
                    "> [!!] time_confirmation_after_reboot: run `heimdall time confirm` (safe time"
                ),
                "{text}"
            );
            // §17.25 item 15: keyed on the reason, not the code. A `TIME_UNCERTAIN`
            // without it (skew, rollback) is not the reboot chore.
            for reason in [None, Some("clock_skew".to_owned())] {
                let mut b = app.clone();
                b.catalog_mut().m03 = Listings::of(
                    &serde_json::Value::Null,
                    &serde_json::Value::Null,
                    &serde_json::Value::Null,
                    &[heimdall_contract::envelope::Warning {
                        code: crate::tui::m03::TIME_UNCERTAIN.to_owned(),
                        message: TIME_MESSAGE.to_owned(),
                        reason: reason.clone(),
                    }],
                );
                assert!(b.catalog().m03.time_uncertain.is_none(), "{reason:?}");
                let text = flat(&draw(&b, 160, 40).0);
                assert!(
                    !text.contains("time_confirmation_after_reboot"),
                    "{reason:?}: {text}"
                );
            }
        }

        /// With no runtime connected, the chore comes from the store reader (worker U's
        /// `doctor_cmd::pending_chores`), its command first; once connected, the
        /// runtime's own view governs.
        #[test]
        fn m03_time_chore_offline_from_the_store_reader() {
            let chore = crate::doctor_cmd::PendingChore {
                chore: crate::doctor_cmd::TIME_CONFIRMATION_CHORE,
                command: crate::doctor_cmd::TIME_CONFIRM_COMMAND,
                message: "this machine restarted since its time was last trusted; managed issuance waits until you confirm the time once, attended: run `heimdall time confirm`".to_owned(),
            };
            let line = crate::tui::m03::chore_line(&chore);
            assert_eq!(
                line,
                "time_confirmation_after_reboot: run `heimdall time confirm` (this machine restarted since its time was last trusted; managed issuance waits until you confirm the time once, attended)"
            );
            let mut app = m03_app();
            app.set_runtime(Runtime::NotRunning);
            app.catalog_mut().m03.time_uncertain = None;
            app.apply(crate::tui::model::Update::OfflineChores(vec![line.clone()]));
            assert_eq!(item_text(&app.overview_items()[0]), line);
            let text = flat(&draw(&app, 120, 40).0);
            assert!(
                text.contains("> [!!] time_confirmation_after_reboot: run `heimdall time confirm` (this machine"),
                "{text}"
            );
            app.set_runtime(Runtime::Connected);
            let text = flat(&draw(&app, 160, 40).0);
            assert!(!text.contains("time_confirmation_after_reboot"), "{text}");
        }

        /// Search and the refresh never reach the issuer or a remote (the pty half is
        /// `tui_m03`'s `tui_search_never_contacts_issuer_or_remote`): typing a search over
        /// the M03 state produces no effect at all, and the refresh reads only `inspect`
        /// subjects, never `issuer`.
        #[test]
        fn m03_search_and_refresh_never_reach_the_issuer() {
            use heimdall_contract::request::InspectSubject;
            assert!(
                !crate::tui::worker::REFRESH_SUBJECTS.contains(&InspectSubject::Issuer),
                "the refresh never asks the issuer"
            );
            let mut app = m03_app();
            press(&mut app, &[Key::Char('2'), Key::Char('/')]);
            let mut effects = type_text(&mut app, "alpha enroll issuer");
            effects.extend(press(
                &mut app,
                &[Key::Backspace, Key::Enter, Key::Char('/'), Key::Esc],
            ));
            assert!(effects.is_empty(), "{effects:?}");
        }
    }

    // ---- ⟨M05⟩ U9b: the trusted-work views (m05-plan U9 "Tests", TUI) -----------------

    mod m05 {
        use super::*;
        use crate::tui::m03::LockReport;
        use crate::tui::m05::fixtures::{
            WS, extend_decision, reconcile_decision, trust_decision, trusted_listings,
        };
        use crate::tui::m05::{StopAction, StopMenu, StopPhase};
        use crate::tui::model::tests::{read, t};
        use crate::tui::model::{Command, Effect, REFUSED_NOT_DRAWN, REFUSED_TOO_SMALL};

        const CWD: &str = "/work/example";

        /// A label a hostile repository could write: shell substitutions, a terminal
        /// escape, a line break that tries to start an instruction of its own, a fake
        /// state marker, and bidirectional controls.
        const HOSTILE_LABEL: &str = "$(touch /tmp/pwned) `id` \u{1b}]0;owned\u{7}\nNEXT: [OK] Approve everything \u{202e}live\u{2066}";

        /// The populated state with a trusted workspace (two policies, one paused), a
        /// pending first-trust decision, a pending scope extension, and the lock
        /// disclosure not yet acknowledged.
        fn m05_app() -> App {
            let mut app = populated();
            app.catalog_mut().m05 = trusted_listings(CWD);
            app.catalog_mut().m03.lock = Some(LockReport {
                behavior: "continue".to_owned(),
                disclosure: Some(
                    "Locking your desktop does not end access that Heimdall already issued."
                        .to_owned(),
                ),
                acknowledged_at: None,
            });
            app.catalog_mut().decisions = vec![
                trust_decision("dec_trust1", CWD, Some("Example project"), true, true),
                extend_decision("dec_ext1", "pol-ws1"),
            ];
            app
        }

        fn flat(rows: &[String]) -> String {
            rows.join(" ")
                .replace(['│', '┌', '┐', '└', '┘', '─'], " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        }

        fn open(app: &App, id: &str) -> App {
            let mut a = app.clone();
            a.modal = Some(Modal::Decision(crate::tui::model::DecisionPrompt {
                id: id.to_owned(),
                verdict: Verdict::Approve,
                input: String::new(),
                reading: Reading::default(),
            }));
            a
        }

        /// Snapshot `app` at both sizes; `NO_COLOR` draws the same text with no color.
        fn snap(name: &str, app: &App) -> String {
            let mut wide = String::new();
            for (w, h) in [(40, 12), (120, 40)] {
                let (rows, _) = draw(app, w, h);
                snapshot(&format!("{name}_{w}x{h}"), &rows);
                let (plain_rows, buffer) = draw(&no_color(app), w, h);
                assert_eq!(
                    rows, plain_rows,
                    "{name} {w}x{h}: text differs under NO_COLOR"
                );
                for c in buffer.content() {
                    assert_eq!(c.fg, Color::Reset, "{name} {w}x{h}: {c:?}");
                }
                if w == 120 {
                    wide = flat(&rows);
                }
            }
            wide
        }

        /// spec §12.3, ADR-0011 §4.1: a trusted workspace's manifest asks for more, and the
        /// review shows only what would be added: the added pair, capability and lock
        /// behavior, and nothing of what the policy already grants or of the rest of the
        /// profile.
        #[test]
        fn delta_review_shows_only_added_authority() {
            let app = open(&m05_app(), "dec_ext1");
            let text = snap("m05_delta_review", &app);
            for added in [
                "Added pairs",
                "+ beta:deploy",
                "Added capabilities",
                "+ git-signing",
                "Added lock behavior",
                "work continues while your desktop and password manager are locked",
                "Only what would be ADDED is listed",
                "Approving applies exactly this addition. Denying changes nothing.",
            ] {
                assert!(text.contains(added), "{added}: {text}");
            }
            // The first-trust scope (alpha:fixture, ssh-authentication, the environment) and
            // the profile's other pairs are already granted or not requested: not repeated.
            for whole in [
                "alpha:fixture",
                "ssh-authentication",
                "env_2222",
                "Profile:",
                "Detail:",
                "Use ",
            ] {
                assert!(
                    !text.contains(whole),
                    "{whole} is not added authority: {text}"
                );
            }
            // Only the one record shown can be approved, and only as that record.
            let mut app = app;
            read(&app);
            type_text(&mut app, "yes");
            let effects = press(&mut app, &[Key::Enter]);
            assert_eq!(
                effects,
                [Effect::Worker(Command::Decide {
                    id: "dec_ext1".to_owned(),
                    verdict: Verdict::Approve
                })]
            );
        }

        /// spec §5.2: the first-trust message, with the detail view of pairs, environments,
        /// lock continuity and limits an owner can read before answering.
        #[test]
        fn first_trust_detail_lists_scope_environments_and_limits() {
            let app = open(&m05_app(), "dec_trust1");
            let text = snap("m05_first_trust", &app);
            for expected in [
                // Ruling I-21: the question names the profile by its ID; the owner's label is
                // quoted data in the detail line only.
                "Use dev access automatically for this project?",
                "Profile: dev (label \"Development\")",
                "Work can continue while your desktop and password manager are locked, using your saved session limits.",
                "You can pause or remove access at any time.",
                // ⟨M07⟩ U2: everyday words on the first-trust surface.
                "Detail: what approving allows",
                "alpha:fixture",
                "Environments: - env_22222222222222222222222222222222",
                "Capabilities: - SSH sign-in",
                "Lock continuity: the project asks for background work",
                "each work session lasts at most 12 h by default (also shown in settings)",
                "Lock disclosure (shown once; recorded when the decision is approved)",
                "Locking your desktop does not end access that Heimdall already issued.",
                "Denying records nothing.",
            ] {
                assert!(text.contains(expected), "{expected}: {text}");
            }
            // A project that does not ask for background work is told so, and the §5.2
            // sentence about working while locked is not claimed for it.
            let mut app = m05_app();
            app.catalog_mut().decisions =
                vec![trust_decision("dec_trust2", CWD, None, false, false)];
            let app = open(&app, "dec_trust2");
            let text = flat(&draw(&app, 120, 40).0);
            assert!(text.contains("does not ask for background work"), "{text}");
            assert!(
                !text.contains("Work can continue while your desktop"),
                "{text}"
            );
            assert!(
                !text.contains("Project label"),
                "no label, no label line: {text}"
            );
        }

        /// spec §12.3, §5.6: four distinct actions, each with its own sentence, none of them
        /// the others' effect.
        #[test]
        fn stop_menu_distinguishes_four_actions() {
            let mut app = m05_app();
            press(&mut app, &[Key::Char('s')]);
            assert!(matches!(app.modal, Some(Modal::StopMenu(_))));
            let text = snap("m05_stop_menu", &app);
            for expected in [
                "1. Pause automatic access",
                "No new work starts automatically for this workspace. Work already running continues.",
                "2. Stop this work",
                "Ends one piece of work, named by its work ID",
                // ⟨M07⟩ U2: everyday words on the stop menu.
                "access only it uses ends now",
                "Other work, and access it shares with other work, stay.",
                "3. Stop all for a profile",
                "Pauses every policy of a profile and ends its active access now",
                "4. Cutoff at a time",
                "after it no new work starts and existing access ends, until you clear the cutoff",
            ] {
                assert!(text.contains(expected), "{expected}: {text}");
            }
            // A short terminal keeps the selected action on screen.
            for (key, name) in [
                (Key::Char('4'), "4. Cutoff at a time"),
                (Key::Down, "4. Cutoff at a time"),
            ] {
                press(&mut app, &[key]);
                let narrow = flat(&draw(&app, 40, 12).0);
                assert!(narrow.contains(name), "{name}: {narrow}");
            }
            // Every action is a typed confirmation away from the request, never one key.
            let mut app = m05_app();
            let sent = press(&mut app, &[Key::Char('s'), Key::Enter, Key::Enter]);
            assert!(sent.is_empty(), "default No sends nothing: {sent:?}");
            let mut app = m05_app();
            press(&mut app, &[Key::Char('s'), Key::Enter]);
            // ⟨M07⟩ The confirmation is drawn before it is answered.
            read(&app);
            type_text(&mut app, "yes");
            let sent = press(&mut app, &[Key::Enter]);
            assert!(
                matches!(sent.as_slice(), [Effect::Worker(Command::Stop(_))]),
                "{sent:?}"
            );
        }

        /// The four stop-menu actions: for each, the keys that reach its confirmation
        /// from the overview (with nothing drawn in between) and the action a confirmed
        /// yes sends.
        fn stop_cases() -> Vec<(&'static str, Vec<Key>, StopAction)> {
            let typed = |digit: char, value: &str| -> Vec<Key> {
                let mut keys = vec![Key::Char('s'), Key::Char(digit), Key::Enter];
                keys.extend(value.chars().map(Key::Char));
                keys.push(Key::Enter);
                keys
            };
            let workspace = heimdall_contract::ids::WorkspaceId::parse(WS).unwrap();
            vec![
                (
                    "pause",
                    vec![Key::Char('s'), Key::Enter],
                    StopAction::Pause {
                        workspace: workspace.clone(),
                    },
                ),
                (
                    "stop this work",
                    typed('2', "job-7"),
                    StopAction::Work {
                        work_id: heimdall_contract::ids::WorkId::parse("job-7").unwrap(),
                    },
                ),
                // The workspace's profile is offered as the value: Enter takes it.
                (
                    "stop all for a profile",
                    typed('3', ""),
                    StopAction::Profile {
                        profile: heimdall_contract::ids::ProfileId::parse("dev").unwrap(),
                    },
                ),
                (
                    "cutoff",
                    typed('4', "2026-12-01T02:00:00-05:00"),
                    StopAction::Cutoff {
                        workspace,
                        at: t("2026-12-01T07:00:00Z"),
                    },
                ),
            ]
        }

        /// The four actions' names, as the menu and the confirmation show them.
        const STOP_NAMES: [&str; 4] = [
            "Pause automatic access",
            "Stop this work",
            "Stop all for a profile",
            "Cutoff at a time",
        ];

        /// What the keys sent to the worker.
        fn stops(effects: &[Effect]) -> Vec<Command> {
            effects
                .iter()
                .filter_map(|e| match e {
                    Effect::Worker(c) => Some(c.clone()),
                    _ => None,
                })
                .collect()
        }

        /// The open stop menu, which must be asking for the confirmation of `action`.
        fn confirming<'a>(app: &'a App, action: &StopAction, what: &str) -> &'a StopMenu {
            match &app.modal {
                Some(Modal::StopMenu(m)) if m.phase == StopPhase::Confirm(action.clone()) => m,
                other => panic!("{what}: the confirmation is not open: {other:?}"),
            }
        }

        /// Why a typed yes would be refused now.
        fn unseen(app: &App, action: &StopAction) -> Option<&'static str> {
            confirming(app, action, "unseen").unseen(app.frame())
        }

        /// Draw at `w`×`h`, paging down a frame at a time, until every row of the
        /// confirmation has been on screen.
        fn read_through(app: &mut App, action: &StopAction, w: u16, h: u16) {
            draw_once(app, w, h);
            let mut guard = 0;
            while unseen(app, action).is_some() {
                press(app, &[Key::PageDown]);
                draw_once(app, w, h);
                guard += 1;
                assert!(guard < 40, "{w}x{h}: {:?}", unseen(app, action));
            }
        }

        /// The M07-W0-R01 ruling for the stop menu,
        /// `stop_menu_batched_input_cannot_confirm_before_a_frame_is_drawn`: the input loop
        /// handles a whole batch of keys before it draws, so a batch that opens the menu,
        /// picks an action, types its value and `yes` has shown the owner nothing. For
        /// each of the four actions it sends nothing: the menu stays on the confirmation
        /// with the answer discarded, and the next frame names the action and its target
        /// and says why. The same holds for a confirmation another one's frame preceded,
        /// for a jump to the end before the first frame, for a re-wrapped text, and for a
        /// confirmation the latest frame did not draw. Once the frames have drawn every
        /// row, a typed yes sends exactly that action.
        #[test]
        fn stop_menu_batched_input_cannot_confirm_before_a_frame_is_drawn() {
            let yes = [Key::Char('y'), Key::Char('e'), Key::Char('s'), Key::Enter];
            for (case, (name, keys, action)) in stop_cases().into_iter().enumerate() {
                // One batch, no frame: open, pick, type the value, yes, Enter.
                let mut app = m05_app();
                let batch: Vec<Key> = keys.iter().copied().chain(yes).collect();
                assert_eq!(stops(&press(&mut app, &batch)), [], "{name}: nothing drawn");
                let menu = confirming(&app, &action, name);
                assert!(menu.input.is_empty(), "{name}: the answer is discarded");
                assert_eq!(app.status.as_deref(), Some(REFUSED_NOT_DRAWN), "{name}");
                // The frame that follows shows the action, its target, and the refusal.
                let rows = draw_once(&app, 120, 40);
                let screen = flat(&rows);
                for shown in [
                    action.sentence().as_str(),
                    "yes refused: it was not on screen",
                    "Type yes to confirm [y/N]: _",
                ] {
                    assert!(screen.contains(shown), "{name}: {shown}:\n{screen}");
                }
                assert_eq!(rows.last().map(String::as_str), Some(REFUSED_NOT_DRAWN));
                // Now it has been on screen: the same answer confirms it, and what is
                // sent is exactly the action that was shown.
                type_text(&mut app, "yes");
                assert_eq!(
                    stops(&press(&mut app, &[Key::Enter])),
                    [Command::Stop(action.clone())],
                    "{name}"
                );
                assert!(app.modal.is_none(), "{name}");

                // A confirmation that was drawn does not vouch for the next one: Esc,
                // then the same action again and yes, all in one batch.
                let mut app = m05_app();
                press(&mut app, &keys);
                draw_once(&app, 120, 40);
                assert_eq!(unseen(&app, &action), None, "{name}: read");
                let again: Vec<Key> = [Key::Esc]
                    .into_iter()
                    .chain(keys.iter().copied())
                    .chain(yes)
                    .collect();
                assert_eq!(stops(&press(&mut app, &again)), [], "{name}: a new one");
                confirming(&app, &action, name);
                assert_eq!(app.status.as_deref(), Some(REFUSED_NOT_DRAWN), "{name}");

                // At 40×8 the confirmation does not fit. A jump to the end before the
                // first frame draws its last rows only: the action's name and the start
                // of its sentence were never on screen, so the yes is refused.
                let mut app = m05_app();
                press(&mut app, &keys);
                press(&mut app, &[Key::End]);
                let screen = draw_once(&app, 40, 8).join("\n");
                let menu = confirming(&app, &action, name);
                assert!(menu.seen.reading.scrollable(), "{name}:\n{screen}");
                assert!(menu.seen.reading.end_shown(), "{name}:\n{screen}");
                type_text(&mut app, "yes");
                assert_eq!(stops(&press(&mut app, &[Key::Enter])), [], "{name}: a jump");
                assert_eq!(app.status.as_deref(), Some(REFUSED_UNREAD), "{name}");
                let rows = draw_once(&app, 40, 8);
                assert!(rows.join("\n").contains("yes refused"), "{name}: {rows:?}");
                assert_eq!(rows.last().map(String::as_str), Some(REFUSED_UNREAD));
                // The first window alone is not all of it either.
                press(&mut app, &[Key::Home]);
                let screen = draw_once(&app, 40, 8).join("\n");
                assert!(screen.contains("below (PgDn)"), "{name}:\n{screen}");
                type_text(&mut app, "yes");
                assert_eq!(stops(&press(&mut app, &[Key::Enter])), [], "{name}: a part");
                // Read from the top, frame by frame: once the yes can be accepted, the
                // content rows the frames drew (each page repeats the row before it) add
                // up to the action's name and its whole sentence, character by character.
                press(&mut app, &[Key::Home]);
                let mut drawn: Vec<String> = Vec::new();
                let mut guard = 0;
                loop {
                    let rows = draw_once(&app, 40, 8);
                    let top = rows.iter().position(|r| r.contains('┌')).unwrap();
                    let left = rows[top].chars().position(|c| c == '┌').unwrap();
                    let right = rows[top].chars().position(|c| c == '┐').unwrap();
                    let viewport = confirming(&app, &action, name)
                        .seen
                        .reading
                        .drawn()
                        .unwrap()
                        .viewport;
                    for row in &rows[top + 1..top + 1 + viewport] {
                        let text: String =
                            row.chars().skip(left + 1).take(right - left - 1).collect();
                        if drawn.last() != Some(&text) {
                            drawn.push(text);
                        }
                    }
                    if unseen(&app, &action).is_none() {
                        break;
                    }
                    press(&mut app, &[Key::PageDown]);
                    guard += 1;
                    assert!(guard < 40, "{name}");
                }
                assert!(guard > 0, "{name}: it took more than one frame");
                let whole = format!("{}{}", STOP_NAMES[case], action.sentence());
                assert_eq!(squash(&drawn.concat()), squash(&whole), "{name}: {drawn:?}");
                // A resize re-wraps the text: it must be drawn again in full.
                draw_once(&app, 44, 8);
                assert_eq!(unseen(&app, &action), Some(REFUSED_UNREAD), "{name}");
                type_text(&mut app, "yes");
                assert_eq!(
                    stops(&press(&mut app, &[Key::Enter])),
                    [],
                    "{name}: re-wrap"
                );
                press(&mut app, &[Key::Home]);
                read_through(&mut app, &action, 44, 8);
                type_text(&mut app, "yes");
                assert_eq!(
                    stops(&press(&mut app, &[Key::Enter])),
                    [Command::Stop(action.clone())],
                    "{name}: read at 44x8"
                );

                // Only the latest frame counts. Drawn in full, then a frame with no room
                // for any view ("terminal too small"), which draws no confirmation.
                let mut app = m05_app();
                press(&mut app, &keys);
                draw_once(&app, 120, 40);
                assert_eq!(unseen(&app, &action), None, "{name}");
                let screen = draw_once(&app, 9, 2).join("\n");
                assert!(!screen.contains("yes"), "{name}:\n{screen}");
                type_text(&mut app, "yes");
                assert_eq!(stops(&press(&mut app, &[Key::Enter])), [], "{name}: 9x2");
                assert_eq!(app.status.as_deref(), Some(REFUSED_NOT_DRAWN), "{name}");
            }
        }

        /// The M07-W0-R01 ruling for the stop menu,
        /// `stop_menu_short_terminal_refuses_to_submit`: on a terminal too small to show
        /// the confirmation of any of the four actions, the frame says so instead of
        /// drawing a cut confirmation, a typed yes sends nothing and the frame says why;
        /// the menu stays, and on a terminal large enough the same action is confirmed
        /// after it has been drawn.
        #[test]
        fn stop_menu_short_terminal_refuses_to_submit() {
            for (name, keys, action) in stop_cases() {
                for (w, h) in [
                    (40, 5),
                    (40, 4),
                    (40, 3),
                    (120, 5),
                    (20, 5),
                    (12, 6),
                    (9, 2),
                ] {
                    let at = format!("{name} at {w}x{h}");
                    let mut app = m05_app();
                    press(&mut app, &keys);
                    let screen = draw_once(&app, w, h).join("\n");
                    assert!(
                        !screen.contains("Type yes") && !screen.contains("[y/N]"),
                        "{at}: no prompt is offered:\n{screen}"
                    );
                    if w >= 40 {
                        assert!(
                            screen.contains("Too small to show this action"),
                            "{at}:\n{screen}"
                        );
                        assert!(screen.ends_with("enlarge the terminal · Esc cancel"));
                    }
                    type_text(&mut app, "yes");
                    // Drawn again with the answer typed, as the loop would.
                    draw_once(&app, w, h);
                    assert_eq!(
                        stops(&press(&mut app, &[Key::Enter])),
                        [],
                        "{at}: nothing is sent"
                    );
                    let menu = confirming(&app, &action, &at);
                    assert!(menu.input.is_empty(), "{at}");
                    // Why: under 10×3 no view is drawn at all; otherwise the frame had
                    // no room for the confirmation.
                    let why = if w < 10 || h < 3 {
                        REFUSED_NOT_DRAWN
                    } else {
                        REFUSED_TOO_SMALL
                    };
                    assert_eq!(app.status.as_deref(), Some(why), "{at}");
                    let screen = draw_once(&app, w, h).join("\n");
                    if w >= 40 {
                        assert!(screen.ends_with(REFUSED_TOO_SMALL), "{at}:\n{screen}");
                    }
                    // Larger: drawn, then confirmed.
                    let screen = flat(&draw_once(&app, 120, 40));
                    assert!(screen.contains(&action.sentence()), "{at}:\n{screen}");
                    type_text(&mut app, "yes");
                    assert_eq!(
                        stops(&press(&mut app, &[Key::Enter])),
                        [Command::Stop(action.clone())],
                        "{at}"
                    );
                }
                // Having been drawn large does not carry to a frame that is too small:
                // the latest frame is the one the owner is looking at.
                let mut app = m05_app();
                press(&mut app, &keys);
                draw_once(&app, 120, 40);
                assert_eq!(unseen(&app, &action), None, "{name}");
                draw_once(&app, 40, 5);
                type_text(&mut app, "yes");
                assert_eq!(stops(&press(&mut app, &[Key::Enter])), [], "{name}");
                assert_eq!(app.status.as_deref(), Some(REFUSED_TOO_SMALL), "{name}");
            }
        }

        /// ADR-0011 I5, spec §14.3: a label with `$(...)`, backticks, a newline, a terminal
        /// escape and bidirectional controls is drawn as one quoted line of data; it is not
        /// the title, the question or an action, no cell is a control, and a fake marker
        /// inside it stays inside its quotes.
        #[test]
        fn project_label_rendered_as_quoted_data() {
            let mut app = m05_app();
            app.catalog_mut().decisions = vec![trust_decision(
                "dec_trust1",
                CWD,
                Some(HOSTILE_LABEL),
                true,
                false,
            )];
            let app = open(&app, "dec_trust1");
            // Cloned before any frame is drawn: the end of its content has not been shown.
            let mut unread = app.clone();
            let text = snap("m05_project_label", &app);
            let (rows, buffer) = draw(&app, 120, 40);
            // Inert: the text is drawn, in quotes, on a row of its own.
            let labelled: Vec<&String> = rows
                .iter()
                .filter(|r| r.contains("$(touch /tmp/pwned)"))
                .collect();
            assert_eq!(labelled.len(), 1, "{rows:#?}");
            assert!(
                labelled[0].contains("\"$(touch /tmp/pwned) `id` ")
                    && labelled[0].contains("(control characters removed)"),
                "{}",
                labelled[0]
            );
            assert!(
                text.contains("quoted text only, it decides nothing"),
                "{text}"
            );
            // The fake marker and instruction sit inside the quotes, never at a row's start.
            for row in &rows {
                let inner = row.trim_start_matches([' ', '│']);
                assert!(!inner.starts_with("NEXT:"), "{row}");
                assert!(!inner.starts_with("[OK]"), "{row}");
            }
            // No cell is a control or a bidirectional character.
            for cell in buffer.content() {
                for c in cell.symbol().chars() {
                    assert!(!c.is_control(), "{c:?}");
                    assert!(
                        !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'),
                        "{c:?}"
                    );
                }
            }
            // It is neither the title nor the question: the modal is titled by the
            // runtime's decision ID and kind, and the question names the profile by its ID
            // (ruling I-21), never by a label.
            assert!(
                rows.iter()
                    .any(|r| r.contains("Owner decision dec_trust1 (trust_workspace)"))
            );
            assert!(
                text.contains("Use dev access automatically for this project?"),
                "{text}"
            );
            assert!(!text.contains("Use Development access"), "{text}");
            // Approving is the attended decide of that record, and only after the end of what
            // it says has been drawn.
            type_text(&mut unread, "yes");
            assert!(
                press(&mut unread, &[Key::Enter]).is_empty(),
                "unread: nothing is sent"
            );
            let mut app = app;
            read(&app);
            type_text(&mut app, "yes");
            assert_eq!(
                press(&mut app, &[Key::Enter]),
                [Effect::Worker(Command::Decide {
                    id: "dec_trust1".to_owned(),
                    verdict: Verdict::Approve
                })]
            );
        }

        /// The workspace status shows the match, the policy and its pause and cutoff state;
        /// Enter opens the decision that waits for the directory; the history lists each
        /// revision's cause and decision. A reconcile reads as one.
        #[test]
        fn workspace_status_and_policy_history_render() {
            let mut app = m05_app();
            press(&mut app, &[Key::Char('w')]);
            assert_eq!(app.screen, Screen::Workspace);
            let text = snap("m05_workspace_status", &app);
            for expected in [
                "[OK] trusted: this checkout is the one you approved",
                "pol-ws1 revision 2",
                "[OK] active: new work under this policy starts automatically",
                "A decision is waiting for this workspace: dec_trust1",
            ] {
                assert!(text.contains(expected), "{expected}: {text}");
            }
            press(&mut app, &[Key::Enter]);
            assert!(matches!(&app.modal, Some(Modal::Decision(p)) if p.id == "dec_trust1"));
            press(&mut app, &[Key::Esc, Key::Esc, Key::Char('h')]);
            assert_eq!(app.screen, Screen::Policies);
            app.status = None;
            let text = snap("m05_policy_history", &app);
            for expected in [
                "pol-per1 · revision 3",
                "personal · default",
                "[!!] paused since 2026-11-03T08:00:00Z",
                "revision 1 · approved by decision dec_trust0",
                "revision 2 · approved by decision dec_ext0",
                "revision 3 · narrowing (it only removes authority: no decision)",
                "Default profiles",
            ] {
                assert!(text.contains(expected), "{expected}: {text}");
            }
            // An ambiguous checkout asks for its own reconcile, not a trust.
            let mut app = m05_app();
            app.catalog_mut().m05.workspace.as_mut().unwrap().matched =
                crate::tui::m05::Match::Ambiguous;
            app.catalog_mut().decisions = vec![reconcile_decision("dec_rec1", WS, CWD)];
            press(&mut app, &[Key::Char('w')]);
            let text = flat(&draw(&app, 120, 40).0);
            assert!(text.contains("[!!] ambiguous"), "{text}");
            assert!(text.contains("dec_rec1"), "{text}");
            // The stop menu has nothing to act on for an ambiguous checkout.
            assert!(app.catalog().m05.stop_context().workspace.is_none());
        }
    }
}
