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
//! screen.

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
use super::model::{
    AUTHORIZATION_TEXT, ActivityRow, App, AuthPrompt, DecisionPrompt, Health, Item, MAX_TYPED,
    Modal, NONE_FOUND_TEXT, PROBE_LEVELS, ProbeView, Reading, RepairPrompt, Screen, Tab,
    level_name,
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

/// How long ago (or from now) `ts` is, coarsely.
fn age(now: Timestamp, ts: Timestamp) -> String {
    let d = now.as_second() - ts.as_second();
    let a = d.unsigned_abs();
    let n = if a < 60 {
        format!("{a}s")
    } else if a < 3600 {
        format!("{}m", a / 60)
    } else if a < 86_400 {
        format!("{}h", a / 3600)
    } else {
        format!("{}d", a / 86_400)
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
    let area = frame.area();
    if area.width < 10 || area.height < 3 {
        frame.render_widget(Paragraph::new("terminal too small"), area);
        return;
    }
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);
    render_header(frame, app, header, theme);
    match &app.screen {
        Screen::Tab(Tab::Overview) => render_overview(frame, app, body, theme),
        Screen::Tab(Tab::Destinations) => render_destinations(frame, app, body, theme),
        Screen::Tab(Tab::Profiles) => render_profiles(frame, app, body, theme),
        Screen::Tab(Tab::Activity) => render_activity(frame, app, body, theme),
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
            super::m03::enrollment_lines(&app.catalog, id),
            app.scroll,
        ),
    }
    if let Some(modal) = &app.modal {
        render_modal(frame, app, modal, body, theme);
    }
    // After the modal: its footer hint reads what the modal's frame has just recorded.
    render_footer(frame, app, footer, theme);
}

fn render_header(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let wide = area.width >= 70;
    let health = app.health();
    let mut spans = Vec::new();
    if wide {
        spans.push(Span::styled("Heimdall ", theme.bold()));
    }
    for (i, tab) in Tab::ALL.iter().enumerate() {
        let name = if wide {
            tab.title().to_owned()
        } else {
            tab.title().chars().take(4).collect()
        };
        let label = format!("{} {name}", i + 1);
        if app.tab == *tab {
            spans.push(Span::styled(format!("[{label}]"), theme.selected()));
        } else {
            spans.push(Span::raw(format!(" {label} ")));
        }
    }
    spans.push(Span::raw(" "));
    spans.push(Span::styled(health.marker(), theme.health(health)));
    if wide {
        spans.push(Span::styled(
            format!(" {}", health.words()),
            theme.health(health),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_footer(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let text = match (&app.status, &app.modal) {
        (_, Some(_)) => modal_hint(app).to_owned(),
        (Some(s), None) => clean(s),
        (None, None) => screen_hint(app).to_owned(),
    };
    frame.render_widget(Paragraph::new(Span::styled(text, theme.dim())), area);
}

fn screen_hint(app: &App) -> &'static str {
    match &app.screen {
        Screen::Tab(Tab::Overview) => {
            "Enter open · r retry · k keep · R refresh · 1-4 views · ? help · q quit"
        }
        Screen::Tab(Tab::Destinations) => {
            "/ search · Enter detail · c connect · p probes · ? help · q quit"
        }
        Screen::Tab(Tab::Profiles) => "/ search · Enter detail · ? help · q quit",
        Screen::Tab(Tab::Activity) => "Enter review · ? help · q quit",
        Screen::Destination(_) => "c connect · p probes · Up/Down scroll · Esc back",
        Screen::Profile(_) | Screen::Enrollment(_) => "Up/Down scroll · Esc back",
        Screen::Operation(_) => "r retry · k keep (held) · x cancel · Enter decision · Esc back",
    }
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
        Some(Modal::Help) | None => "any key closes",
    }
}

/// Draw `lines` into `area`, keeping the `selected` line visible.
fn render_list(frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>, selected: usize) {
    let height = usize::from(area.height.max(1));
    let offset = selected.saturating_sub(height - 1);
    let offset = u16::try_from(offset).unwrap_or(u16::MAX);
    frame.render_widget(Paragraph::new(lines).scroll((offset, 0)), area);
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
    match &app.runtime {
        Runtime::Connecting => "Runtime: connecting".to_owned(),
        Runtime::Connected => format!(
            "Runtime: connected; listings read {}",
            when(app.now, app.catalog.read_at)
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
        Item::Warning { .. } | Item::LateWrite { .. } | Item::ProjectionPending { .. } => "[ !]",
        Item::SlotFree { .. } => "[ i]",
        _ => "[!!]",
    }
}

fn item_text(item: &Item) -> String {
    match item {
        Item::Held { op, kind } => format!(
            "held: {kind} {op} is held for you (a file it manages changed; nothing was moved). r retry · k keep"
        ),
        Item::Decision { id, kind } => format!("decision waiting: {kind} {id} (Enter to review)"),
        Item::Unresolved { op, kind } => format!("unresolved: {kind} {op} (outcome unknown)"),
        Item::Problem {
            code,
            alias,
            message,
        }
        | Item::Warning {
            code,
            alias,
            message,
        } => match alias {
            Some(a) => format!("{code} ({a}): {message}"),
            None => format!("{code}: {message}"),
        },
        Item::Working { op, kind, state } => format!("working: {kind} {op} {state}"),
        Item::Chore { line } => line.clone(),
        Item::Enrollment { id, state } => {
            format!("enrollment {id} is {state} (Enter for its reason and next step)")
        }
        Item::LateWrite { id } => format!(
            "{}: enrollment {id} (Enter for the residual and its command)",
            heimdall_contract::envelope::m03_warning::POSSIBLE_LATE_WRITE
        ),
        Item::ProjectionPending { alias } => format!(
            "{} ({alias}): run `{}` (the managed projection is not applied yet)",
            super::m03::PROJECTION_PENDING,
            super::m03::SETUP_APPLY_COMMAND
        ),
        Item::SlotFree { alias } => super::m03::slot_free_line(alias),
    }
}

fn item_style(item: &Item, theme: Theme) -> Style {
    match item {
        Item::Working { .. } => theme.fg(Color::Yellow),
        Item::Warning { .. } | Item::LateWrite { .. } | Item::ProjectionPending { .. } => {
            theme.fg(Color::Magenta)
        }
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
        match &app.runtime {
            Runtime::Connected => format!(
                "Runtime: connected, read {}",
                app.catalog
                    .read_at
                    .map_or_else(|| "?".to_owned(), |t| age(app.now, t))
            ),
            Runtime::Connecting => "Runtime: connecting".to_owned(),
            Runtime::NotRunning => "Runtime: not running (S starts it)".to_owned(),
            Runtime::Failed(_) => "Runtime: unavailable (S retries)".to_owned(),
        }
    } else {
        runtime_line(app)
    }));
    lines.push(plain(match (&app.doctor, narrow) {
        (Some(d), true) => format!("Static pass: {}", age(app.now, d.taken_at)),
        (Some(d), false) => format!(
            "Static pass: {}; {} destinations, {} profiles, {} identities",
            when(app.now, Some(d.taken_at)),
            app.catalog.destinations.len(),
            app.catalog.profiles.len(),
            app.catalog.identities.len()
        ),
        (None, true) => "Static pass: running".to_owned(),
        (None, false) => {
            "Static pass: running (reads your configuration; executes nothing)".to_owned()
        }
    }));
    let header = lines.len();
    let selected = app.selection(Tab::Overview);
    if items.is_empty() {
        lines.push(plain("  Nothing needs you; nothing is running."));
    }
    for (i, item) in items.iter().enumerate() {
        lines.push(row(
            selected == Some(i),
            theme,
            vec![
                Span::styled(item_marker(item), item_style(item, theme)),
                Span::raw(" "),
                Span::raw(item_text(item)),
            ],
        ));
    }
    if !narrow && let Some(Item::Held { .. }) = selected.and_then(|i| items.get(i)) {
        lines.push(plain(""));
        lines.push(plain(format!(
            "  r {}",
            super::model::HeldRepair::Retry.sentence()
        )));
        lines.push(plain(format!(
            "  k {}",
            super::model::HeldRepair::Keep.sentence()
        )));
    }
    render_list(frame, area, lines, header + selected.unwrap_or(0));
}

// ---- lists ---------------------------------------------------------------------------

fn search_line(app: &App, tab: Tab, shown: usize, total: usize) -> Line<'static> {
    match app.search(tab) {
        Some(s) if s.editing => plain(format!("Search: {}_  ({shown} of {total})", s.text)),
        Some(s) if !s.text.is_empty() => plain(format!(
            "Filter: {}  ({shown} of {total}; / edits, Esc in search clears)",
            s.text
        )),
        _ => plain(format!("{total} total · / to search (never probes)")),
    }
}

fn alias_findings(app: &App, alias: &str) -> (usize, usize) {
    app.doctor.as_ref().map_or((0, 0), |d| {
        d.report
            .findings
            .iter()
            .filter(|f| f.subject.id.as_deref() == Some(alias))
            .fold((0, 0), |(p, w), f| match f.severity {
                heimdall_contract::doctor::FindingSeverity::Problem => (p + 1, w),
                heimdall_contract::doctor::FindingSeverity::Warning => (p, w + 1),
                _ => (p, w),
            })
    })
}

fn render_destinations(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let shown = app.visible_destinations();
    let mut lines = vec![search_line(
        app,
        Tab::Destinations,
        shown.len(),
        app.catalog.destinations.len(),
    )];
    if app.catalog.destinations.is_empty() {
        lines.push(plain(match app.runtime {
            Runtime::Connected => "  No catalog destinations.",
            _ => "  The catalog is read from the runtime (S starts it).",
        }));
    }
    let selected = app.selection(Tab::Destinations);
    for (i, d) in shown.iter().enumerate() {
        let (problems, warnings) = alias_findings(app, &d.alias);
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
        lines.push(row(
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
        ));
    }
    render_list(frame, area, lines, selected.map_or(0, |s| s + 1));
}

fn render_profiles(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let shown = app.visible_profiles();
    let mut lines = vec![search_line(
        app,
        Tab::Profiles,
        shown.len(),
        app.catalog.profiles.len(),
    )];
    if app.catalog.profiles.is_empty() {
        lines.push(plain("  No profiles."));
    }
    let selected = app.selection(Tab::Profiles);
    for (i, p) in shown.iter().enumerate() {
        lines.push(row(
            selected == Some(i),
            theme,
            vec![Span::raw(format!(
                "{:<12} {}  {} pair(s)  rev {}",
                p.id,
                p.label.as_deref().unwrap_or(""),
                p.pairs.len(),
                p.revision.as_deref().unwrap_or("?")
            ))],
        ));
    }
    render_list(frame, area, lines, selected.map_or(0, |s| s + 1));
}

fn render_activity(frame: &mut Frame<'_>, app: &App, area: Rect, theme: Theme) {
    let rows = app.activity_rows();
    let selected = app.selection(Tab::Activity);
    let mut lines = vec![Line::styled("Pending decisions", theme.bold())];
    let mut sel_line = 0;
    if app.catalog.decisions.is_empty() {
        lines.push(plain("  none"));
    }
    let mut ops_header = false;
    let mut enr_header = false;
    for (i, r) in rows.iter().enumerate() {
        let spans = match r {
            ActivityRow::Enrollment(id) => {
                if !ops_header {
                    ops_header = true;
                    lines.push(Line::styled("Operations", theme.bold()));
                    lines.push(plain("  none open"));
                }
                if !enr_header {
                    enr_header = true;
                    lines.push(Line::styled("Enrollments", theme.bold()));
                }
                let e = app.catalog.m03.enrollments.iter().find(|e| &e.id == id);
                let (marker, _) = e.map_or(("[??]", ""), |e| super::m03::state_class(&e.state));
                vec![
                    Span::styled(marker, theme.fg(Color::Red)),
                    Span::raw(e.map_or_else(
                        || format!(" {id}"),
                        |e| super::m03::enrollment_row(&app.catalog, e),
                    )),
                ]
            }
            ActivityRow::Decision(id) => {
                let d = app.catalog.decisions.iter().find(|d| &d.id == id);
                let expiry = d.and_then(|d| d.expires_at).map_or_else(String::new, |t| {
                    format!("  expires {} ({})", hms(t), age(app.now, t))
                });
                let expired =
                    d.is_some_and(|d| d.expired || d.expires_at.is_some_and(|t| t <= app.now));
                vec![
                    Span::styled(if expired { "[--]" } else { "[!!]" }, theme.fg(Color::Red)),
                    Span::raw(format!(
                        " {id}  {}{expiry}{}",
                        d.map_or("?", |d| d.kind.as_str()),
                        if expired { " (expired)" } else { "" }
                    )),
                ]
            }
            ActivityRow::Operation(id) => {
                if !ops_header {
                    ops_header = true;
                    lines.push(Line::styled("Operations", theme.bold()));
                }
                let o = app.catalog.operations.iter().find(|o| &o.id == id);
                let (marker, color) = match o {
                    Some(o) if o.is_held() || o.is_unresolved() => ("[!!]", Color::Red),
                    Some(o) if o.is_active() => ("[..]", Color::Yellow),
                    _ => ("[--]", Color::Gray),
                };
                vec![
                    Span::styled(marker, theme.fg(color)),
                    Span::raw(format!(
                        " {id}  {}  {}{}",
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
        };
        if selected == Some(i) {
            sel_line = lines.len();
        }
        lines.push(row(selected == Some(i), theme, spans));
    }
    if !ops_header {
        lines.push(Line::styled("Operations", theme.bold()));
        lines.push(plain("  none open"));
    }
    render_list(frame, area, lines, sel_line);
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
    let dest = app.catalog.destination(alias);
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
            when(app.now, app.catalog.read_at)
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
        lines.extend(super::m03::managed_lines(
            &app.catalog,
            d,
            observation
                .and_then(|o| o.identity_selection.as_ref())
                .map(|s| s.selection),
        ));
    }
    let doctor = app.doctor.as_ref();
    match (doctor, observation) {
        (Some(doc), Some(obs)) => {
            lines.push(Line::styled(
                format!(
                    "Effective values (static pass at {}, {}; nothing executed):",
                    hms(doc.taken_at),
                    age(app.now, doc.taken_at)
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
            when(app.now, Some(doc.taken_at))
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
                when(app.now, Some(p.observed_at)),
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
            app.catalog
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
    let dest = app.catalog.destination(alias);
    let by_id = dest
        .and_then(|d| d.identity_id.as_deref())
        .and_then(|id| app.catalog.identity(id));
    let by_entry = || {
        app.doctor_alias(alias)?
            .identity_selection
            .as_ref()?
            .entries
            .iter()
            .find_map(|e| {
                e.fingerprint
                    .as_deref()
                    .and_then(|f| app.catalog.identity_by_fingerprint(f))
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
        when(app.now, identity.checked_at)
    )));
}

fn profile_lines(app: &App, id: &str) -> Vec<Line<'static>> {
    let Some(p) = app.catalog.profiles.iter().find(|p| p.id == id) else {
        return vec![plain(format!("{id}: not in the latest listing"))];
    };
    let mut lines = vec![plain(format!(
        "{}: {} (rev {}; listing read {})",
        p.id,
        p.label.as_deref().unwrap_or("no label"),
        p.revision.as_deref().unwrap_or("?"),
        when(app.now, app.catalog.read_at)
    ))];
    lines.push(plain("Pairs:"));
    for pair in &p.pairs {
        let alias = app
            .catalog
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
    let listed = app.catalog.operations.iter().find(|o| o.id == id);
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
                when(app.now, o.created_at),
                when(app.now, o.updated_at)
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
                .catalog
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

fn help_lines() -> Vec<Line<'static>> {
    [
        "1-4, Tab, Shift-Tab   switch view (Overview, Destinations, Profiles, Activity)",
        "Up/Down, PgUp/PgDn    move or scroll; Home/End go to the first and last row",
        "Enter                 open the selected item",
        "/                     search the list (in memory; never probes)",
        "c                     connect: hand the terminal to ssh <alias>",
        "p                     explicit probes, each labelled by its level",
        "r / k                 retry or keep a held setup operation",
        "x                     cancel the open operation",
        "R                     refresh, re-running the passive static pass",
        "S                     start the runtime (the TUI never starts it itself)",
        "Esc, q                back; q on a view quits; Ctrl-C quits",
        "Confirmations need a typed yes once their last row has been on screen;",
        "anything else is No and sends nothing.",
    ]
    .into_iter()
    .map(plain)
    .collect()
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
    let verb = match p.verdict {
        Verdict::Approve => "Approve",
        Verdict::Deny => "Deny",
    };
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
        _ => {
            let text = serde_json::to_string_pretty(&d.request).unwrap_or_default();
            content.extend(text.lines().map(|l| plain(format!("  {}", clean(l)))));
        }
    }
    content.push(plain(IMITATION_TEXT));
    // What the owner confirms is the record itself, not its age.
    let key = fingerprint(&[&d.id, &d.kind, &d.request.to_string()]);
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
            when(app.now, Some(r.started_at)),
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
        fresh.runtime = Runtime::NotRunning;
        out.push(("first_frame", fresh));
        out
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
            assert!(text.contains("[!!] held: setup.apply op_held1"), "{text}");
            assert!(text.contains("[..] working: ensure op_run1"), "{text}");
            assert!(
                text.contains("[ !] identity_selection_not_exclusive"),
                "{text}"
            );
            assert!(text.contains("> [!!]"), "the selection is marked in text");
            assert!(text.contains("[1 Overview]"), "the tab is marked in text");
        }
        let mut ready = populated();
        ready.catalog.operations.clear();
        ready.catalog.decisions.clear();
        let (rows, _) = draw(&no_color(&ready), 120, 40);
        assert!(rows.join("\n").contains("[OK] Ready"));
        let mut working = populated();
        working.catalog.operations.retain(|o| !o.is_held());
        working.catalog.decisions.clear();
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
        app.catalog = crate::tui::data::Catalog::from_answers(
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
            .catalog
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
                .catalog
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
            request: serde_json::Value::Object(
                (0..4 + extra)
                    .map(|i| (format!("field{i:02}"), serde_json::json!(i)))
                    .collect(),
            ),
        };
        app.catalog.decisions.push(other(0));
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
        app.catalog.decisions.retain(|d| d.id != "dec_other");
        app.catalog.decisions.push(other(12));
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
        assert_eq!(age(n, t("2026-11-03T09:00:25Z")), "5s ago");
        assert_eq!(age(n, t("2026-11-03T08:58:30Z")), "2m ago");
        assert_eq!(age(n, t("2026-11-03T09:15:00Z")), "in 14m");
        assert_eq!(age(n, t("2026-11-01T09:00:30Z")), "2d ago");
        assert_eq!(hms(t("2026-11-03T09:00:25.123Z")), "09:00:25Z");
    }

    // ---- ⟨M03⟩ U12: the M03 views (m03-plan U12 "Tests", TUI) ------------------------

    mod m03 {
        use super::*;
        use crate::tui::m03::fixtures::{enroll_decision, enrollment, target_change_decision};
        use crate::tui::m03::{Listings, LockReport, PolicyReport, Preference, Projection};
        use crate::tui::model::{Command, DecisionPrompt, Effect};
        use heimdall_contract::enrollment::DisclosureKind;
        use heimdall_contract::managed::{ExistingConnectionsMode, MultiplexingMode};
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
            app.catalog.destinations[0].preference = Some(pending());
            app.catalog.m03 = Listings::of(
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
                }],
            );
            app.catalog.decisions = vec![
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
            if let Some(d) = &mut app.doctor {
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
            let rows = a.activity_rows();
            let held = rows
                .iter()
                .position(|r| matches!(r, ActivityRow::Enrollment(_)))
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
        /// D8 item 6, §17.20 item 9): the managed detail shows the D8 wording, graceful
        /// and strict, each in its exclusive and not-exclusive form, exactly U8's
        /// strings (compared with the constants, never retyped); an unknown selection
        /// gets the qualified text; the runtime's own wording (with D8 item 3's
        /// owned-masters line) is shown verbatim; owned masters without it are never
        /// presented as the plain text alone; no policy reads unknown.
        #[test]
        fn managed_readiness_detail_exact_deadline_strings() {
            let policy = |existing, multiplexing, wording: Option<String>| PolicyReport {
                existing: Some(existing),
                multiplexing: Some(multiplexing),
                wording,
            };
            let with = |selection: Option<IdentitySelection>, p: Option<PolicyReport>| {
                let mut app = m03_app();
                app.catalog.destinations[0].preference = Some(Preference {
                    policy: p,
                    ..pending()
                });
                if let Some(d) = &mut app.doctor {
                    match selection {
                        Some(sel) => {
                            d.report.aliases[0]
                                .identity_selection
                                .as_mut()
                                .unwrap()
                                .selection = sel;
                        }
                        None => d.report.aliases.clear(),
                    }
                }
                let app = detail(&app);
                let lines: Vec<String> = crate::tui::m03::managed_lines(
                    &app.catalog,
                    &app.catalog.destinations[0],
                    app.doctor_alias("alpha")
                        .and_then(|o| o.identity_selection.as_ref())
                        .map(|s| s.selection),
                )
                .iter()
                .map(|l| l.to_string())
                .collect();
                let screen = flat(&draw(&app, 120, 60).0);
                (lines, screen)
            };
            let cases = [
                (
                    IdentitySelection::Exclusive,
                    ExistingConnectionsMode::Graceful,
                    DEADLINE_GRACEFUL_EXCLUSIVE,
                ),
                (
                    IdentitySelection::NotExclusive,
                    ExistingConnectionsMode::Graceful,
                    DEADLINE_GRACEFUL_NOT_EXCLUSIVE,
                ),
                (
                    IdentitySelection::Exclusive,
                    ExistingConnectionsMode::Strict,
                    DEADLINE_STRICT_EXCLUSIVE,
                ),
                (
                    IdentitySelection::NotExclusive,
                    ExistingConnectionsMode::Strict,
                    DEADLINE_STRICT_NOT_EXCLUSIVE,
                ),
            ];
            let all = [
                DEADLINE_GRACEFUL_EXCLUSIVE,
                DEADLINE_GRACEFUL_NOT_EXCLUSIVE,
                DEADLINE_STRICT_EXCLUSIVE,
                DEADLINE_STRICT_NOT_EXCLUSIVE,
            ];
            for (selection, existing, expected) in cases {
                let (lines, screen) = with(
                    Some(selection),
                    Some(policy(existing, MultiplexingMode::Disabled, None)),
                );
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
            // No identity selection evaluated: `undetermined`, the qualified text.
            let (lines, _) = with(
                None,
                Some(policy(
                    ExistingConnectionsMode::Graceful,
                    MultiplexingMode::Disabled,
                    None,
                )),
            );
            assert!(
                lines
                    .iter()
                    .any(|l| l.trim() == DEADLINE_GRACEFUL_NOT_EXCLUSIVE),
                "{lines:#?}"
            );
            // The runtime's wording, owned-masters line included, verbatim.
            let theirs = format!(
                "{DEADLINE_STRICT_EXCLUSIVE} {}",
                heimdall_adapters::managed::report::OWNED_MASTERS_DISCLOSURE
            );
            let (lines, screen) = with(
                Some(IdentitySelection::Exclusive),
                Some(policy(
                    ExistingConnectionsMode::Strict,
                    MultiplexingMode::OwnedMasters,
                    Some(theirs.clone()),
                )),
            );
            assert!(lines.iter().any(|l| l.trim() == theirs), "{lines:#?}");
            assert!(screen.contains(&theirs), "{screen}");
            // Owned masters without the runtime's wording: the base text and an explicit
            // unknown, never the base text alone (switch OWNED_MASTERS_LINE).
            if !cfg!(windows) {
                let (lines, _) = with(
                    Some(IdentitySelection::Exclusive),
                    Some(policy(
                        ExistingConnectionsMode::Graceful,
                        MultiplexingMode::OwnedMasters,
                        None,
                    )),
                );
                let at = lines
                    .iter()
                    .position(|l| l.trim() == DEADLINE_GRACEFUL_EXCLUSIVE)
                    .unwrap();
                assert!(
                    lines[at + 1].contains("[??] owned masters are applied"),
                    "{lines:#?}"
                );
            }
            // No policy reported: unknown, and none of the four texts.
            let (lines, screen) = with(Some(IdentitySelection::Exclusive), None);
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("unknown: no connection policy is reported")),
                "{lines:#?}"
            );
            for w in all {
                assert!(!screen.contains(w), "{w}: {screen}");
            }
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
            let hint = "managed_projection_pending (alpha): run `heimdall setup apply` (the managed projection is not applied yet)";
            let mut app = App::new(now(), false);
            app.runtime = Runtime::Connected;
            app.catalog = c;
            app.doctor = Some(crate::tui::data::Doctor {
                report: crate::tui::model::tests::report(),
                taken_at: now(),
            });
            if let Some(d) = &mut app.doctor {
                d.report.findings.clear();
            }
            let overview = flat(&draw(&app, 120, 40).0);
            assert!(overview.contains(&format!("[ !] {hint}")), "{overview}");
            assert_eq!(
                overview.matches("managed_projection_pending").count(),
                1,
                "only the pending pair: {overview}"
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
            app.catalog.destinations[0].preference = Some(Preference {
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
            if let Some(d) = &mut app.doctor {
                d.report.findings = vec![slot_free_disclosure("alpha", &dst)];
            }
            app.catalog.operations.clear();
            app.catalog.decisions.clear();
            let command = slot_free_command("alpha");
            assert_eq!(command, "heimdall run --profile <profile> -- ssh alpha");
            // An overview row is one terminal row: the command comes first, whole.
            let overview = flat(&draw(&app, 120, 40).0);
            assert!(
                overview.contains(&format!(
                    "[ i] slot_free (alpha): hold the slot with `{command}`"
                )),
                "{overview}"
            );
            let items = app.overview_items();
            assert_eq!(
                item_text(&items[0]),
                format!(
                    "slot_free (alpha): hold the slot with `{command}` (ordinary `ssh alpha` needs a held slot)"
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

        /// m03-plan U12 `lock_disclosure_once` (ADR-0008 D9 item 1, R-UX-03): the lock
        /// disclosure is shown in the decision whose record carries it, and not in one
        /// that does not (the runtime records it only until acknowledged); with no text
        /// the TUI can show, Approve is not offered and nothing is sent, Deny still is;
        /// with the runtime's text it is shown verbatim and Approve proceeds; the
        /// managed detail always shows the current lock behaviour.
        #[test]
        fn lock_disclosure_once() {
            let mut app = m03_app();
            app.catalog.decisions = vec![
                enroll_decision("dec_first", vec![DisclosureKind::LockContinuityOnce]),
                enroll_decision("dec_second", vec![]),
            ];
            app.catalog.m03.time_uncertain = None;
            let heading = "Lock disclosure (shown once; recorded when you approve):";
            // The first: shown, without a text here: no approval can be sent.
            let first = open(&app, "dec_first");
            let text = flat(&read_everything(&first, 120, 40));
            assert!(text.contains(heading), "{text}");
            assert!(text.contains("[text not available in the TUI]"), "{text}");
            assert!(text.contains("Approve is not offered here"), "{text}");
            let mut a = first.clone();
            type_text(&mut a, "yes");
            let effects = press(&mut a, &[Key::Enter]);
            assert!(decides(&effects).is_empty(), "{effects:?}");
            assert!(
                a.status.as_deref().unwrap().contains("approve not sent"),
                "{:?}",
                a.status
            );
            let mut a = first.clone();
            press(&mut a, &[Key::Tab]);
            draw(&a, 120, 40);
            type_text(&mut a, "yes");
            let effects = press(&mut a, &[Key::Enter]);
            assert_eq!(decides(&effects), [("dec_first".to_owned(), Verdict::Deny)]);
            // The second: no lock disclosure.
            let text = flat(&read_everything(&open(&app, "dec_second"), 120, 40));
            assert!(!text.contains("Lock disclosure"), "{text}");
            assert!(text.contains("Disclosures: none"), "{text}");
            // The runtime's text (Q-T5's `lock` report): verbatim, and Approve proceeds.
            let said = "Approved work is designed to keep working while your screen or password manager is locked, until the end time you approve.";
            app.catalog.m03.lock = Some(LockReport {
                behavior: "continue".to_owned(),
                disclosure: Some(said.to_owned()),
            });
            let mut a = open(&app, "dec_first");
            let text = flat(&read_everything(&a, 120, 40));
            assert!(text.contains(&format!("{heading} {said}")), "{text}");
            assert!(!text.contains("Approve is not offered"), "{text}");
            draw(&a, 120, 40);
            type_text(&mut a, "yes");
            let effects = press(&mut a, &[Key::Enter]);
            assert_eq!(
                decides(&effects),
                [("dec_first".to_owned(), Verdict::Approve)]
            );
            // The detail always shows the current behaviour.
            let screen = flat(&draw(&detail(&app), 120, 60).0);
            assert!(screen.contains("Lock behaviour: continue"), "{screen}");
            app.catalog.m03.lock = None;
            let screen = flat(&draw(&detail(&app), 120, 60).0);
            assert!(
                screen.contains("Lock behaviour: unknown (not reported by the runtime)"),
                "{screen}"
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
            for want in [
                "Plan: enroll fixture at alpha (dst-alpha), account form, under CA SHA256:",
                "Registry ~/.ssh/authorized_keys (resolved by remote_home)",
                &format!("line SHA-256 {}", "ab".repeat(32)),
                "Existing access: ssh alpha",
                "* ca_trust_blast_radius:",
                "Lock disclosure (shown once",
            ] {
                assert!(text.contains(want), "{want}: {text}");
            }
            // An enrollment decision's operation is linked from its record.
            assert_eq!(
                app.catalog.decisions[0].operation().as_deref(),
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
                .catalog
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
                    "`heimdall enroll verify {} --approve-target-change`",
                    ids[0]
                )),
                "{text}"
            );
            a.screen = Screen::Enrollment(ids[1].clone());
            let text = flat(&draw(&a, 120, 40).0);
            assert!(
                text.contains("Possible late write (the late_write residual)"),
                "{text}"
            );
            assert!(
                text.contains(&format!("`heimdall enroll remove {}`", ids[1])),
                "{text}"
            );
            let mut b = app.clone();
            b.catalog.m03.enrollments[0].hold = None;
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
                    "[ !] possible_late_write: enrollment {} (Enter for the residual and its command)",
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
            app.runtime = Runtime::NotRunning;
            app.catalog.m03.time_uncertain = None;
            app.apply(crate::tui::model::Update::OfflineChores(vec![line.clone()]));
            assert_eq!(item_text(&app.overview_items()[0]), line);
            let text = flat(&draw(&app, 120, 40).0);
            assert!(
                text.contains("> [!!] time_confirmation_after_reboot: run `heimdall time confirm` (this machine"),
                "{text}"
            );
            app.runtime = Runtime::Connected;
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
}
