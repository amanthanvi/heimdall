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
    AUTHORIZATION_TEXT, ActivityRow, App, AuthPrompt, DecisionPrompt, Health, Item, Modal,
    NONE_FOUND_TEXT, PROBE_LEVELS, ProbeView, RepairPrompt, Screen, Tab, level_name,
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
    }
    render_footer(frame, app, footer, theme);
    if let Some(modal) = &app.modal {
        render_modal(frame, app, modal, body, theme);
    }
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
        Screen::Profile(_) => "Up/Down scroll · Esc back",
        Screen::Operation(_) => "r retry · k keep (held) · x cancel · Enter decision · Esc back",
    }
}

fn modal_hint(app: &App) -> &'static str {
    match &app.modal {
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
        Item::Warning { .. } => "[ !]",
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
    }
}

fn item_style(item: &Item, theme: Theme) -> Style {
    match item {
        Item::Working { .. } => theme.fg(Color::Yellow),
        Item::Warning { .. } => theme.fg(Color::Magenta),
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
    for (i, r) in rows.iter().enumerate() {
        let spans = match r {
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
            .filter(|f| f.subject.id.as_deref() == Some(alias))
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

/// A modal's parts: title, scrollable content, the fixed prompt under it, and the
/// content's scroll offset.
struct ModalParts {
    title: String,
    content: Vec<Line<'static>>,
    prompt: Vec<Line<'static>>,
    scroll: u16,
}

/// Rows `lines` take when wrapped to `width` (an estimate by characters, enough to
/// size a prompt area).
fn wrapped_rows(lines: &[Line<'static>], width: u16) -> u16 {
    let w = usize::from(width.max(1));
    let rows: usize = lines.iter().map(|l| l.width().max(1).div_ceil(w)).sum();
    u16::try_from(rows).unwrap_or(u16::MAX)
}

fn render_modal(frame: &mut Frame<'_>, app: &App, modal: &Modal, body: Rect, theme: Theme) {
    let width = body.width.saturating_sub(2).clamp(10, 110);
    let inner_width = width.saturating_sub(2);
    let parts = match modal {
        Modal::Help => ModalParts {
            title: "Keys".to_owned(),
            content: help_lines(),
            prompt: Vec::new(),
            scroll: 0,
        },
        Modal::Decision(p) => decision_modal(app, p, inner_width, theme),
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
                prompt: Vec::new(),
                scroll: 0,
            }
        }
        Modal::Authorization(p) => authorization_parts(p),
        Modal::Repair(p) => repair_parts(p),
        Modal::Probe(v) => ModalParts {
            title: format!("{} probe: {}", level_name(v.level), v.alias),
            content: probe_lines(app, v),
            prompt: Vec::new(),
            scroll: v.scroll,
        },
    };
    let prompt_rows = wrapped_rows(&parts.prompt, inner_width);
    let content_rows = wrapped_rows(&parts.content, inner_width);
    let height = if matches!(modal, Modal::Decision(_) | Modal::Probe(_)) {
        body.height
    } else {
        content_rows.saturating_add(prompt_rows).saturating_add(2)
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
    // The prompt keeps its rows (the content above it scrolls), leaving one row of
    // content at least.
    let prompt_rows = prompt_rows.min(inner.height.saturating_sub(1));
    let [content_area, prompt_area] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(prompt_rows)]).areas(inner);
    frame.render_widget(
        Paragraph::new(parts.content)
            .wrap(Wrap { trim: false })
            .scroll((parts.scroll, 0)),
        content_area,
    );
    if prompt_rows > 0 {
        frame.render_widget(
            Paragraph::new(parts.prompt).wrap(Wrap { trim: false }),
            prompt_area,
        );
    }
}

fn help_lines() -> Vec<Line<'static>> {
    [
        "1-4, Tab, Shift-Tab   switch view (Overview, Destinations, Profiles, Activity)",
        "Up/Down, PgUp/PgDn    move or scroll",
        "Enter                 open the selected item",
        "/                     search the list (in memory; never probes)",
        "c                     connect: hand the terminal to ssh <alias>",
        "p                     explicit probes, each labelled by its level",
        "r / k                 retry or keep a held setup operation",
        "x                     cancel the open operation",
        "R                     refresh, re-running the passive static pass",
        "S                     start the runtime (the TUI never starts it itself)",
        "Esc, q                back; q on a view quits; Ctrl-C quits",
        "Confirmations need a typed yes; anything else is No and sends nothing.",
    ]
    .into_iter()
    .map(plain)
    .collect()
}

fn prompt_line(verb: &str, input: &str) -> Line<'static> {
    plain(format!("{verb}? Type yes to confirm [y/N]: {input}_"))
}

/// The diff's before and after lines, file by file: each file's heading starts on the
/// same row in both columns, so the side-by-side form lines up.
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

/// The before, after and restore columns of an `ApplyProjection` record: side by side
/// when `width` allows, one under the other otherwise.
fn apply_projection_lines(d: &Decision, width: u16, theme: Theme) -> Vec<Line<'static>> {
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
    if width >= 78 {
        let w = usize::from(width / 3);
        let cell = |t: &str| {
            let t: String = t.chars().take(w.saturating_sub(1)).collect();
            format!("{t:<w$}")
        };
        lines.push(Line::styled(
            format!("{}{}{}", cell("Before"), cell("After"), cell("Restore"))
                .trim_end()
                .to_owned(),
            theme.bold(),
        ));
        let n = before.len().max(after.len()).max(restore.len());
        for i in 0..n {
            let get = |v: &Vec<String>| v.get(i).cloned().unwrap_or_default();
            lines.push(plain(
                format!(
                    "{}{}{}",
                    cell(&get(&before)),
                    cell(&get(&after)),
                    cell(&get(&restore))
                )
                .trim_end()
                .to_owned(),
            ));
        }
    } else {
        for (title, col) in [
            ("Before", &before),
            ("After", &after),
            ("Restore", &restore),
        ] {
            lines.push(Line::styled(format!("{title}:"), theme.bold()));
            lines.extend(col.iter().map(|l| plain(l.clone())));
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

fn decision_modal(app: &App, p: &DecisionPrompt, width: u16, theme: Theme) -> ModalParts {
    let verb = match p.verdict {
        Verdict::Approve => "Approve",
        Verdict::Deny => "Deny",
    };
    let Some(d) = app.catalog.decisions.iter().find(|d| d.id == p.id) else {
        return ModalParts {
            title: format!("Owner decision {}", p.id),
            content: vec![
                plain(
                    "This decision is not pending in this runtime (completed, expired and replaced, or unknown).",
                ),
                plain("There is no recorded request to show, and nothing can be sent."),
            ],
            prompt: vec![plain("Esc closes.")],
            scroll: 0,
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
        _ => {
            let text = serde_json::to_string_pretty(&d.request).unwrap_or_default();
            content.extend(text.lines().map(|l| plain(format!("  {}", clean(l)))));
        }
    }
    content.push(plain(IMITATION_TEXT));
    ModalParts {
        title: format!("Owner decision {} ({})", d.id, clean(&d.kind)),
        content,
        prompt: vec![
            Line::styled(
                format!(
                    "Tab: {} instead · Esc: send nothing",
                    match p.verdict {
                        Verdict::Approve => "deny",
                        Verdict::Deny => "approve",
                    }
                ),
                theme.dim(),
            ),
            prompt_line(verb, &p.input).style(theme.bold()),
        ],
        scroll: p.scroll,
    }
}

fn authorization_parts(p: &AuthPrompt) -> ModalParts {
    let mut content = vec![plain(format!(
        "The {} level for {} {AUTHORIZATION_TEXT}.",
        level_name(p.level),
        p.alias
    ))];
    let mut prompt = Vec::new();
    match &p.executed {
        None => content.push(plain(
            "Reading your configuration first (static pass; nothing executes)...",
        )),
        Some(found) => {
            content.push(plain("Configuration commands the static pass found:"));
            if found.is_empty() {
                content.push(plain(format!("  {NONE_FOUND_TEXT}")));
            }
            for f in found {
                content.push(plain(format!("  {}", clean(f))));
            }
            content.push(plain(
                "Without a typed yes the level is declined (config_commands_not_authorized) and nothing runs.",
            ));
            prompt.push(prompt_line("Authorize", &p.input));
        }
    }
    ModalParts {
        title: format!("Authorize {}", level_name(p.level)),
        content,
        prompt,
        scroll: 0,
    }
}

fn repair_parts(p: &RepairPrompt) -> ModalParts {
    let mut content = vec![plain(p.repair.sentence())];
    let mut prompt = Vec::new();
    match &p.plan {
        None => content.push(plain("Previewing the repair (nothing changes yet)...")),
        Some(Err(e)) => {
            content.push(plain(format!("The preview was refused: {}", clean(e))));
            prompt.push(plain("Nothing can be sent. Esc closes."));
        }
        Some(Ok(plan)) => {
            content.push(plain(format!("Plan digest {}", clean(&plan.digest))));
            content.extend(plan.lines.iter().map(|l| plain(format!("  {}", clean(l)))));
            content.push(plain(
                "It is done only when the refreshed listing shows no held operation.",
            ));
            prompt.push(prompt_line("Submit this repair", &p.input));
        }
    }
    ModalParts {
        title: format!("Repair {}: {}", p.operation, p.repair.name()),
        content,
        prompt,
        scroll: 0,
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
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/tui/snapshots")
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
        let mut narrow = app.clone();
        if let Some(Modal::Decision(p)) = &mut narrow.modal {
            p.scroll = 0;
        }
        let all: Vec<String> = (0..40u16)
            .flat_map(|s| {
                let mut a = narrow.clone();
                if let Some(Modal::Decision(p)) = &mut a.modal {
                    p.scroll = s;
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
}
