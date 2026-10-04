//! `tui --file <path>` (contract §5): Ratatui rendering of the shared `ListModel`.
//! Profile loading uses the same `profile::load_file` as the CLI.
//!
//! Round 2 (contract §9.1 K16): on Unix, crossterm is used only to write escape
//! sequences and to switch raw mode. Input is read from stdin and decoded by
//! `heimdall_proto::keys`; the terminal size comes from `tcgetwinsize(stdout)`.
//! crossterm's event source and `terminal::size()` are never called, because
//! `size()` executes `tput` from PATH when the size ioctl fails (reproduced on Linux
//! arm64 with the round-1 binary). The same change replaces round 1's watchdog thread:
//! a hangup (POLLHUP, EOF or EIO on the terminal) is seen by the event loop itself,
//! which restores the terminal and exits 129 on the main thread.

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use heimdall_proto::list_model::{Action, Key, ListModel};
use heimdall_proto::profile;
use ratatui::Terminal;
use ratatui::backend::{Backend, ClearType, CrosstermBackend, WindowSize};
use ratatui::buffer::Cell;
use ratatui::crossterm::cursor::{Hide, Show};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    Clear, ClearType as CtClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
    enable_raw_mode,
};
use ratatui::layout::{Constraint, Layout, Position, Size};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{HighlightSpacing, List, ListItem, ListState, Paragraph};

static ACTIVE: AtomicBool = AtomicBool::new(false);
static HOOK: Once = Once::new();

/// Leave the alternate screen, show the cursor, and restore the termios settings
/// saved by crossterm when raw mode was enabled. Idempotent.
fn restore() {
    if ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
        let _ = disable_raw_mode();
        let _ = io::stdout().flush();
        // Darwin sets the kernel-managed PENDIN flag when a terminal switches back to
        // canonical mode with TCSANOW; a select/poll on it (ttnread) processes and
        // clears it. Round 1 got this from its watchdog thread's poll; do it explicitly
        // so tcgetattr() after exit equals the saved settings exactly.
        #[cfg(unix)]
        {
            use rustix::event::{PollFd, PollFlags, Timespec, poll};
            let stdin = io::stdin();
            let mut fds = [PollFd::new(&stdin, PollFlags::IN)];
            let _ = poll(
                &mut fds,
                Some(&Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            );
        }
    }
}

struct Guard;

impl Guard {
    fn enter() -> io::Result<Guard> {
        HOOK.call_once(|| {
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                restore();
                prev(info);
            }));
        });
        enable_raw_mode()?;
        ACTIVE.store(true, Ordering::SeqCst);
        let g = Guard;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            Hide,
            Clear(CtClearType::All)
        )?;
        Ok(g)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        restore();
    }
}

/// Terminal size without any fallback that runs a program (K16).
#[cfg(unix)]
fn term_size() -> io::Result<Size> {
    let w = rustix::termios::tcgetwinsize(io::stdout())?;
    Ok(Size {
        width: w.ws_col,
        height: w.ws_row,
    })
}

/// Windows: crossterm reads the console screen buffer; its `tput` fallback is Unix-only.
#[cfg(windows)]
fn term_size() -> io::Result<Size> {
    let (width, height) = ratatui::crossterm::terminal::size()?;
    Ok(Size { width, height })
}

/// CrosstermBackend with the two terminal-querying methods replaced: `size` uses
/// [`term_size`] and the cursor-position query (DSR, which would read the terminal
/// through crossterm's event source) is refused. Everything else delegates.
struct NoProbeBackend(CrosstermBackend<io::Stdout>);

impl Backend for NoProbeBackend {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        self.0.draw(content)
    }
    fn append_lines(&mut self, n: u16) -> io::Result<()> {
        self.0.append_lines(n)
    }
    fn hide_cursor(&mut self) -> io::Result<()> {
        self.0.hide_cursor()
    }
    /// Errors are swallowed: `restore()` shows the cursor authoritatively, and
    /// ratatui's `Terminal` drop reports a failed show with `eprintln!`, which panics
    /// when stderr is the hung-up terminal (observed on macOS: exit 1 instead of 129).
    fn show_cursor(&mut self) -> io::Result<()> {
        let _ = self.0.show_cursor();
        Ok(())
    }
    fn get_cursor_position(&mut self) -> io::Result<Position> {
        Err(io::Error::other("terminal queries are disabled"))
    }
    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        self.0.set_cursor_position(position)
    }
    fn clear(&mut self) -> io::Result<()> {
        self.0.clear()
    }
    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        self.0.clear_region(clear_type)
    }
    fn size(&self) -> io::Result<Size> {
        term_size()
    }
    fn window_size(&mut self) -> io::Result<WindowSize> {
        Ok(WindowSize {
            columns_rows: term_size()?,
            pixels: Size {
                width: 0,
                height: 0,
            },
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        Backend::flush(&mut self.0)
    }
}

fn render(f: &mut ratatui::Frame, m: &ListModel, state: &mut ListState, color: bool) {
    let area = f.area();
    let [list_area, status_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
    let items: Vec<ListItem> = m
        .shown_items()
        .map(|d| ListItem::new(ListModel::row_text(d, area.width)))
        .collect();
    // Selection is marked by the "> " prefix; unselected rows get two spaces.
    let mut list = List::new(items)
        .highlight_symbol("> ")
        .highlight_spacing(HighlightSpacing::Always);
    if color {
        list = list.highlight_style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    }
    state.select(m.selected());
    f.render_stateful_widget(list, list_area, state);
    f.render_widget(Paragraph::new(m.status_line()), status_area);
}

/// Pending termination signal number (0 = none): SIGTERM/SIGHUP/SIGINT sent by
/// another process (terminal Ctrl-C arrives as a key byte in raw mode), plus a
/// resize flag set by SIGWINCH.
struct SignalFlags {
    term: Arc<AtomicUsize>,
    winch: Arc<AtomicBool>,
}

fn install_signal_flags() -> SignalFlags {
    let term = Arc::new(AtomicUsize::new(0));
    let winch = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        for sig in [
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
            signal_hook::consts::SIGINT,
        ] {
            let _ = signal_hook::flag::register_usize(sig, Arc::clone(&term), sig as usize);
        }
        let _ = signal_hook::flag::register(signal_hook::consts::SIGWINCH, Arc::clone(&winch));
        // Handlers are in place: let signals blocked since main() through.
        heimdall_proto::sigdisp::restore_mask();
    }
    SignalFlags { term, winch }
}

/// One step of terminal input.
enum Input {
    Keys(Vec<Key>),
    /// Windows console resize event (Unix resizes arrive through the SIGWINCH flag).
    #[cfg_attr(unix, allow(dead_code))]
    Resize,
    /// The terminal hung up (POLLHUP, EOF or EIO; Unix).
    #[cfg_attr(windows, allow(dead_code))]
    Hangup,
    Idle,
}

#[cfg(unix)]
struct Reader {
    decoder: heimdall_proto::keys::Decoder,
}

#[cfg(unix)]
impl Reader {
    fn new() -> Self {
        Reader {
            decoder: heimdall_proto::keys::Decoder::new(),
        }
    }

    /// Wait up to `timeout` for input on stdin. A pending lone ESC is decided after
    /// 30 ms without further bytes.
    fn next(&mut self, timeout: Duration) -> io::Result<Input> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        let wait = if self.decoder.has_pending() {
            Duration::from_millis(30)
        } else {
            timeout
        };
        let stdin = io::stdin();
        let ts = Timespec {
            tv_sec: wait.as_secs() as _,
            tv_nsec: wait.subsec_nanos() as _,
        };
        let mut fds = [PollFd::new(&stdin, PollFlags::IN)];
        match poll(&mut fds, Some(&ts)) {
            Ok(0) => {
                if self.decoder.has_pending() {
                    return Ok(Input::Keys(self.decoder.flush()));
                }
                return Ok(Input::Idle);
            }
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => return Ok(Input::Idle),
            Err(e) => return Err(e.into()),
        }
        let rev = fds[0].revents();
        if rev.intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL) {
            return Ok(Input::Hangup);
        }
        let mut buf = [0u8; 1024];
        match rustix::io::read(&stdin, &mut buf) {
            Ok(0) => Ok(Input::Hangup),
            Ok(n) => Ok(Input::Keys(self.decoder.push(&buf[..n]))),
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => Ok(Input::Idle),
            Err(rustix::io::Errno::IO) => Ok(Input::Hangup),
            Err(e) => Err(e.into()),
        }
    }
}

/// Windows: crossterm's console event reader (ReadConsoleInput; no helper programs).
#[cfg(windows)]
struct Reader;

#[cfg(windows)]
impl Reader {
    fn new() -> Self {
        Reader
    }
    fn next(&mut self, timeout: Duration) -> io::Result<Input> {
        use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
        if !event::poll(timeout)? {
            return Ok(Input::Idle);
        }
        Ok(match event::read()? {
            Event::Key(k) if k.kind == KeyEventKind::Press => {
                let key = match k.code {
                    KeyCode::Up => Key::Up,
                    KeyCode::Down => Key::Down,
                    KeyCode::Enter => Key::Enter,
                    KeyCode::Esc => Key::Esc,
                    KeyCode::Backspace => Key::Backspace,
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => Key::CtrlC,
                    KeyCode::Char(_)
                        if k.modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                    {
                        Key::Other
                    }
                    KeyCode::Char(c) => Key::Char(c),
                    _ => Key::Other,
                };
                Input::Keys(vec![key])
            }
            Event::Resize(_, _) => Input::Resize,
            _ => Input::Idle,
        })
    }
}

/// True for errors that mean the terminal is gone (K10: hangup seen as EIO/EOF).
fn is_hangup(e: &io::Error) -> bool {
    #[cfg(unix)]
    if let Some(code) = e.raw_os_error()
        && (code == libc::EIO || code == libc::ENXIO)
    {
        return true;
    }
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof
    )
}

pub fn main(file: &Path) -> i32 {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        #[cfg(unix)]
        heimdall_proto::sigdisp::restore_mask();
        eprintln!("heimdall-proto: USAGE_ERROR: tui requires a terminal on stdin and stdout");
        return 2;
    }
    let sig = install_signal_flags();
    let p = match profile::load_file(file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("heimdall-proto: {}: {}", e.code.as_str(), e.message);
            return e.code.exit_code();
        }
    };
    let color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let mut model = ListModel::new(p.destinations);

    let guard = match Guard::enter() {
        Ok(g) => g,
        Err(e) => {
            restore();
            eprintln!("heimdall-proto: cannot initialize terminal: {:?}", e.kind());
            return 1;
        }
    };
    let result = event_loop(&mut model, color, &sig);
    drop(guard);
    match result {
        Ok(Outcome::Selected(alias)) => {
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "SELECTED {alias}");
            let _ = out.flush();
            0
        }
        Ok(Outcome::Quit) => 0,
        Ok(Outcome::Cancelled) => 130,
        Ok(Outcome::Signal(n)) => 128 + n as i32,
        Ok(Outcome::Hangup) => 129,
        Err(e) if is_hangup(&e) => 129,
        Err(e) => {
            eprintln!("heimdall-proto: terminal error: {:?}", e.kind());
            1
        }
    }
}

enum Outcome {
    Selected(String),
    Quit,
    Cancelled,
    Signal(usize),
    Hangup,
}

fn event_loop(model: &mut ListModel, color: bool, sig: &SignalFlags) -> io::Result<Outcome> {
    // Terminal::clear() would query the cursor position (DSR); the alternate screen is
    // cleared in Guard::enter instead, and NoProbeBackend refuses the query.
    let mut terminal = Terminal::new(NoProbeBackend(CrosstermBackend::new(io::stdout())))?;
    let mut state = ListState::default();
    let mut reader = Reader::new();
    let mut dirty = true;
    loop {
        if sig.winch.swap(false, Ordering::SeqCst) {
            dirty = true;
        }
        if dirty {
            terminal.draw(|f| render(f, model, &mut state, color))?;
            dirty = false;
        }
        match sig.term.load(Ordering::SeqCst) {
            0 => {}
            #[cfg(unix)]
            n if n == signal_hook::consts::SIGINT as usize => return Ok(Outcome::Cancelled),
            n => return Ok(Outcome::Signal(n)),
        }
        match reader.next(Duration::from_millis(50))? {
            Input::Idle => {}
            Input::Resize => dirty = true,
            Input::Hangup => return Ok(Outcome::Hangup),
            Input::Keys(keys) => {
                for key in keys {
                    #[cfg(feature = "test-panic")]
                    if key == Key::Char('!') && !model.is_filtering() {
                        panic!("g02 test-panic hook");
                    }
                    match model.handle(key) {
                        Action::None => dirty = true,
                        Action::Select(a) => return Ok(Outcome::Selected(a)),
                        Action::Quit => return Ok(Outcome::Quit),
                        Action::Cancel => return Ok(Outcome::Cancelled),
                    }
                }
            }
        }
    }
}
