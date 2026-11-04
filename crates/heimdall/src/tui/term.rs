//! The terminal (m02-plan U10; spec §12.2; prototypes/rust/REPORT.md §5, §9 K16).
//!
//! * **Enter and leave.** [`enter`] saves the terminal mode once, switches to raw mode
//!   and the alternate screen and hides the cursor; [`leave`] shows the cursor, leaves
//!   the alternate screen and restores the saved mode exactly. [`leave`] is idempotent
//!   and is called on every way out: a normal quit, the connect handoff, a hang-up, a
//!   termination signal, and a panic of the TUI's thread (the panic hook restores the
//!   terminal **before** the panic message is printed).
//! * **No terminal queries.** [`TermBackend`] refuses the cursor-position request
//!   (`ESC[6n`) that ratatui's `Terminal::clear` would send and a terminal may never
//!   answer, and sizes the screen with `tcgetwinsize` on Unix, never with crossterm's
//!   `terminal::size`, which runs `tput` from `PATH` when the ioctl fails (K16). A full
//!   repaint uses `Terminal::resize`, which clears without asking anything.
//! * **Hang-up watchdog.** On Unix the TUI reads its own input ([`Reader`]): `poll` and
//!   `read` on stdin, never crossterm's event source, which spins at full CPU on a
//!   hung-up terminal. `POLLHUP`, end of file and `EIO` are a hang-up: the main loop
//!   restores what it can and exits 129 at once.
//! * Windows uses crossterm's console input (`ReadConsoleInput`) and raw mode, and the
//!   console size; there is no `tput` fallback there.

use std::io::{self, Write as _};
#[cfg(unix)]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Once, OnceLock};
use std::time::Duration;

use ratatui::backend::{Backend, ClearType, CrosstermBackend, WindowSize};
use ratatui::buffer::Cell;
use ratatui::crossterm::cursor::{Hide, MoveTo, Show};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    Clear, ClearType as CtClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Position, Size};

use super::keys::Key;

/// Whether the terminal is in TUI mode (raw, alternate screen).
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// The mode saved by the first [`enter`]; every [`leave`] restores exactly this.
#[cfg(unix)]
static SAVED: Mutex<Option<rustix::termios::Termios>> = Mutex::new(None);
/// The thread that owns the terminal (the panic hook restores only for it).
static OWNER: OnceLock<std::thread::ThreadId> = OnceLock::new();
/// Set when another thread panicked while the terminal was in TUI mode.
pub(crate) static OTHER_THREAD_PANICKED: AtomicBool = AtomicBool::new(false);
static HOOK: Once = Once::new();

/// Install the panic hook (once per process). A panic of the terminal's owner thread
/// restores the terminal, then prints the message as usual; a panic of another thread
/// while the terminal is in TUI mode is recorded instead of being printed into the
/// alternate screen, and the main loop reports it after leaving.
pub(crate) fn install_panic_hook() {
    let _ = OWNER.set(std::thread::current().id());
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let owner = OWNER.get().copied() == Some(std::thread::current().id());
            if owner || !ACTIVE.load(Ordering::SeqCst) {
                leave();
                previous(info);
            } else {
                OTHER_THREAD_PANICKED.store(true, Ordering::SeqCst);
            }
        }));
    });
}

#[cfg(unix)]
fn poisoned<T>(e: std::sync::PoisonError<T>) -> T {
    e.into_inner()
}

/// Switch to raw mode and the alternate screen, cursor hidden, screen cleared.
///
/// # Errors
/// The terminal mode cannot be read or set, or the screen cannot be written.
pub(crate) fn enter() -> io::Result<()> {
    #[cfg(unix)]
    {
        use rustix::termios::{OptionalActions, tcgetattr, tcsetattr};
        let stdin = io::stdin();
        // The guard is released before anything else runs, so the panic hook's
        // `leave` can never wait on it.
        let mut raw = {
            let mut saved = SAVED.lock().unwrap_or_else(poisoned);
            if saved.is_none() {
                *saved = Some(tcgetattr(&stdin)?);
            }
            saved
                .clone()
                .ok_or_else(|| io::Error::other("no saved mode"))?
        };
        raw.make_raw();
        tcsetattr(&stdin, OptionalActions::Now, &raw)?;
    }
    #[cfg(windows)]
    ratatui::crossterm::terminal::enable_raw_mode()?;
    ACTIVE.store(true, Ordering::SeqCst);
    let mut out = io::stdout();
    execute!(
        out,
        EnterAlternateScreen,
        Hide,
        Clear(CtClearType::All),
        MoveTo(0, 0)
    )?;
    out.flush()
}

/// Show the cursor, leave the alternate screen and restore the saved mode. Errors are
/// ignored: on a hung-up terminal there is nothing left to restore. Idempotent.
pub(crate) fn leave() {
    if !ACTIVE.swap(false, Ordering::SeqCst) {
        return;
    }
    let mut out = io::stdout();
    let _ = execute!(out, Show, LeaveAlternateScreen);
    let _ = out.flush();
    #[cfg(unix)]
    {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        use rustix::termios::{OptionalActions, tcsetattr};
        let stdin = io::stdin();
        if let Some(saved) = SAVED.lock().unwrap_or_else(poisoned).as_ref() {
            let _ = tcsetattr(&stdin, OptionalActions::Now, saved);
        }
        // Darwin sets the kernel-managed PENDIN flag when a terminal goes back to
        // canonical mode with TCSANOW; a poll processes and clears it, so the mode
        // read afterwards equals the saved one (REPORT.md §5).
        let mut fds = [PollFd::new(&stdin, PollFlags::IN)];
        let _ = poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        );
    }
    #[cfg(windows)]
    {
        let _ = ratatui::crossterm::terminal::disable_raw_mode();
    }
}

/// The terminal size, without any fallback that runs a program.
///
/// # Errors
/// The size cannot be read.
pub(crate) fn size() -> io::Result<Size> {
    #[cfg(unix)]
    {
        let w = rustix::termios::tcgetwinsize(io::stdout())?;
        if w.ws_col == 0 || w.ws_row == 0 {
            // A terminal that reports no size (some ptys): a conventional default.
            return Ok(Size {
                width: 80,
                height: 24,
            });
        }
        Ok(Size {
            width: w.ws_col,
            height: w.ws_row,
        })
    }
    #[cfg(windows)]
    {
        let (width, height) = ratatui::crossterm::terminal::size()?;
        Ok(Size { width, height })
    }
}

/// Whether `e` means the terminal is gone (a hang-up seen as `EIO`, `ENXIO`, a broken
/// pipe or end of file).
#[must_use]
pub(crate) fn is_hangup(e: &io::Error) -> bool {
    #[cfg(unix)]
    if let Some(code) = e.raw_os_error()
        && (code == rustix::io::Errno::IO.raw_os_error()
            || code == rustix::io::Errno::NXIO.raw_os_error())
    {
        return true;
    }
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof
    )
}

/// ratatui's crossterm backend with the two terminal-querying methods replaced: the
/// cursor-position request is refused and the size comes from [`size`].
pub(crate) struct TermBackend(CrosstermBackend<io::Stdout>);

impl TermBackend {
    /// A backend writing to stdout.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self(CrosstermBackend::new(io::stdout()))
    }
}

impl Backend for TermBackend {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        self.0.draw(content)
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        self.0.hide_cursor()
    }

    /// Errors are ignored: [`leave`] shows the cursor authoritatively.
    fn show_cursor(&mut self) -> io::Result<()> {
        let _ = self.0.show_cursor();
        Ok(())
    }

    /// Never asks the terminal (no `ESC[6n`).
    fn get_cursor_position(&mut self) -> io::Result<Position> {
        Err(io::Error::other("the TUI never queries the terminal"))
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
        size()
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        Ok(WindowSize {
            columns_rows: size()?,
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

/// One step of terminal input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Input {
    /// Keys.
    Keys(Vec<Key>),
    /// The console was resized (Windows; Unix resizes arrive as SIGWINCH).
    #[cfg_attr(unix, allow(dead_code))]
    Resize,
    /// The terminal hung up (Unix: `POLLHUP`, end of file or `EIO`).
    #[cfg_attr(windows, allow(dead_code))]
    Hangup,
    /// Nothing within the timeout.
    Idle,
}

/// The input reader.
#[cfg(unix)]
pub(crate) struct Reader {
    decoder: super::keys::Decoder,
}

#[cfg(unix)]
impl Reader {
    /// A reader of stdin.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            decoder: super::keys::Decoder::new(),
        }
    }

    /// Wait up to `timeout` for input. A pending lone ESC is decided after 30 ms.
    ///
    /// # Errors
    /// `poll` or `read` fails other than by a hang-up or an interruption.
    pub(crate) fn next(&mut self, timeout: Duration) -> io::Result<Input> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        use rustix::io::Errno;
        let wait = if self.decoder.has_pending() {
            Duration::from_millis(30)
        } else {
            timeout
        };
        let stdin = io::stdin();
        let ts = Timespec {
            tv_sec: i64::try_from(wait.as_secs()).unwrap_or(1),
            tv_nsec: wait.subsec_nanos().into(),
        };
        let mut fds = [PollFd::new(&stdin, PollFlags::IN)];
        match poll(&mut fds, Some(&ts)) {
            Ok(0) => {
                return Ok(if self.decoder.has_pending() {
                    Input::Keys(self.decoder.flush())
                } else {
                    Input::Idle
                });
            }
            Ok(_) => {}
            Err(Errno::INTR) => return Ok(Input::Idle),
            Err(e) => return Err(e.into()),
        }
        let revents = fds[0].revents();
        if revents.intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL) {
            return Ok(Input::Hangup);
        }
        let mut buf = [0u8; 1024];
        match rustix::io::read(&stdin, &mut buf) {
            Ok(0) | Err(Errno::IO) => Ok(Input::Hangup),
            Ok(n) => Ok(Input::Keys(self.decoder.push(&buf[..n]))),
            Err(Errno::INTR | Errno::AGAIN) => Ok(Input::Idle),
            Err(e) => Err(e.into()),
        }
    }
}

/// The input reader (Windows: crossterm's console input; no helper program runs).
#[cfg(windows)]
pub(crate) struct Reader;

#[cfg(windows)]
impl Reader {
    /// A reader of the console.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self
    }

    /// Wait up to `timeout` for input.
    ///
    /// # Errors
    /// The console cannot be read.
    pub(crate) fn next(&mut self, timeout: Duration) -> io::Result<Input> {
        use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
        if !event::poll(timeout)? {
            return Ok(Input::Idle);
        }
        Ok(match event::read()? {
            Event::Key(k) if k.kind == KeyEventKind::Press => {
                let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
                let key = match k.code {
                    KeyCode::Char('c') if ctrl => Key::CtrlC,
                    KeyCode::Char(_) if ctrl || k.modifiers.contains(KeyModifiers::ALT) => {
                        Key::Other
                    }
                    KeyCode::Char(c) => Key::Char(c),
                    KeyCode::Enter => Key::Enter,
                    KeyCode::Esc => Key::Esc,
                    KeyCode::Backspace => Key::Backspace,
                    KeyCode::Tab => Key::Tab,
                    KeyCode::BackTab => Key::BackTab,
                    KeyCode::Up => Key::Up,
                    KeyCode::Down => Key::Down,
                    KeyCode::Left => Key::Left,
                    KeyCode::Right => Key::Right,
                    KeyCode::Home => Key::Home,
                    KeyCode::End => Key::End,
                    KeyCode::PageUp => Key::PageUp,
                    KeyCode::PageDown => Key::PageDown,
                    KeyCode::Delete => Key::Delete,
                    _ => Key::Other,
                };
                Input::Keys(vec![key])
            }
            Event::Resize(_, _) => Input::Resize,
            _ => Input::Idle,
        })
    }
}
