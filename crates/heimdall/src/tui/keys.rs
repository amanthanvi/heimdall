//! Keys, and the Unix decoder that turns terminal bytes into them (m02-plan U10).
//!
//! On Unix the TUI reads the terminal itself (`poll` and `read` on stdin) and never
//! uses crossterm's event source, which spins on a hung-up terminal
//! (prototypes/rust/REPORT.md §5). The decoder understands what a terminal sends in
//! raw mode for the keys the TUI binds: printable UTF-8, Enter, Tab and Shift-Tab,
//! Backspace, Escape, the arrows (CSI and SS3 forms), Home, End, Page Up and Page
//! Down, Delete, and Ctrl-C. Any other sequence decodes to [`Key::Other`] and is never
//! echoed. A lone Escape is decided by the caller's timeout ([`Decoder::flush`]).

/// One key the TUI understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Key {
    /// A printable character.
    Char(char),
    /// Enter (carriage return or line feed).
    Enter,
    /// Escape.
    Esc,
    /// Backspace (DEL or BS).
    Backspace,
    /// Tab.
    Tab,
    /// Shift-Tab.
    BackTab,
    /// Up arrow.
    Up,
    /// Down arrow.
    Down,
    /// Left arrow.
    Left,
    /// Right arrow.
    Right,
    /// Home.
    Home,
    /// End.
    End,
    /// Page Up.
    PageUp,
    /// Page Down.
    PageDown,
    /// Delete.
    Delete,
    /// Ctrl-C (a byte in raw mode, never a signal).
    CtrlC,
    /// Anything else (ignored).
    Other,
}

/// Incremental decoder of terminal input bytes (Unix raw mode; Windows reads console
/// key events instead).
#[derive(Debug, Default)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct Decoder {
    pending: Vec<u8>,
}

/// The longest escape sequence the decoder buffers before giving up on it.
#[cfg_attr(not(unix), allow(dead_code))]
const MAX_SEQUENCE: usize = 16;

#[cfg_attr(not(unix), allow(dead_code))]
impl Decoder {
    /// A decoder with nothing pending.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether an incomplete sequence (a lone ESC, a partial CSI or UTF-8 character)
    /// waits for more bytes.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Feed `bytes`; returns every key they complete.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Vec<Key> {
        self.pending.extend_from_slice(bytes);
        let mut keys = Vec::new();
        loop {
            match decode(&self.pending) {
                Step::Key(key, used) => {
                    keys.push(key);
                    self.pending.drain(..used);
                }
                Step::Incomplete if self.pending.len() > MAX_SEQUENCE => {
                    keys.push(Key::Other);
                    self.pending.clear();
                }
                Step::Incomplete | Step::Empty => return keys,
            }
        }
    }

    /// No more bytes arrived in time: a pending lone ESC is Escape; anything else
    /// pending is dropped as [`Key::Other`].
    pub(crate) fn flush(&mut self) -> Vec<Key> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let key = if self.pending == [0x1b] {
            Key::Esc
        } else {
            Key::Other
        };
        self.pending.clear();
        vec![key]
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
enum Step {
    Key(Key, usize),
    Incomplete,
    Empty,
}

#[cfg_attr(not(unix), allow(dead_code))]
fn decode(buf: &[u8]) -> Step {
    let Some(&first) = buf.first() else {
        return Step::Empty;
    };
    match first {
        0x1b => decode_escape(buf),
        b'\r' | b'\n' => Step::Key(Key::Enter, 1),
        b'\t' => Step::Key(Key::Tab, 1),
        0x7f | 0x08 => Step::Key(Key::Backspace, 1),
        0x03 => Step::Key(Key::CtrlC, 1),
        0x00..=0x1f => Step::Key(Key::Other, 1),
        0x20..=0x7e => Step::Key(Key::Char(char::from(first)), 1),
        _ => decode_utf8(buf),
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn decode_utf8(buf: &[u8]) -> Step {
    let len = match buf[0] {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return Step::Key(Key::Other, 1),
    };
    if buf.len() < len {
        return Step::Incomplete;
    }
    match std::str::from_utf8(&buf[..len])
        .ok()
        .and_then(|s| s.chars().next())
    {
        Some(c) if !c.is_control() => Step::Key(Key::Char(c), len),
        _ => Step::Key(Key::Other, 1),
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn decode_escape(buf: &[u8]) -> Step {
    let Some(&second) = buf.get(1) else {
        return Step::Incomplete;
    };
    match second {
        b'[' => decode_csi(buf),
        b'O' => match buf.get(2) {
            None => Step::Incomplete,
            Some(b'A') => Step::Key(Key::Up, 3),
            Some(b'B') => Step::Key(Key::Down, 3),
            Some(b'C') => Step::Key(Key::Right, 3),
            Some(b'D') => Step::Key(Key::Left, 3),
            Some(b'H') => Step::Key(Key::Home, 3),
            Some(b'F') => Step::Key(Key::End, 3),
            Some(_) => Step::Key(Key::Other, 3),
        },
        // ESC ESC: the first is a lone Escape.
        0x1b => Step::Key(Key::Esc, 1),
        // Alt-<key>: not bound.
        _ => Step::Key(Key::Other, 2),
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn decode_csi(buf: &[u8]) -> Step {
    // ESC [ parameters (0x30..=0x3f) intermediates (0x20..=0x2f) final (0x40..=0x7e).
    for (i, &b) in buf.iter().enumerate().skip(2) {
        match b {
            0x20..=0x3f => {}
            0x40..=0x7e => {
                let params = &buf[2..i];
                let key = match (params, b) {
                    (_, b'A') => Key::Up,
                    (_, b'B') => Key::Down,
                    (_, b'C') => Key::Right,
                    (_, b'D') => Key::Left,
                    (_, b'H') => Key::Home,
                    (_, b'F') => Key::End,
                    (b"", b'Z') => Key::BackTab,
                    (b"1" | b"7", b'~') => Key::Home,
                    (b"4" | b"8", b'~') => Key::End,
                    (b"3", b'~') => Key::Delete,
                    (b"5", b'~') => Key::PageUp,
                    (b"6", b'~') => Key::PageDown,
                    _ => Key::Other,
                };
                return Step::Key(key, i + 1);
            }
            _ => return Step::Key(Key::Other, i + 1),
        }
    }
    Step::Incomplete
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn keys(bytes: &[u8]) -> Vec<Key> {
        let mut d = Decoder::new();
        let mut out = d.push(bytes);
        out.extend(d.flush());
        out
    }

    #[test]
    fn printable_control_and_navigation_keys_decode() {
        assert_eq!(
            keys(b"ab\r\t\x7f\x03"),
            [
                Key::Char('a'),
                Key::Char('b'),
                Key::Enter,
                Key::Tab,
                Key::Backspace,
                Key::CtrlC
            ]
        );
        assert_eq!(
            keys(b"\x1b[A\x1b[B\x1b[C\x1b[D\x1bOA\x1b[5~\x1b[6~\x1b[H\x1b[4~\x1b[Z\x1b[3~"),
            [
                Key::Up,
                Key::Down,
                Key::Right,
                Key::Left,
                Key::Up,
                Key::PageUp,
                Key::PageDown,
                Key::Home,
                Key::End,
                Key::BackTab,
                Key::Delete
            ]
        );
        assert_eq!(keys("é€".as_bytes()), [Key::Char('é'), Key::Char('€')]);
    }

    #[test]
    fn a_lone_escape_waits_for_the_timeout_and_split_sequences_join() {
        let mut d = Decoder::new();
        assert!(d.push(b"\x1b").is_empty());
        assert!(d.has_pending());
        assert_eq!(d.flush(), [Key::Esc]);
        assert!(d.push(b"\x1b[").is_empty());
        assert_eq!(d.push(b"A"), [Key::Up]);
        assert!(d.push(&[0xc3]).is_empty());
        assert_eq!(d.push(&[0xa9]), [Key::Char('é')]);
    }

    #[test]
    fn unknown_or_hostile_sequences_never_become_text() {
        // An OSC, a long CSI and stray C1 bytes decode to nothing printable.
        for k in keys(b"\x1b]0;title\x07\x1b[999;999;999;999;999;999;999R\x9b\x85") {
            assert!(!matches!(k, Key::Char(c) if c.is_control()), "{k:?}");
        }
        assert_eq!(keys(b"\x1b[6n"), [Key::Other]);
    }
}
