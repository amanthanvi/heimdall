//! Terminal input decoder for the TUI (contract §5 keys), round 2.
//!
//! Round 1 read keys through crossterm's event source. On SIGWINCH that source calls
//! `crossterm::terminal::size()`, which falls back to executing `tput cols` and
//! `tput lines` from PATH when the terminal size ioctl fails (crossterm 0.29
//! `terminal/sys/unix.rs` `tput_size`; observed on Linux arm64 after the output
//! terminal hung up). Contract §9.1 K16 forbids executing any helper program, and the
//! fallback cannot be switched off, so the TUI now decodes raw input bytes itself and
//! never calls crossterm's event or size functions. This decoder is pure: bytes in,
//! keys out, no I/O.
//!
//! Recognized: Up/Down as `ESC [ A|B` and `ESC O A|B` (with or without CSI
//! parameters), Enter (`CR`), Esc (a lone `ESC`, decided by the caller's timeout),
//! Backspace (`DEL` or `BS`), Ctrl-C (`ETX`), and printable UTF-8 characters. Every
//! other control byte or escape sequence becomes [`Key::Other`].

use crate::list_model::Key;

/// Incremental decoder. Feed bytes with [`Decoder::push`]; call [`Decoder::flush`]
/// when no more input arrived within the escape timeout, so a pending lone `ESC`
/// becomes [`Key::Esc`].
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

/// Longest escape sequence kept while waiting for its final byte; anything longer is
/// discarded as [`Key::Other`] (bounds memory on garbage input).
const MAX_SEQ: usize = 64;

enum Step {
    Key(Key, usize),
    /// More bytes are needed to decide.
    Incomplete,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// True if undecided bytes are buffered (the caller should wait briefly for more
    /// input, then call [`Decoder::flush`]).
    pub fn has_pending(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Append `bytes` and return every key that is now complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Key> {
        self.buf.extend_from_slice(bytes);
        self.drain(false)
    }

    /// Decide whatever is pending: a lone `ESC` is the Esc key; an unfinished escape
    /// sequence is Esc followed by its remaining bytes decoded on their own.
    pub fn flush(&mut self) -> Vec<Key> {
        self.drain(true)
    }

    fn drain(&mut self, flush: bool) -> Vec<Key> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.buf.len() {
            match step(&self.buf[i..]) {
                Step::Key(k, n) => {
                    out.push(k);
                    i += n;
                }
                Step::Incomplete if flush => {
                    // ESC prefix without its final byte, or a truncated UTF-8 char.
                    out.push(if self.buf[i] == 0x1b {
                        Key::Esc
                    } else {
                        Key::Other
                    });
                    i += 1;
                }
                Step::Incomplete if self.buf.len() - i > MAX_SEQ => {
                    out.push(Key::Other);
                    i += 1;
                }
                Step::Incomplete => break,
            }
        }
        self.buf.drain(..i);
        out
    }
}

fn step(b: &[u8]) -> Step {
    match b[0] {
        0x1b => escape(b),
        b'\r' => Step::Key(Key::Enter, 1),
        0x7f | 0x08 => Step::Key(Key::Backspace, 1),
        0x03 => Step::Key(Key::CtrlC, 1),
        0x00..=0x1f => Step::Key(Key::Other, 1),
        _ => utf8_char(b),
    }
}

fn escape(b: &[u8]) -> Step {
    let Some(&second) = b.get(1) else {
        return Step::Incomplete;
    };
    match second {
        b'[' => {
            // CSI: parameter/intermediate bytes 0x20..=0x3f, final byte 0x40..=0x7e.
            for (j, &c) in b.iter().enumerate().skip(2) {
                match c {
                    0x20..=0x3f => continue,
                    0x40..=0x7e => {
                        let key = match c {
                            b'A' => Key::Up,
                            b'B' => Key::Down,
                            _ => Key::Other,
                        };
                        return Step::Key(key, j + 1);
                    }
                    // Not a valid CSI byte: drop the ESC [ prefix as unknown input.
                    _ => return Step::Key(Key::Other, j),
                }
            }
            Step::Incomplete
        }
        b'O' => match b.get(2) {
            None => Step::Incomplete,
            Some(b'A') => Step::Key(Key::Up, 3),
            Some(b'B') => Step::Key(Key::Down, 3),
            Some(_) => Step::Key(Key::Other, 3),
        },
        // ESC ESC: the first one is a lone Esc key.
        0x1b => Step::Key(Key::Esc, 1),
        // Alt+<key>: not a contract key.
        _ => match utf8_char(&b[1..]) {
            Step::Key(_, n) => Step::Key(Key::Other, 1 + n),
            Step::Incomplete => Step::Incomplete,
        },
    }
}

fn utf8_char(b: &[u8]) -> Step {
    let need = match b[0] {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return Step::Key(Key::Other, 1),
    };
    if b.len() < need {
        // Only incomplete if every byte present is a continuation byte so far.
        if b[1..].iter().all(|&c| c & 0xc0 == 0x80) {
            return Step::Incomplete;
        }
        return Step::Key(Key::Other, 1);
    }
    match std::str::from_utf8(&b[..need]) {
        Ok(s) => {
            let c = s.chars().next().unwrap_or('\u{FFFD}');
            if c.is_control() {
                Step::Key(Key::Other, need)
            } else {
                Step::Key(Key::Char(c), need)
            }
        }
        Err(_) => Step::Key(Key::Other, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(bytes: &[u8]) -> Vec<Key> {
        let mut d = Decoder::new();
        let mut k = d.push(bytes);
        k.extend(d.flush());
        k
    }

    #[test]
    fn contract_keys() {
        assert_eq!(
            all(b"\x1b[A\x1b[B\x1bOA\x1bOB"),
            [Key::Up, Key::Down, Key::Up, Key::Down]
        );
        assert_eq!(all(b"\x1b[1;2A"), [Key::Up]);
        assert_eq!(all(b"\r"), [Key::Enter]);
        assert_eq!(all(b"\x7f\x08"), [Key::Backspace, Key::Backspace]);
        assert_eq!(all(b"\x03"), [Key::CtrlC]);
        assert_eq!(
            all(b"jk/q"),
            [
                Key::Char('j'),
                Key::Char('k'),
                Key::Char('/'),
                Key::Char('q')
            ]
        );
        assert_eq!(
            all("/東京ü".as_bytes()),
            [
                Key::Char('/'),
                Key::Char('東'),
                Key::Char('京'),
                Key::Char('ü')
            ]
        );
        assert_eq!(all(b"\n\t\x1b[C\x1b[5~"), [Key::Other; 4]);
        assert_eq!(all(b"\x1bx"), [Key::Other], "Alt+x");
    }

    #[test]
    fn lone_escape_needs_flush() {
        let mut d = Decoder::new();
        assert_eq!(d.push(b"\x1b"), []);
        assert!(d.has_pending());
        assert_eq!(d.flush(), [Key::Esc]);
        assert!(!d.has_pending());
        assert_eq!(all(b"\x1b\x1b"), [Key::Esc, Key::Esc]);
    }

    #[test]
    fn split_sequences_and_utf8_across_reads() {
        let mut d = Decoder::new();
        assert_eq!(d.push(b"\x1b["), []);
        assert_eq!(d.push(b"B"), [Key::Down]);
        let e = "東".as_bytes();
        assert_eq!(d.push(&e[..1]), []);
        assert_eq!(d.push(&e[1..2]), []);
        assert_eq!(d.push(&e[2..]), [Key::Char('東')]);
    }

    #[test]
    fn garbage_is_bounded_and_invalid_utf8_is_other() {
        assert_eq!(all(b"\xff\xc3("), [Key::Other, Key::Other, Key::Char('(')]);
        let mut d = Decoder::new();
        let mut long = b"\x1b[".to_vec();
        long.extend(std::iter::repeat_n(b'1', 200));
        let keys = d.push(&long);
        assert!(
            !keys.is_empty() && d.buf.len() <= MAX_SEQ + 1,
            "unterminated CSI is not buffered without bound"
        );
        assert_eq!(all(b"\x1b[\x01"), [Key::Other, Key::Other]);
    }
}
