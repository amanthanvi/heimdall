//! Shared helpers for strings that end up in machine output or on the terminal.

/// True if `c` is a C0/C1 control character or DEL (anything that could start a
/// terminal escape sequence or reshape output).
pub fn is_unsafe_control(c: char) -> bool {
    c.is_control()
}

/// Replace every control character with U+FFFD. Used for peer-supplied agent
/// strings (comment, key type) so machine output never carries terminal escapes
/// (contract §1: "No ANSI escapes in JSON strings").
pub fn replace_controls(s: &str) -> String {
    s.chars()
        .map(|c| if is_unsafe_control(c) { '\u{FFFD}' } else { c })
        .collect()
}

/// Render a TOML key for use inside a dotted key path. Bare-key-safe names are
/// emitted as-is; anything else is quoted with Rust debug escaping so control
/// characters never reach output verbatim. Key *names* may appear in messages;
/// key *values* never do.
pub fn key_segment(key: &str) -> String {
    let bare = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if bare {
        key.to_string()
    } else {
        format!("{key:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_replaced() {
        assert_eq!(
            replace_controls("a\u{1b}[31mb\u{7f}c\u{9b}"),
            "a\u{FFFD}[31mb\u{FFFD}c\u{FFFD}"
        );
        assert_eq!(replace_controls("plain ü 東京"), "plain ü 東京");
    }

    #[test]
    fn key_segments() {
        assert_eq!(key_segment("identity_file"), "identity_file");
        assert_eq!(key_segment("we ird"), "\"we ird\"");
        assert_eq!(key_segment("e\u{1b}x"), "\"e\\u{1b}x\"");
    }
}
