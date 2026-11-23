//! The checks a string passes before it may enter a bundle (ADR-0014 §5.1).
//!
//! These checks are a second line, not the guarantee. The guarantee is the typing: free
//! text and secrets hold no text at all ([`crate::FreeText`], [`crate::Secret`]), and a
//! default bundle carries a pseudonym, never the identifier itself. The checks decide
//! which typed strings are fit to write:
//!
//! * [`screen_code`]: a code is **code-shaped** (below) and carries no canary marker, no
//!   key armor and no key-like run. Anything else is withheld as `malformed` (shape) or
//!   `failed_secret_check`.
//! * [`screen_version`], [`screen_build_id`]: the string-valued safe values have exact
//!   shapes.
//! * [`screen_identifier`]: an identifier is non-empty, at most [`IDENT_MAX_LEN`] bytes
//!   ([`PATH_MAX_LEN`] for a path), has no control character, no line or paragraph
//!   separator (so no embedded newline) and no invisible or bidirectional formatting
//!   character, no canary marker, no key armor in any casing or spacing, and no key-like
//!   run. A fingerprint and a Heimdall ID must match their exact shapes instead of the
//!   key-like-run check (both are random-looking by design). The bundle applies this to
//!   **every** identifier, pseudonymized or included, so a failing value reaches neither
//!   the bundle nor the inverse map.
//!
//! **Canary and armor.** Both are looked for in the value normalized to lower-case ASCII
//! letters and digits (every other character removed), so casing, spacing, dashes and
//! underscores do not hide them: the canary marker `heimdallcanary`; `begin` or `end`
//! followed by a key type (`openssh`, `rsa`, `private`, `pgp`, `ssh2`, `certificate`,
//! ...); the PuTTY key-file headers; the OpenSSH key magic and its base64 form; PEM
//! encryption headers. Separately, four or more dashes in a row once whitespace is
//! ignored (`-----`, `- - - -`, Unicode dashes) are armor.
//!
//! **Code shape.** 1 to [`CODE_MAX_LEN`] ASCII bytes: an ASCII letter, then ASCII letters
//! and digits in segments joined by single separators from `_ . : -` (no leading,
//! trailing or doubled separator). No `/` or `\` (keeps paths out), no whitespace, no
//! `@`, `+`, `=` or quote. Examples: `store_corrupt`, `x86_64-unknown-linux-gnu`,
//! `transport.enabled`, `custody:macos-keychain`.
//!
//! **Key-like run.** The value is cut into maximal runs of `[A-Za-z0-9+/=_-]` (the base64,
//! base64url and hex alphabets). A run is key-like when, after trailing `=` padding is
//! removed, it (or one of its pieces between `_ - / + =`) is pure hex of at least
//! [`HEX_RUN_MIN`] characters; or it is not made of word-like pieces and either carried
//! `=` padding with at least 8 characters before it, or is at least [`KEY_RUN_MIN`]
//! characters mixing at least two of {upper case, lower case, digit, `+`/`=`}. A piece is
//! word-like when it has at most three characters, is all digits, or is letters shaped
//! `word`, `WORD`, `Word` or `CamelCase` followed by at most six digits (so `ed25519`,
//! `sha256` and `aarch64` are words). This is stricter than the local log redactor
//! (`telemetry::redact`, which uses 24); it cannot recognize a short or word-like secret,
//! which is why identifiers are pseudonymized by default and text is never collected.

/// Longest code, in bytes.
pub const CODE_MAX_LEN: usize = 64;
/// Longest version string, in bytes.
pub const VERSION_MAX_LEN: usize = 64;
/// Longest path identifier, in bytes.
pub const PATH_MAX_LEN: usize = 1024;
/// Longest identifier of any other kind, in bytes.
pub const IDENT_MAX_LEN: usize = 256;
/// Shortest mixed-class run treated as key-like.
pub const KEY_RUN_MIN: usize = 16;
/// Shortest pure-hex run treated as key-like.
pub const HEX_RUN_MIN: usize = 32;

/// The canary marker (`HEIMDALL_CANARY_`, ADR-0004 §4), normalized: lower case with every
/// character that is not an ASCII letter or digit removed, so `heimdall-canary` and
/// `HEIMDALL CANARY` match too.
const CANARY_NORMALIZED: &str = "heimdallcanary";

/// Key-file markers, normalized (lower case, ASCII letters and digits only): PuTTY key
/// files, the OpenSSH key magic and its base64 form, PEM encryption headers.
const ARMOR_MARKERS: &[&str] = &[
    "puttyuserkeyfile",
    "privatelines",
    "publiclines",
    "privatemac",
    "opensshkeyv1",
    "b3blbnnzac1rzxktdje",
    "proctype4encrypted",
    "dekinfo",
];

/// Words that follow `begin` or `end` in an armor line, normalized.
const ARMOR_TYPES: &[&str] = &[
    "openssh",
    "rsa",
    "dsa",
    "ecprivate",
    "ecparameters",
    "private",
    "public",
    "encrypted",
    "anyprivate",
    "pgp",
    "ssh2",
    "sshsignature",
    "certificate",
    "trustedcertificate",
    "x509",
    "pkcs",
];

/// Why a value was withheld. Each reason is written to the manifest as its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Withheld {
    /// Typed as free text: never written.
    FreeText,
    /// Typed as a secret: never written.
    Secret,
    /// Not the shape its type requires (a code that is not code-shaped, a malformed
    /// version, build identifier, timestamp, fingerprint or Heimdall ID, an empty
    /// identifier, an invalid or repeated field name).
    Malformed,
    /// Failed a secret check: a control character or line separator, the canary marker,
    /// key armor, a key-like run, or an identifier over its length cap.
    FailedSecretCheck,
}

impl Withheld {
    /// Every reason, in manifest order.
    pub const ALL: [Withheld; 4] = [
        Withheld::FreeText,
        Withheld::Secret,
        Withheld::Malformed,
        Withheld::FailedSecretCheck,
    ];

    /// The manifest code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Withheld::FreeText => "free_text",
            Withheld::Secret => "secret",
            Withheld::Malformed => "malformed",
            Withheld::FailedSecretCheck => "failed_secret_check",
        }
    }
}

/// The kind of a public identifier (ADR-0014 §5.1 "Every remaining string is
/// pseudonymized"). Each kind has its own placeholder prefix and its own counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentKind {
    /// A user name (local or remote account).
    User,
    /// A host name or address.
    Host,
    /// An SSH alias.
    Alias,
    /// A label, profile, destination or policy name.
    Label,
    /// A filesystem path.
    Path,
    /// A key or host-key fingerprint (`SHA256:<43 base64>` or `MD5:<16 hex pairs>`).
    Fingerprint,
    /// A key comment.
    KeyComment,
    /// One of Heimdall's own runtime IDs (`<prefix>_<32 lowercase hex>`).
    HeimdallId,
}

impl IdentKind {
    /// Every kind.
    pub const ALL: [IdentKind; 8] = [
        IdentKind::User,
        IdentKind::Host,
        IdentKind::Alias,
        IdentKind::Label,
        IdentKind::Path,
        IdentKind::Fingerprint,
        IdentKind::KeyComment,
        IdentKind::HeimdallId,
    ];

    /// The placeholder prefix: a pseudonym is `<prefix>-<n>`, `n` counting from 1 per kind.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            IdentKind::User => "user",
            IdentKind::Host => "host",
            IdentKind::Alias => "alias",
            IdentKind::Label => "label",
            IdentKind::Path => "path",
            IdentKind::Fingerprint => "fp",
            IdentKind::KeyComment => "comment",
            IdentKind::HeimdallId => "id",
        }
    }

    /// The length cap, in bytes.
    #[must_use]
    pub fn max_len(self) -> usize {
        match self {
            IdentKind::Path => PATH_MAX_LEN,
            _ => IDENT_MAX_LEN,
        }
    }
}

/// Check a code: code-shaped, then the canary, armor and key-like-run checks.
///
/// # Errors
/// [`Withheld::Malformed`] when not code-shaped, [`Withheld::FailedSecretCheck`] when a
/// secret check fails.
pub fn screen_code(code: &str) -> Result<(), Withheld> {
    if !code_shaped(code) {
        return Err(Withheld::Malformed);
    }
    if fails_marker_checks(code) || has_key_like_run(code) {
        return Err(Withheld::FailedSecretCheck);
    }
    Ok(())
}

/// Check a version string: 1 to [`VERSION_MAX_LEN`] bytes of `[0-9A-Za-z.+-]` starting with
/// a digit (`1.0.0-rc.1`, `9.9p1`, `15.1`), then the canary, armor and key-like-run checks.
///
/// # Errors
/// As [`screen_code`].
pub fn screen_version(version: &str) -> Result<(), Withheld> {
    let shaped = !version.is_empty()
        && version.len() <= VERSION_MAX_LEN
        && version.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'));
    if !shaped {
        return Err(Withheld::Malformed);
    }
    if fails_marker_checks(version) || has_key_like_run(version) {
        return Err(Withheld::FailedSecretCheck);
    }
    Ok(())
}

/// Check a build identifier (a commit or build digest): 7 to 64 lowercase hex digits.
/// Hex by definition, so the key-like-run check does not apply; the shape excludes every
/// marker.
///
/// # Errors
/// [`Withheld::Malformed`] when not that shape.
pub fn screen_build_id(id: &str) -> Result<(), Withheld> {
    let shaped = (7..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if shaped {
        Ok(())
    } else {
        Err(Withheld::Malformed)
    }
}

/// Check an identifier of `kind`: the checks in the module documentation.
///
/// # Errors
/// [`Withheld::Malformed`] for an empty value or a fingerprint or Heimdall ID of the wrong
/// shape; [`Withheld::FailedSecretCheck`] for an over-long value, a control character or
/// line separator, the canary marker, key armor or a key-like run.
pub fn screen_identifier(kind: IdentKind, value: &str) -> Result<(), Withheld> {
    if value.is_empty() {
        return Err(Withheld::Malformed);
    }
    if value.len() > kind.max_len() || has_control(value) || fails_marker_checks(value) {
        return Err(Withheld::FailedSecretCheck);
    }
    match kind {
        IdentKind::Fingerprint if !fingerprint_shaped(value) => Err(Withheld::Malformed),
        IdentKind::HeimdallId if !heimdall_id_shaped(value) => Err(Withheld::Malformed),
        IdentKind::Fingerprint | IdentKind::HeimdallId => Ok(()),
        _ if has_key_like_run(value) => Err(Withheld::FailedSecretCheck),
        _ => Ok(()),
    }
}

/// Code shape (module documentation).
#[must_use]
pub fn code_shaped(code: &str) -> bool {
    let bytes = code.as_bytes();
    if bytes.is_empty()
        || bytes.len() > CODE_MAX_LEN
        || !bytes.first().is_some_and(u8::is_ascii_alphabetic)
    {
        return false;
    }
    let mut after_separator = false;
    for &b in bytes {
        if b.is_ascii_alphanumeric() {
            after_separator = false;
        } else if matches!(b, b'_' | b'.' | b':' | b'-') && !after_separator {
            after_separator = true;
        } else {
            return false;
        }
    }
    !after_separator
}

/// The canary marker or key armor, in any casing or spacing.
fn fails_marker_checks(text: &str) -> bool {
    let normalized = normalized(text);
    normalized.contains(CANARY_NORMALIZED) || armor_words(&normalized) || has_dash_run(text)
}

/// Lower-case ASCII letters and digits only; everything else removed.
fn normalized(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn armor_words(normalized: &str) -> bool {
    if ARMOR_MARKERS.iter().any(|m| normalized.contains(m)) {
        return true;
    }
    ["begin", "end"].iter().any(|keyword| {
        normalized.match_indices(keyword).any(|(at, _)| {
            normalized
                .get(at + keyword.len()..)
                .is_some_and(|rest| ARMOR_TYPES.iter().any(|t| rest.starts_with(t)))
        })
    })
}

/// Four or more dashes in a row once whitespace is ignored (`-----`, `- - - -`, `----`),
/// counting the Unicode dashes and minus signs as dashes.
fn has_dash_run(text: &str) -> bool {
    let mut run = 0usize;
    for c in text.chars() {
        if c.is_whitespace() {
            continue;
        }
        if is_dash(c) {
            run += 1;
            if run >= 4 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn is_dash(c: char) -> bool {
    matches!(
        c,
        '-' | '\u{2010}'
            ..='\u{2015}'
                | '\u{2212}'
                | '\u{2E3A}'
                | '\u{2E3B}'
                | '\u{FE58}'
                | '\u{FE63}'
                | '\u{FF0D}'
    )
}

/// A character that would make an included value read differently in the preview than it
/// is (review M08-W0-R05). The preview is the bundle, so nothing a reader cannot see may be
/// in a value:
///
/// * every control character (C0, DEL, C1: so every newline, carriage return and tab);
/// * the Unicode line and paragraph separators;
/// * every format character (general category `Cf`): the soft hyphen, the Arabic letter
///   mark and the Arabic and Syriac prepended marks, zero-width spaces and joiners,
///   directional marks, embeddings, overrides and isolates, the word joiner and the
///   invisible operators, the deprecated format characters U+206A–U+206F, the byte-order
///   mark, interlinear annotation marks, the shorthand and musical format controls, the
///   Egyptian hieroglyph format controls, and the whole tag block U+E0000–U+E007F;
/// * the variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF, the Mongolian U+180B–U+180F);
/// * invisible fillers and joiners that are not `Cf`: the combining grapheme joiner, the
///   Hangul fillers, the Khmer inherent vowels, and the reserved U+2065.
///
/// `std` has no general-category test, so the ranges are listed. A test names one
/// character of each class.
fn has_control(text: &str) -> bool {
    text.chars()
        .any(|c| c.is_control() || is_invisible_or_format(c))
}

fn is_invisible_or_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'                      // soft hyphen
            | '\u{034F}'                // combining grapheme joiner
            | '\u{0600}'..='\u{0605}'  // Arabic prepended format marks
            | '\u{061C}'                // Arabic letter mark
            | '\u{06DD}'
            | '\u{070F}'                // Syriac abbreviation mark
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'  // Hangul fillers
            | '\u{17B4}'..='\u{17B5}'  // Khmer inherent vowels
            | '\u{180B}'..='\u{180F}'  // Mongolian variation selectors and vowel separator
            | '\u{200B}'..='\u{200F}'  // zero-width spaces, joiners, directional marks
            | '\u{2028}'..='\u{202E}'  // line and paragraph separators, embeddings, overrides
            | '\u{2060}'..='\u{206F}'  // word joiner, invisible operators, U+2065, isolates, deprecated
            | '\u{3164}'                // Hangul filler
            | '\u{FE00}'..='\u{FE0F}'  // variation selectors
            | '\u{FEFF}'                // byte-order mark
            | '\u{FFA0}'                // halfwidth Hangul filler
            | '\u{FFF9}'..='\u{FFFB}'  // interlinear annotation
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}' // Egyptian hieroglyph format controls
            | '\u{1BCA0}'..='\u{1BCA3}' // shorthand format controls
            | '\u{1D173}'..='\u{1D17A}' // musical format controls
            | '\u{E0000}'..='\u{E007F}' // tags
            | '\u{E0100}'..='\u{E01EF}' // variation selectors supplement
    )
}

fn is_run_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

/// A key-like run anywhere in `text` (module documentation).
#[must_use]
pub fn has_key_like_run(text: &str) -> bool {
    text.split(|c: char| !is_run_char(c)).any(key_like)
}

fn key_like(run: &str) -> bool {
    let core = run.trim_end_matches('=');
    let padded = core.len() != run.len();
    let long_hex =
        |piece: &str| piece.len() >= HEX_RUN_MIN && piece.bytes().all(|b| b.is_ascii_hexdigit());
    if long_hex(core) || pieces(core).any(long_hex) {
        return true;
    }
    if pieces(core).all(word_like) {
        return false;
    }
    if padded && core.len() >= 8 {
        return true;
    }
    core.len() >= KEY_RUN_MIN && classes(core) >= 2
}

fn pieces(run: &str) -> impl Iterator<Item = &str> {
    run.split(['_', '-', '/', '+', '='])
}

fn word_like(piece: &str) -> bool {
    if piece.len() <= 3 || piece.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    let letters_end = piece
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(piece.len());
    let (letters, digits) = piece.split_at(letters_end);
    if digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let bytes = letters.as_bytes();
    if bytes.iter().all(u8::is_ascii_uppercase) {
        return true;
    }
    // word, Word or CamelCase: every capital is followed by two lower-case letters.
    bytes.iter().enumerate().all(|(i, b)| {
        !b.is_ascii_uppercase()
            || bytes
                .get(i + 1..i + 3)
                .is_some_and(|next| next.iter().all(u8::is_ascii_lowercase))
    })
}

fn classes(core: &str) -> usize {
    let (mut upper, mut lower, mut digit, mut symbol) = (false, false, false, false);
    for b in core.bytes() {
        match b {
            b'A'..=b'Z' => upper = true,
            b'a'..=b'z' => lower = true,
            b'0'..=b'9' => digit = true,
            b'+' | b'=' => symbol = true,
            _ => {}
        }
    }
    [upper, lower, digit, symbol].iter().filter(|x| **x).count()
}

/// `SHA256:` and 43 unpadded base64 characters, or `MD5:` and 16 colon-separated pairs of
/// hex digits.
fn fingerprint_shaped(value: &str) -> bool {
    if let Some(body) = value.strip_prefix("SHA256:") {
        return body.len() == 43
            && body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    }
    if let Some(body) = value.strip_prefix("MD5:") {
        let mut pairs = 0usize;
        for pair in body.split(':') {
            pairs += 1;
            if pair.len() != 2 || !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
                return false;
            }
        }
        return pairs == 16;
    }
    false
}

/// `<1..=16 lower-case letters>_<32 lowercase hex>` (`heimdall_contract::ids`).
fn heimdall_id_shaped(value: &str) -> bool {
    value.split_once('_').is_some_and(|(prefix, hex)| {
        (1..=16).contains(&prefix.len())
            && prefix.bytes().all(|b| b.is_ascii_lowercase())
            && hex.len() == 32
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canary built at run time (never a committed value).
    fn canary() -> String {
        format!("{}_{}_{}", "HEIMDALL", "CANARY", std::process::id())
    }

    #[test]
    fn code_shape_accepts_enumerated_codes_and_refuses_everything_else() {
        for ok in [
            "ok",
            "store_corrupt",
            "x86_64-unknown-linux-gnu",
            "transport.enabled",
            "custody:macos-keychain",
            "D-SSH-001",
            "host-1",
        ] {
            assert!(screen_code(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "_lead",
            "trail_",
            "two__seps",
            "1leading_digit",
            "has space",
            "/abs/path",
            "rel/path",
            "C:\\Users",
            "user@host",
            "a+b",
            "a=b",
            "quote\"",
            "new\nline",
            "ünïcode",
        ] {
            assert_eq!(screen_code(bad), Err(Withheld::Malformed), "{bad:?}");
        }
        // `z`, not `a`: a run of 32 or more hex digits is key-like.
        assert_eq!(
            screen_code(&"z".repeat(CODE_MAX_LEN + 1)),
            Err(Withheld::Malformed)
        );
        assert!(screen_code(&"z".repeat(CODE_MAX_LEN)).is_ok());
        assert_eq!(
            screen_code(&"a".repeat(CODE_MAX_LEN)),
            Err(Withheld::FailedSecretCheck)
        );
    }

    #[test]
    fn codes_carrying_markers_or_key_like_runs_fail_the_secret_check() {
        let c = canary();
        assert_eq!(screen_code(&c), Err(Withheld::FailedSecretCheck));
        assert_eq!(
            screen_code(&c.to_ascii_lowercase()),
            Err(Withheld::FailedSecretCheck)
        );
        let armor = format!("{}_OPENSSH_{}_KEY", "BEGIN", "PRIVATE");
        assert_eq!(screen_code(&armor), Err(Withheld::FailedSecretCheck));
        // A Heimdall ID typed as a code: a 32-hex run.
        let id = format!("op_{}", "0123456789abcdef".repeat(2));
        assert_eq!(screen_code(&id), Err(Withheld::FailedSecretCheck));
        // A random mixed-class token.
        assert_eq!(
            screen_code("aB3dE5fG7hJ9kL1mN3pQ"),
            Err(Withheld::FailedSecretCheck)
        );
    }

    /// Review M08-W0-R05: one character of every invisible or formatting class, inside an
    /// otherwise ordinary host name, makes the identifier fail. Each class is listed.
    #[test]
    fn invisible_and_format_characters_of_every_class_are_refused() {
        let classes: &[(&str, char)] = &[
            ("soft hyphen", '\u{00AD}'),
            ("combining grapheme joiner", '\u{034F}'),
            ("Arabic number sign (prepended format)", '\u{0600}'),
            ("Arabic letter mark", '\u{061C}'),
            ("Arabic end of ayah", '\u{06DD}'),
            ("Syriac abbreviation mark", '\u{070F}'),
            ("Hangul choseong filler", '\u{115F}'),
            ("Khmer inherent vowel", '\u{17B4}'),
            ("Mongolian vowel separator", '\u{180E}'),
            ("Mongolian variation selector", '\u{180B}'),
            ("zero-width space", '\u{200B}'),
            ("right-to-left mark", '\u{200F}'),
            ("line separator", '\u{2028}'),
            ("right-to-left override", '\u{202E}'),
            ("word joiner", '\u{2060}'),
            ("invisible times", '\u{2062}'),
            ("reserved U+2065", '\u{2065}'),
            ("first strong isolate", '\u{2068}'),
            ("deprecated inhibit symmetric swapping", '\u{206A}'),
            ("deprecated nominal digit shapes", '\u{206F}'),
            ("Hangul filler", '\u{3164}'),
            ("variation selector 16", '\u{FE0F}'),
            ("variation selector 1", '\u{FE00}'),
            ("byte-order mark", '\u{FEFF}'),
            ("halfwidth Hangul filler", '\u{FFA0}'),
            ("interlinear annotation anchor", '\u{FFF9}'),
            ("Egyptian hieroglyph format control", '\u{13430}'),
            ("shorthand format control", '\u{1BCA0}'),
            ("musical format control", '\u{1D173}'),
            ("language tag", '\u{E0001}'),
            ("tag letter", '\u{E0053}'),
            ("cancel tag", '\u{E007F}'),
            ("variation selector 17", '\u{E0100}'),
            ("variation selector 256", '\u{E01EF}'),
            ("C0 control", '\u{0007}'),
            ("C1 control", '\u{0085}'),
            ("delete", '\u{007F}'),
        ];
        for (name, c) in classes {
            for value in [
                format!("build{c}host"),
                format!("{c}buildhost"),
                format!("buildhost{c}"),
            ] {
                assert_eq!(
                    screen_identifier(IdentKind::Host, &value),
                    Err(Withheld::FailedSecretCheck),
                    "{name} (U+{:04X}) was accepted",
                    u32::from(*c)
                );
            }
        }
        // Visible text in other scripts, and ordinary combining marks, are not refused.
        for ok in ["b\u{00FC}ro-host", "\u{6771}\u{4EAC}-1", "cafe\u{0301}"] {
            assert_eq!(
                screen_identifier(IdentKind::Host, ok),
                Ok(()),
                "a visible name was refused"
            );
        }
    }

    #[test]
    fn ordinary_identifiers_pass_and_marked_ones_do_not() {
        for (kind, ok) in [
            (IdentKind::Host, "build-server-01.example.invalid"),
            (IdentKind::Host, "ip-172-31-5-10.us-west-2.compute.internal"),
            (IdentKind::Host, "DESKTOP-AB12CD3"),
            (IdentKind::User, "fixture.user"),
            (IdentKind::Path, "/srv/fixture/.ssh/id_ed25519_sk"),
            (
                IdentKind::Path,
                "/srv/fixture/.config/heimdall/keys/id_ed25519-cert",
            ),
            (IdentKind::Path, "/var/log/heimdall-20261122.log"),
            (
                IdentKind::Path,
                "C:\\Users\\fixture\\AppData\\Local\\Heimdall",
            ),
            (IdentKind::Path, "/srv/fixture/Application Support/state.db"),
            (IdentKind::KeyComment, "fixture@workstation"),
            (IdentKind::Label, "prod-db-1"),
        ] {
            assert!(screen_identifier(kind, ok).is_ok(), "{kind:?} {ok}");
        }
        let c = canary();
        for bad in [
            c.clone(),
            format!("/srv/{c}/x"),
            c.replace('_', "-").to_ascii_lowercase(),
            "line\nbreak".to_owned(),
            "carriage\rreturn".to_owned(),
            "tab\there".to_owned(),
            "nul\0byte".to_owned(),
            "sep\u{2028}arator".to_owned(),
            format!("{} {} {}", "-----BEGIN", "OPENSSH PRIVATE", "KEY-----"),
            format!("{} {}", "begin openssh", "private key"),
            "- - - - - begin rsa".to_owned(),
            "\u{2014}\u{2014}\u{2014}\u{2014}BEGIN".to_owned(),
            format!("{}{}", "PuTTY-User-", "Key-File-3: ssh-ed25519"),
            "aB3dE5fG7hJ9kL1mN3pQ".to_owned(),
            "0123456789abcdef0123456789abcdef".to_owned(),
            "QUJDREVGR0g=".to_owned(),
            "x".repeat(IDENT_MAX_LEN + 1),
        ] {
            assert_eq!(
                screen_identifier(IdentKind::Host, &bad),
                Err(Withheld::FailedSecretCheck),
                "case of {} bytes",
                bad.len()
            );
        }
        assert_eq!(
            screen_identifier(IdentKind::User, ""),
            Err(Withheld::Malformed)
        );
        let long_path = format!("/{}", "a/".repeat(400));
        assert!(screen_identifier(IdentKind::Path, &long_path).is_ok());
        assert!(screen_identifier(IdentKind::User, &long_path).is_err());
    }

    #[test]
    fn fingerprints_and_heimdall_ids_need_their_exact_shapes() {
        let sha = format!("SHA256:{}", "A".repeat(43));
        assert!(screen_identifier(IdentKind::Fingerprint, &sha).is_ok());
        let md5 = format!("MD5:{}", ["ab"; 16].join(":"));
        assert!(screen_identifier(IdentKind::Fingerprint, &md5).is_ok());
        for bad in [
            format!("SHA256:{}", "A".repeat(42)),
            format!("SHA256:{}=", "A".repeat(43)),
            "MD5:ab:cd".to_owned(),
            "fixture-host".to_owned(),
        ] {
            assert_eq!(
                screen_identifier(IdentKind::Fingerprint, &bad),
                Err(Withheld::Malformed)
            );
        }
        let id = format!("op_{}", "0123456789abcdef".repeat(2));
        assert!(screen_identifier(IdentKind::HeimdallId, &id).is_ok());
        for bad in [
            format!("OP_{}", "0123456789abcdef".repeat(2)),
            format!("op_{}", "0123456789ABCDEF".repeat(2)),
            "op_123".to_owned(),
            "request-7".to_owned(),
        ] {
            assert_eq!(
                screen_identifier(IdentKind::HeimdallId, &bad),
                Err(Withheld::Malformed)
            );
        }
        // A canary is a secret-check failure even where the shape check would also fail.
        assert_eq!(
            screen_identifier(IdentKind::HeimdallId, &canary()),
            Err(Withheld::FailedSecretCheck)
        );
    }

    #[test]
    fn versions_and_build_ids_have_exact_shapes() {
        for ok in ["1.0.0-rc.1", "9.9p1", "15.1", "0.1.0-m01", "1.2.3+build.7"] {
            assert!(screen_version(ok).is_ok(), "{ok}");
        }
        for bad in ["", "v1", "OpenSSH_9.9p1", "1.0 beta", "1_0"] {
            assert_eq!(screen_version(bad), Err(Withheld::Malformed), "{bad:?}");
        }
        assert!(screen_build_id("08662ad9").is_ok());
        assert!(screen_build_id(&"a".repeat(40)).is_ok());
        for bad in ["abc", "08662AD9", "g8662ad9", &"a".repeat(65)] {
            assert_eq!(screen_build_id(bad), Err(Withheld::Malformed), "{bad:?}");
        }
    }
}
