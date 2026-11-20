//! WSL distribution discovery, the pure half (ADR-0010 §2, §3 item 1; design U3 §1).
//!
//! The Windows reads live elsewhere (`heimdall_localenv::sys::lxss` reads the Lxss key;
//! [`crate::spawn`] runs `wsl.exe --list --running --quiet`); everything that interprets
//! what they return is here and runs on any host.

use std::collections::BTreeSet;

use heimdall_app::ports::{DiscoveredDistribution, RunningState};
use heimdall_contract::environment::DistributionGuid;

/// The values of one Lxss subkey the registry read returns (design §1). Everything else in
/// the key is ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LxssValues {
    /// `DistributionName` (`REG_SZ`).
    pub name: Option<String>,
    /// `Version` (`DWORD`): 1 or 2.
    pub version: Option<u32>,
    /// `DefaultUid` (`DWORD`).
    pub default_uid: Option<u32>,
    /// `State` (`DWORD`).
    pub state: Option<u32>,
}

/// A registered distribution: identity is the GUID, never the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distribution {
    /// The registration GUID: lowercase, no braces.
    pub guid: DistributionGuid,
    /// `DistributionName`.
    pub name: String,
    /// WSL version (1 or 2).
    pub version: u32,
    /// `DefaultUid`.
    pub default_uid: Option<u32>,
    /// `State`.
    pub state: Option<u32>,
}

impl From<&Distribution> for DiscoveredDistribution {
    fn from(d: &Distribution) -> Self {
        DiscoveredDistribution {
            guid: d.guid.clone(),
            name: d.name.clone(),
            version: d.version,
            default_uid: d.default_uid,
        }
    }
}

/// The canonical GUID of an Lxss subkey name (`{0B1C…}`), or `None` when it is not one.
#[must_use]
pub fn guid_of_subkey(subkey: &str) -> Option<DistributionGuid> {
    let inner = subkey.strip_prefix('{')?.strip_suffix('}')?;
    DistributionGuid::parse(&inner.to_ascii_lowercase()).ok()
}

/// One Lxss subkey as a distribution. A malformed GUID, a missing or empty name, or a
/// missing or unknown `Version` is `None`: never guessed (the caller counts it unreadable).
#[must_use]
pub fn parse_lxss_entry(subkey: &str, values: &LxssValues) -> Option<Distribution> {
    let guid = guid_of_subkey(subkey)?;
    let name = values.name.as_deref()?.trim();
    if name.is_empty() {
        return None;
    }
    let version = values.version.filter(|v| matches!(v, 1 | 2))?;
    Some(Distribution {
        guid,
        name: name.to_owned(),
        version,
        default_uid: values.default_uid,
        state: values.state,
    })
}

/// What reading the whole key gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovered {
    /// The readable distributions, in subkey order.
    pub distributions: Vec<Distribution>,
    /// Subkeys that were not distributions this build can name.
    pub unreadable: usize,
}

/// Fold the subkeys into [`Discovered`].
#[must_use]
pub fn discover_from<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a LxssValues)>,
) -> Discovered {
    let mut out = Discovered::default();
    for (subkey, values) in entries {
        match parse_lxss_entry(subkey, values) {
            Some(d) => out.distributions.push(d),
            None => out.unreadable += 1,
        }
    }
    out
}

/// The answer of selecting a distribution by the name the CLI took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection<'a> {
    /// Exactly one distribution has this name.
    One(&'a Distribution),
    /// None does.
    None,
    /// Several GUIDs share the name: refused (identity is the GUID).
    Ambiguous,
}

/// Select by exact `DistributionName`.
#[must_use]
pub fn select_by_name<'a>(list: &'a [Distribution], name: &str) -> Selection<'a> {
    let mut hits = list.iter().filter(|d| d.name == name);
    match (hits.next(), hits.next()) {
        (Some(d), None) => Selection::One(d),
        (None, _) => Selection::None,
        (Some(_), Some(_)) => Selection::Ambiguous,
    }
}

/// The running set `wsl.exe --list --running --quiet` printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunningSet {
    /// The names listed.
    Known(BTreeSet<String>),
    /// The listing failed (non-zero exit, a timeout) or its output could not be decoded.
    Unknown,
}

impl RunningSet {
    /// Whether `name` runs. Conservative: only a listed name runs, and `Unknown` runs
    /// nothing (so no helper is spawned and nothing starts in the background).
    #[must_use]
    pub fn state_of(&self, name: &str) -> RunningState {
        match self {
            RunningSet::Known(names) if names.contains(name) => RunningState::Running,
            RunningSet::Known(_) => RunningState::NotRunning,
            RunningSet::Unknown => RunningState::Unknown,
        }
    }
}

/// Decode the listing: UTF-16LE (with or without a BOM, CRLF, trailing NULs) whenever any
/// byte is NUL; UTF-8 only when there is no NUL at all. Anything else is
/// [`RunningSet::Unknown`]. The localized "no running distributions" text is never
/// interpreted: it is just a name no registration has.
#[must_use]
pub fn parse_running_list(bytes: &[u8]) -> RunningSet {
    let text = if bytes.contains(&0) {
        let body = bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes);
        // A UTF-16 stream is whole code units; a trailing odd byte is not a listing.
        if !body.len().is_multiple_of(2) {
            return RunningSet::Unknown;
        }
        let units: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        match String::from_utf16(&units) {
            Ok(s) => s,
            Err(_) => return RunningSet::Unknown,
        }
    } else {
        let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
        match std::str::from_utf8(body) {
            Ok(s) => s.to_owned(),
            Err(_) => return RunningSet::Unknown,
        }
    };
    RunningSet::Known(
        text.split('\n')
            .map(|l| l.trim_matches(|c: char| c.is_whitespace() || c == '\0' || c == '\u{feff}'))
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn values(name: &str) -> LxssValues {
        LxssValues {
            name: Some(name.to_owned()),
            version: Some(2),
            default_uid: Some(1000),
            state: Some(1),
        }
    }

    fn utf16(s: &str, bom: bool) -> Vec<u8> {
        let mut out = if bom { vec![0xFF, 0xFE] } else { Vec::new() };
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    /// `lxss_entries_parse_to_guid_identity`: the subkey becomes the canonical GUID
    /// (lowercase, no braces); a malformed GUID, a missing or empty name, and a missing
    /// version are skipped and counted, never guessed; a shared name is ambiguous.
    #[test]
    fn lxss_entries_parse_to_guid_identity() {
        let ubuntu = parse_lxss_entry("{0B1C2D3E-1111-4222-8333-ABCDEF012345}", &values("Ubuntu"))
            .expect("a distribution");
        assert_eq!(ubuntu.guid.as_str(), "0b1c2d3e-1111-4222-8333-abcdef012345");
        assert_eq!((ubuntu.name.as_str(), ubuntu.version), ("Ubuntu", 2));
        assert_eq!(ubuntu.default_uid, Some(1000));

        let no_name = LxssValues {
            name: None,
            ..values("x")
        };
        let blank = values("  ");
        let no_version = LxssValues {
            version: None,
            ..values("Debian")
        };
        let odd_version = LxssValues {
            version: Some(3),
            ..values("Debian")
        };
        let rows: [(&str, &LxssValues); 8] = [
            ("{0B1C2D3E-1111-4222-8333-ABCDEF012345}", &values("Ubuntu")),
            ("{0b1c2d3e-1111-4222-8333-abcdef012346}", &values("Ubuntu")),
            ("0b1c2d3e-1111-4222-8333-abcdef012347", &values("NoBraces")),
            ("{not-a-guid}", &values("Bad")),
            ("{0b1c2d3e-1111-4222-8333-abcdef012348}", &no_name),
            ("{0b1c2d3e-1111-4222-8333-abcdef012349}", &blank),
            ("{0b1c2d3e-1111-4222-8333-abcdef01234a}", &no_version),
            ("{0b1c2d3e-1111-4222-8333-abcdef01234b}", &odd_version),
        ];
        let found = discover_from(rows);
        assert_eq!(found.distributions.len(), 2);
        assert_eq!(found.unreadable, 6);
        // Two GUIDs share the name: ambiguous. Identity is the GUID.
        assert_eq!(
            select_by_name(&found.distributions, "Ubuntu"),
            Selection::Ambiguous
        );
        assert_eq!(
            select_by_name(&found.distributions, "ubuntu"),
            Selection::None
        );
        let one = [found.distributions[0].clone()];
        assert_eq!(select_by_name(&one, "Ubuntu"), Selection::One(&one[0]));
    }

    /// `wsl_running_list_utf16_parse`: UTF-16LE with a BOM, CRLF and trailing NULs; without
    /// a BOM; UTF-8 only when no NUL; undecodable output is `Unknown`, which runs nothing.
    #[test]
    fn wsl_running_list_utf16_parse() {
        let expect =
            |names: &[&str]| RunningSet::Known(names.iter().map(|s| (*s).to_owned()).collect());
        let mut with_bom = utf16("Ubuntu\r\nDebian GNU\r\n\r\n", true);
        with_bom.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            parse_running_list(&with_bom),
            expect(&["Ubuntu", "Debian GNU"])
        );
        assert_eq!(
            parse_running_list(&utf16("Ubuntu\n", false)),
            expect(&["Ubuntu"])
        );
        assert_eq!(
            parse_running_list(b"Ubuntu\r\nAlpine\r\n"),
            expect(&["Ubuntu", "Alpine"])
        );
        assert_eq!(parse_running_list(b""), expect(&[]));
        // A lone surrogate, an odd trailing byte, and invalid UTF-8 are not a listing.
        assert_eq!(
            parse_running_list(&[0x00, 0xD8, 0x41, 0x00]),
            RunningSet::Unknown
        );
        assert_eq!(parse_running_list(&[0x55, 0x00, 0x62]), RunningSet::Unknown);
        assert_eq!(parse_running_list(&[0xFF, 0xC3, 0x28]), RunningSet::Unknown);

        let set = parse_running_list(&utf16("Ubuntu\r\n", true));
        assert_eq!(set.state_of("Ubuntu"), RunningState::Running);
        assert_eq!(set.state_of("Debian"), RunningState::NotRunning);
        assert_eq!(
            RunningSet::Unknown.state_of("Ubuntu"),
            RunningState::Unknown
        );
    }
}
