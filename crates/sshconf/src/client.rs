//! What each supported OpenSSH client was observed to do, and the version gates the
//! evaluator reads from it (ADR-0007 §12.15 item 4, §12.32 items 11 and 12).
//!
//! The pinned manual (S01, OpenBSD-current) describes the newest client. An older
//! client may refuse a construct the manual documents, or take literally what the
//! manual says it expands. Such a difference is a defect fixed by gating on the client
//! version (§12.15 item 4). **The boundaries come from the corpus test
//! (`integration_sshconf_vs_ssh_g`) run on each client, never from release notes or
//! memory** (§12.32 item 11): a client in [`OBSERVED_CLIENTS`] answers with what it
//! was seen to do, and a version the observations do not settle takes the strictest
//! reading. An unknown version is passed as [`OpenSshVersion::MINIMUM`] (the callers'
//! fallback), which no observation names, so it is strict too.
//!
//! The strictest reading differs per gate (ADR-0007 §12.35 item 1 amends "strictest"):
//!
//! * a gate of the first kind, where a construct is refused or accepted, takes the
//!   reading that **refuses**: a `Match` criterion or a keyword that some observed
//!   client refuses is refused ([`accepts_match_criterion`], [`knows_keyword`]) unless
//!   the version is at least the lowest one observed to accept it. A refused construct
//!   makes the file invalid for that client: the evaluator records the line in
//!   `Evaluation::invalid` and decides nothing from it (§12.32 item 11 (a));
//! * a gate of the second kind, where the two behaviours give **different results**,
//!   makes the affected value **undetermined**, never one of the two readings:
//!   `${VAR}` and the `%` tokens in `User`, `SetEnv` and `Include`. A client observed
//!   to take them literally ([`expands_env`], [`expands_tokens`] are `false`) or to
//!   expand them has an established answer, and the value is determined as that client
//!   reads it. For any client whose behaviour the observations do not settle
//!   ([`behaviour_unknown`]: a version not in [`OBSERVED_CLIENTS`], and a version whose
//!   row records nothing for that fact), the evaluator reads the expanding reading but
//!   records the argument as unresolved (reason `client_behaviour_unknown`) and adds an
//!   opaque point for an `Include`, or makes the `User` or `SetEnv` value undetermined
//!   (§12.35 item 1). Picking either reading would be unsound: expanding `%h` selects a
//!   different file than the literal reading, not a stricter one.
//!
//! **Default identities** (§12.32 item 12, amending §12.17 item 9).
//! [`DEFAULT_IDENTITIES`] is the union of every observed client's list and the pinned
//! manuals' list, so an unknown default key can never be offered behind Heimdall's
//! back. The per-client lists stay here as data ([`ObservedClient::default_identities`],
//! [`MANUAL_DEFAULT_IDENTITIES`]) for the compatibility matrix to cite.

use crate::directive::{self, KnownKeyword};
use crate::eval::OpenSshVersion;
use crate::include::Expansion;

/// One client the corpus test (or a recorded `ssh -G` run) was seen on, and what it
/// did. `None` in a field means "not recorded for this client": the gate then does not
/// use this client for that fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedClient {
    /// Where it was observed (no host or user names).
    pub label: &'static str,
    /// The exact version `ssh -V` printed.
    pub version: OpenSshVersion,
    /// Whether `Match command`, `Match sessiontype` and `Match version` load
    /// ([`GATED_MATCH_CRITERIA`], in that order); `None` when not recorded.
    pub match_criteria: [Option<bool>; 3],
    /// Whether `RefuseConnection`, `VersionAddendum` and `WarnWeakCrypto` are known
    /// keywords ([`GATED_KEYWORDS`], in that order); `None` when not recorded.
    pub keywords: [Option<bool>; 3],
    /// Whether `${VAR}` in `User`, `SetEnv` and `Include` is expanded.
    pub env_in_user_setenv_include: Option<bool>,
    /// Whether `%` tokens (and `%%`) in `User`, `SetEnv` and `Include` are expanded.
    pub tokens_in_user_setenv_include: Option<bool>,
    /// The default identity files `ssh -G` printed with no `IdentityFile` configured,
    /// as names under `~/.ssh`, in its order; empty when not recorded.
    pub default_identities: &'static [&'static str],
    /// The evidence the row comes from.
    pub evidence: &'static str,
}

const fn v(major: u16, minor: u16, portable: u16) -> OpenSshVersion {
    OpenSshVersion {
        major,
        minor,
        portable: Some(portable),
    }
}

/// The `Match` criteria the observations gate, in [`ObservedClient::match_criteria`]
/// order.
pub const GATED_MATCH_CRITERIA: [&str; 3] = ["command", "sessiontype", "version"];

/// The keywords the observations gate, in [`ObservedClient::keywords`] order: the
/// pinned table's keywords that an observed client does not know ("Bad configuration
/// option").
pub const GATED_KEYWORDS: [KnownKeyword; 3] = [
    KnownKeyword::RefuseConnection,
    KnownKeyword::VersionAddendum,
    KnownKeyword::WarnWeakCrypto,
];

/// The keywords whose `${VAR}` and `%` expansion is gated on the version: the ones
/// OpenSSH 9.6p1 takes literally although S01 says they expand.
pub const GATED_EXPANSION_KEYWORDS: [KnownKeyword; 3] = [
    KnownKeyword::User,
    KnownKeyword::SetEnv,
    KnownKeyword::Include,
];

/// Every client observed so far.
///
/// * macOS `OpenSSH_10.3p1` (M02 waves 1-2b): the wave-1 code review's `ssh -G` run
///   loaded `Match sessiontype` (`tests/evidence/artifacts/review-m02-code/wave1.md`,
///   Y04); the corpus test's S01 environment check passed on it in the wave-2b review
///   run (`wave2bc.md`), so `User`, `SetEnv` and `Include` expanded `${VAR}`; its
///   default identity list had five names (ADR-0007 §12.17 item 9, U3 E7).
/// * macOS `OpenSSH_10.5p1` and the Linux devbox's `OpenSSH_9.6p1` (Ubuntu
///   `3ubuntu13.20`): the same inert configurations through `ssh -G -F <scratch>` on
///   both, 2026-11-06 (`tests/evidence/artifacts/m02/sshconf-9.6p1/`).
pub const OBSERVED_CLIENTS: &[ObservedClient] = &[
    ObservedClient {
        label: "macOS build host, system client",
        version: v(10, 3, 1),
        match_criteria: [None, Some(true), None],
        keywords: [None, None, None],
        env_in_user_setenv_include: Some(true),
        tokens_in_user_setenv_include: None,
        default_identities: &[
            "id_rsa",
            "id_ecdsa",
            "id_ecdsa_sk",
            "id_ed25519",
            "id_ed25519_sk",
        ],
        evidence: "tests/evidence/artifacts/review-m02-code/wave1.md (Y04), wave2bc.md; ADR-0007 §12.17 item 9",
    },
    ObservedClient {
        label: "macOS build host, system client",
        version: v(10, 5, 1),
        match_criteria: [Some(true), Some(true), Some(true)],
        keywords: [Some(true), Some(true), Some(true)],
        env_in_user_setenv_include: Some(true),
        tokens_in_user_setenv_include: Some(true),
        default_identities: &[
            "id_rsa",
            "id_ecdsa",
            "id_ecdsa_sk",
            "id_ed25519",
            "id_ed25519_sk",
            "id_mldsa44_ed25519",
        ],
        evidence: "tests/evidence/artifacts/m02/sshconf-9.6p1/ssh-g-10.5p1.txt",
    },
    ObservedClient {
        label: "Linux devbox, Ubuntu OpenSSH 9.6p1",
        version: v(9, 6, 1),
        match_criteria: [Some(false), Some(false), Some(false)],
        keywords: [Some(false), Some(false), Some(false)],
        env_in_user_setenv_include: Some(false),
        tokens_in_user_setenv_include: Some(false),
        default_identities: &[
            "id_rsa",
            "id_ecdsa",
            "id_ecdsa_sk",
            "id_ed25519",
            "id_ed25519_sk",
            "id_xmss",
            "id_dsa",
        ],
        evidence: "tests/evidence/artifacts/m02/sshconf-9.6p1/ssh-g-9.6p1.txt",
    },
];

/// The default identity files the pinned manuals list: S01's `IdentityFile` entry and
/// S02's `-i` option (OpenBSD-current, `docs/sources/pins.json`), names under
/// `~/.ssh`.
pub const MANUAL_DEFAULT_IDENTITIES: &[&str] = &[
    "id_rsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    "id_mldsa44_ed25519",
];

/// The default identity files under `~/.ssh` the evaluator considers (F20): the union
/// of [`MANUAL_DEFAULT_IDENTITIES`] and every [`ObservedClient::default_identities`]
/// (ADR-0007 §12.32 item 12), the manual's names first, then the others in the order
/// the clients print them. A test checks the union is exact.
pub const DEFAULT_IDENTITIES: &[&str] = &[
    "id_rsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    "id_mldsa44_ed25519",
    "id_xmss",
    "id_dsa",
];

/// The observation of exactly this version, if any.
#[must_use]
pub fn observed(version: OpenSshVersion) -> Option<&'static ObservedClient> {
    OBSERVED_CLIENTS.iter().find(|c| c.version == version)
}

/// The lowest observed version for which `fact` is `Some(true)`.
fn lowest_accepting(fact: impl Fn(&ObservedClient) -> Option<bool>) -> Option<OpenSshVersion> {
    OBSERVED_CLIENTS
        .iter()
        .filter(|c| fact(c) == Some(true))
        .map(|c| c.version)
        .min()
}

/// Accepted from the lowest version observed to accept, and refused below it or with
/// no accepting observation; an exact observation always answers for its own version.
fn accepted_from(version: OpenSshVersion, fact: impl Fn(&ObservedClient) -> Option<bool>) -> bool {
    if let Some(answer) = observed(version).and_then(&fact) {
        return answer;
    }
    lowest_accepting(fact).is_some_and(|low| version >= low)
}

/// Whether a client of `version` loads a `Match` line with `criterion` (lower case, no
/// `!`). The criteria of [`GATED_MATCH_CRITERIA`] are refused by OpenSSH 9.6p1
/// ("Unsupported Match attribute", the file is refused); each is accepted from the
/// lowest version observed to load it and refused otherwise (§12.32 item 11 (a): an
/// unknown version takes the strictest reading). Every other criterion is accepted.
#[must_use]
pub fn accepts_match_criterion(criterion: &str, version: OpenSshVersion) -> bool {
    match GATED_MATCH_CRITERIA.iter().position(|c| *c == criterion) {
        Some(i) => accepted_from(version, |c| c.match_criteria[i]),
        None => true,
    }
}

/// Whether a client of `version` knows `keyword`. The keywords of [`GATED_KEYWORDS`]
/// are unknown to OpenSSH 9.6p1 ("Bad configuration option"); each is known from the
/// lowest version observed to know it and unknown otherwise. Every other keyword of
/// the pinned table is known.
#[must_use]
pub fn knows_keyword(keyword: KnownKeyword, version: OpenSshVersion) -> bool {
    match GATED_KEYWORDS.iter().position(|k| *k == keyword) {
        Some(i) => accepted_from(version, |c| c.keywords[i]),
        None => true,
    }
}

/// The recorded `${VAR}` behaviour of exactly this version for `User`, `SetEnv` and
/// `Include`: `Some(true)` expands, `Some(false)` literal, `None` not established.
fn env_fact(version: OpenSshVersion) -> Option<bool> {
    observed(version).and_then(|c| c.env_in_user_setenv_include)
}

/// The recorded `%` token behaviour of exactly this version for `User`, `SetEnv` and
/// `Include` (as [`env_fact`]).
fn tokens_fact(version: OpenSshVersion) -> Option<bool> {
    observed(version).and_then(|c| c.tokens_in_user_setenv_include)
}

/// Whether a client of `version` expands `${VAR}` in `keyword`'s arguments: the pinned
/// set ([`directive::expands_env`]), except that `User`, `SetEnv` and `Include` are
/// literal for a version observed to take them literally (OpenSSH 9.6p1). Any other
/// version, an unknown one included, is **read** as expanding: the reading the
/// evaluator walks, under which a value that reads the environment is undetermined
/// (§12.32 item 11 (b)). Whether the version settles that answer is
/// [`behaviour_unknown`].
#[must_use]
pub fn expands_env(keyword: KnownKeyword, version: OpenSshVersion) -> bool {
    if !directive::expands_env(keyword) {
        return false;
    }
    !(GATED_EXPANSION_KEYWORDS.contains(&keyword) && env_fact(version) == Some(false))
}

/// Whether a client of `version` expands `%` tokens (and `%%`) in `keyword`'s
/// arguments: the pinned set ([`directive::expands_tokens`]), except that `User`,
/// `SetEnv` and `Include` are literal for a version observed to take them literally
/// (OpenSSH 9.6p1). Any other version is **read** as expanding, as every observed
/// expanding client does; that is the reading the evaluator walks, not a claim that
/// the client does so. Whether the version settles the answer is [`behaviour_unknown`].
#[must_use]
pub fn expands_tokens(keyword: KnownKeyword, version: OpenSshVersion) -> bool {
    if !directive::expands_tokens(keyword) {
        return false;
    }
    !(GATED_EXPANSION_KEYWORDS.contains(&keyword) && tokens_fact(version) == Some(false))
}

/// Whether `text` holds a construct whose result depends on whether the client expands
/// it: any `%` (a token, `%%`, or one a client refuses) or a well-formed `${…}`.
fn has_expandable(text: &str, tokens: bool, env: bool) -> bool {
    (tokens && text.contains('%')) || (env && !crate::eval::env_names(text).is_empty())
}

/// Whether the observations leave open how a client of `version` reads `args` as
/// `keyword`'s arguments, so that the two possible readings give different results
/// (ADR-0007 §12.35 item 1).
///
/// True only for `User`, `SetEnv` and `Include` (the keywords of
/// [`GATED_EXPANSION_KEYWORDS`]), only when an argument holds `%` or `${…}`, and only
/// for the fact the version's row does not record: a version not in
/// [`OBSERVED_CLIENTS`] settles neither, and a row with `None` for one fact settles the
/// other only. A construct without either expansion reads the same on every client,
/// and a keyword outside the gated set is read as the manual says on every client.
///
/// The evaluator reads the expanding reading ([`expands_env`], [`expands_tokens`]) and,
/// when this is true, makes the value undetermined: an `Include` argument is recorded
/// as unresolved with reason `client_behaviour_unknown` and adds an opaque point, and a
/// `User` or `SetEnv` value applies under an unknown condition.
#[must_use]
pub fn behaviour_unknown<'a>(
    keyword: KnownKeyword,
    args: impl IntoIterator<Item = &'a str>,
    version: OpenSshVersion,
) -> bool {
    if !GATED_EXPANSION_KEYWORDS.contains(&keyword) {
        return false;
    }
    let tokens = directive::expands_tokens(keyword) && tokens_fact(version).is_none();
    let env = directive::expands_env(keyword) && env_fact(version).is_none();
    (tokens || env) && args.into_iter().any(|a| has_expandable(a, tokens, env))
}

/// The expansions a client of `version` is **read** as applying to an `Include`
/// argument ([`expands_env`] and [`expands_tokens`] for `Include`): the files the walk
/// opens. For a version whose behaviour is not established the walk still opens the
/// expanded path, and the evaluator marks the argument undetermined
/// ([`behaviour_unknown`]) because the client may read the literal path instead.
#[must_use]
pub fn include_expansion(version: OpenSshVersion) -> Expansion {
    Expansion {
        env: expands_env(KnownKeyword::Include, version),
        tokens: expands_tokens(KnownKeyword::Include, version),
    }
}

/// The default identity list this exact client printed, when it was recorded.
#[must_use]
pub fn default_identities_of(version: OpenSshVersion) -> Option<&'static [&'static str]> {
    observed(version)
        .map(|c| c.default_identities)
        .filter(|l| !l.is_empty())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const MINIMUM: OpenSshVersion = OpenSshVersion::MINIMUM;

    /// §12.32 item 12: the evaluator's list is exactly the union of the per-client
    /// lists and the manuals', with no name twice.
    #[test]
    fn default_identities_are_exactly_the_union_of_clients_and_manuals() {
        let mut union: Vec<&str> = Vec::new();
        for name in MANUAL_DEFAULT_IDENTITIES
            .iter()
            .chain(OBSERVED_CLIENTS.iter().flat_map(|c| c.default_identities))
        {
            if !union.contains(name) {
                union.push(name);
            }
        }
        assert_eq!(DEFAULT_IDENTITIES, union.as_slice());
        for c in OBSERVED_CLIENTS {
            for name in c.default_identities {
                assert!(DEFAULT_IDENTITIES.contains(name), "{}: {name}", c.label);
            }
        }
        assert!(DEFAULT_IDENTITIES.contains(&"id_xmss"));
        assert!(DEFAULT_IDENTITIES.contains(&"id_dsa"));
        assert!(DEFAULT_IDENTITIES.contains(&"id_mldsa44_ed25519"));
    }

    #[test]
    fn observations_are_unique_per_version() {
        for (i, a) in OBSERVED_CLIENTS.iter().enumerate() {
            for b in &OBSERVED_CLIENTS[i + 1..] {
                assert_ne!(a.version, b.version);
            }
        }
    }

    /// §12.32 item 11 (a), both sides of the boundary: refused on 9.6p1, accepted on
    /// the lowest accepting observation and above, refused between and below, and for
    /// the unknown version.
    #[test]
    fn match_criteria_follow_the_observed_boundary() {
        for c in GATED_MATCH_CRITERIA {
            assert!(!accepts_match_criterion(c, v(9, 6, 1)), "{c}");
            assert!(accepts_match_criterion(c, v(10, 5, 1)), "{c}");
            assert!(accepts_match_criterion(c, v(11, 0, 1)), "{c}");
            assert!(!accepts_match_criterion(c, v(9, 5, 2)), "{c}");
            assert!(!accepts_match_criterion(c, v(10, 0, 1)), "{c}");
            assert!(
                !accepts_match_criterion(c, MINIMUM),
                "{c}: unknown is strict"
            );
        }
        // Observed on 10.3p1 (wave-1 review): sessiontype only.
        assert!(accepts_match_criterion("sessiontype", v(10, 3, 1)));
        assert!(!accepts_match_criterion("command", v(10, 3, 1)));
        assert!(!accepts_match_criterion("version", v(10, 3, 1)));
        for c in [
            "all",
            "host",
            "originalhost",
            "user",
            "localuser",
            "localnetwork",
        ] {
            assert!(accepts_match_criterion(c, v(9, 6, 1)), "{c}");
            assert!(accepts_match_criterion(c, MINIMUM), "{c}");
        }
        for c in ["tagged", "canonical", "final", "exec"] {
            assert!(accepts_match_criterion(c, v(9, 6, 1)), "{c}");
        }
    }

    #[test]
    fn keywords_follow_the_observed_boundary() {
        for k in GATED_KEYWORDS {
            assert!(!knows_keyword(k, v(9, 6, 1)), "{k:?}");
            assert!(knows_keyword(k, v(10, 5, 1)), "{k:?}");
            assert!(!knows_keyword(k, v(10, 3, 1)), "{k:?}: not recorded there");
            assert!(!knows_keyword(k, MINIMUM), "{k:?}: unknown is strict");
        }
        for k in [
            KnownKeyword::SessionType,
            KnownKeyword::Tag,
            KnownKeyword::Port,
        ] {
            assert!(knows_keyword(k, v(9, 6, 1)), "{k:?}");
            assert!(knows_keyword(k, MINIMUM), "{k:?}");
        }
    }

    /// §12.32 item 11 (b), both sides: literal only for the version observed to take
    /// them literally; every other version (between the observations, below, the
    /// unknown one) expands.
    #[test]
    fn expansion_is_literal_only_where_observed() {
        for k in GATED_EXPANSION_KEYWORDS {
            assert!(!expands_env(k, v(9, 6, 1)), "{k:?}");
            assert!(!expands_tokens(k, v(9, 6, 1)), "{k:?}");
            for version in [
                v(10, 3, 1),
                v(10, 5, 1),
                v(9, 5, 2),
                v(9, 7, 1),
                v(9, 6, 2),
                MINIMUM,
            ] {
                assert!(expands_env(k, version), "{k:?} {version:?}");
            }
            assert!(expands_tokens(k, v(10, 5, 1)), "{k:?}");
            assert!(expands_tokens(k, MINIMUM), "{k:?}");
        }
        // The other S01 keywords are not gated.
        for k in [
            KnownKeyword::IdentityAgent,
            KnownKeyword::ControlPath,
            KnownKeyword::RevokedHostKeys,
            KnownKeyword::LocalForward,
        ] {
            assert!(expands_env(k, v(9, 6, 1)), "{k:?}");
        }
        assert!(!expands_env(KnownKeyword::Port, v(10, 5, 1)));
    }

    /// §12.35 item 1: the behaviour is unknown exactly where the observations do not
    /// settle the fact for the construct the argument holds. Each side of every
    /// boundary: observed expanding and observed literal are settled; a version between
    /// the observations, below them, and the unknown one are not; a row that records
    /// one fact settles that fact only.
    #[test]
    fn behaviour_is_unknown_only_where_the_observations_do_not_settle_it() {
        let unobserved = [v(9, 5, 2), v(9, 7, 1), v(9, 6, 2), v(10, 0, 1), v(11, 0, 1)];
        for k in GATED_EXPANSION_KEYWORDS {
            for arg in ["a%hb", "%%", "%", "a${V}b"] {
                for settled in [v(9, 6, 1), v(10, 5, 1)] {
                    assert!(
                        !behaviour_unknown(k, [arg], settled),
                        "{k:?} {arg} {settled:?}"
                    );
                }
                for version in unobserved.into_iter().chain([MINIMUM]) {
                    assert!(
                        behaviour_unknown(k, [arg], version),
                        "{k:?} {arg} {version:?}"
                    );
                }
            }
            // 10.3p1 records `${VAR}` (expanding) and nothing for `%`.
            assert!(!behaviour_unknown(k, ["a${V}b"], v(10, 3, 1)), "{k:?}");
            assert!(behaviour_unknown(k, ["a%hb"], v(10, 3, 1)), "{k:?}");
            assert!(
                behaviour_unknown(k, ["a${V}b", "x"], MINIMUM),
                "{k:?}: any argument"
            );
            // No expandable construct: every client reads it the same way.
            for arg in ["plain", "a$b", "a{b}", "${", "a${b"] {
                for version in [v(9, 6, 1), v(10, 5, 1), v(10, 3, 1), MINIMUM] {
                    assert!(!behaviour_unknown(k, [arg], version), "{k:?} {arg}");
                }
            }
            assert!(!behaviour_unknown(k, [], MINIMUM));
        }
        // A keyword outside the gated set is read as the manual says on every client.
        for k in [
            KnownKeyword::IdentityFile,
            KnownKeyword::IdentityAgent,
            KnownKeyword::Port,
        ] {
            assert!(!behaviour_unknown(k, ["a%hb${V}"], MINIMUM), "{k:?}");
        }
    }

    #[test]
    fn default_identities_per_client_are_kept_as_data() {
        assert_eq!(default_identities_of(v(9, 6, 1)).map(<[_]>::len), Some(7));
        assert_eq!(default_identities_of(v(10, 5, 1)).map(<[_]>::len), Some(6));
        assert_eq!(default_identities_of(v(10, 3, 1)).map(<[_]>::len), Some(5));
        assert_eq!(default_identities_of(MINIMUM), None);
    }
}
