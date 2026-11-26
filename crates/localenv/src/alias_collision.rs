//! ⟨M08 U1b; U0-Q10, ruled 2026-11-24⟩ A user `Host` line that names a managed alias.
//!
//! The passive doctor's finding `alias_collision` and setup's conflict `alias_collision`
//! (`ConflictKind::AliasCollision`, reported in the plan) both come from [`user_host_lines`]:
//! every `Host` line, in the user's configuration or a file it includes, one of whose patterns
//! is a managed alias as an **exact literal, compared without ASCII case**.
//!
//! * **What is read:** the files of the user tree as the static include walk reads them
//!   (`heimdall_sshconf::include::record`): the user file and every file it includes, at any
//!   depth, whatever section the `Include` sits in. The managed file P (Heimdall's own `Host`
//!   sections, [`SourceRole::Managed`]) and the system tree are never compared.
//! * **What is compared:** each pattern of a `Host` line with no `*`, `?` or `!` in it, against
//!   each managed alias, with `eq_ignore_ascii_case`. The rule is Heimdall's own: its renderer
//!   refuses case-variant aliases (`sshconf::render`, `DuplicateAlias`), so the catalog keeps
//!   aliases unique without case (U0-Q9). It is not a statement about how `ssh` matches
//!   `Host` patterns; no reading here claims one.
//! * **Limitations (1.0, stated):** a wildcard or negated pattern (`Host *`, `Host lab*`,
//!   `Host !lab`) and every `Match` line are out of scope, even when they apply to a managed
//!   alias. What such a section adds to a managed alias's identity is reported by the identity
//!   selection findings (`identity_selection_not_exclusive`) and weighed by setup's consent
//!   (ADR-0007 §5.2), not here. A file the walk could not read is not compared (its failure
//!   is its own finding).
//!
//! Pure over the walk's [`ConfigSet`] and [`WalkRecord`]: nothing is read here.

use std::collections::BTreeSet;
use std::path::PathBuf;

use heimdall_sshconf::directive::{Keyword, KnownKeyword};
use heimdall_sshconf::include::{ConfigSet, Origin, SourceRole, WalkRecord};
use heimdall_sshconf::parse::{Line, Span};

/// One user `Host` line naming a managed alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserHostLine {
    /// The managed alias, as the catalog (or the plan's spec) holds it.
    pub alias: String,
    /// The canonical path of the file the line is in.
    pub canonical: PathBuf,
    /// The line.
    pub span: Span,
}

/// Whether `pattern` is an exact literal (no `*`, `?` or `!`; module docs).
#[must_use]
pub fn is_literal(pattern: &str) -> bool {
    !pattern.is_empty() && !pattern.contains(['*', '?', '!'])
}

/// Every user `Host` line of the walk that names one of `managed` (module docs), each line
/// once per alias it names, in reading order. A file the walk read twice is compared once.
#[must_use]
pub fn user_host_lines(
    set: &ConfigSet,
    record: &WalkRecord,
    managed: &[&str],
) -> Vec<UserHostLine> {
    let mut out = Vec::new();
    if managed.is_empty() {
        return out;
    }
    let mut seen = BTreeSet::new();
    for visit in &record.visits {
        if visit.origin != Origin::User
            || visit.role == SourceRole::Managed
            || !seen.insert(visit.canonical.clone())
        {
            continue;
        }
        let Some(file) = set.file(visit.source) else {
            continue;
        };
        for line in &file.lines {
            let Line::Directive(dir) = line else {
                continue;
            };
            if !matches!(dir.keyword, Keyword::Known(KnownKeyword::Host)) {
                continue;
            }
            for alias in managed {
                if dir
                    .args
                    .iter()
                    .any(|p| is_literal(p) && p.eq_ignore_ascii_case(alias))
                {
                    out.push(UserHostLine {
                        alias: (*alias).to_owned(),
                        canonical: visit.canonical.clone(),
                        span: dir.span,
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use heimdall_sshconf::include::{self, MemSource, Roots};
    use heimdall_sshconf::limits::Limits;

    use super::*;

    const USER: &str = "/hm/home/.ssh/config";
    const P: &str = "/hm/heimdall/config/ssh_config";
    const SYSTEM: &str = "/hm/etc/ssh/ssh_config";

    fn lines(user: &str, files: &[(&str, &str)], managed: &[&str]) -> Vec<(String, String, u32)> {
        let mut src = MemSource::new("/hm/home", "/hm/home/.ssh", "/hm/etc/ssh")
            .with_file(USER, user.as_bytes().to_vec())
            .with_file(
                P,
                b"Host alpha\n    HostName alpha.example.invalid\n".to_vec(),
            )
            .with_file(SYSTEM, b"Host alpha beta\n    Port 2222\n".to_vec());
        for (path, text) in files {
            src = src.with_file(path, text.as_bytes().to_vec());
        }
        let roots = Roots::new(Some(PathBuf::from(USER)), Some(PathBuf::from(SYSTEM)))
            .with_managed(PathBuf::from(P));
        let mut set = ConfigSet::new();
        let record = include::record(&mut set, &src, &roots, &Limits::default(), &|_| None);
        user_host_lines(&set, &record, managed)
            .into_iter()
            .map(|l| {
                (
                    l.alias,
                    l.canonical.to_string_lossy().into_owned(),
                    l.span.line,
                )
            })
            .collect()
    }

    /// A literal, compared without ASCII case, in the user file or an included file at any
    /// depth; each alias a line names once; P and the system tree never.
    #[test]
    fn a_literal_user_host_line_names_a_managed_alias_case_insensitively() {
        let user = format!(
            "Include {P}\nInclude /hm/home/.ssh/conf.d/*.conf\nHost other\n    User x\nHost ALPHA other\n    Port 2\n"
        );
        let found = lines(
            &user,
            &[
                (
                    "/hm/home/.ssh/conf.d/a.conf",
                    "Include /hm/home/.ssh/deep.conf\nHost Beta\n",
                ),
                ("/hm/home/.ssh/deep.conf", "Host gamma alpha\n"),
            ],
            &["alpha", "beta"],
        );
        let mut sorted = found.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                ("alpha".to_owned(), "/hm/home/.ssh/config".to_owned(), 5),
                ("alpha".to_owned(), "/hm/home/.ssh/deep.conf".to_owned(), 1),
                (
                    "beta".to_owned(),
                    "/hm/home/.ssh/conf.d/a.conf".to_owned(),
                    2
                ),
            ],
            "{found:?}"
        );
    }

    /// Wildcards, negations, `Match` lines and other aliases are out of scope (module docs).
    #[test]
    fn wildcards_negations_and_match_lines_are_not_compared() {
        let user = "Host *\n    User x\nHost alph?\nHost alpha*\nHost !alpha\nMatch host alpha\n    Port 2\nHost alphabet\n";
        assert!(lines(user, &[], &["alpha"]).is_empty());
        assert!(
            lines("Host alpha\n", &[], &[]).is_empty(),
            "no managed alias"
        );
        assert!(is_literal("lab") && !is_literal("") && !is_literal("l*b"));
    }
}
