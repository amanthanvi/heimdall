//! Configuration-tree snapshots around a level (m02-plan U3; M2-S04).
//!
//! [`take`] runs once with the static pass and once after the level. A snapshot holds
//! every `Include`'s expansion result and every reached file's display path and
//! digest, so a new glob member is detected. `config_tree_changed` is
//! `!compare(..).is_empty()`; `false` means only that the two snapshots are equal (a
//! change reverted in between is not detected).
//!
//! The walk is `heimdall_sshconf::include::record` over a fresh `ConfigSet`, so it
//! re-expands every `Include` (globs, `~`, tokens, `${VAR}`) under the same bounds as
//! the static pass, and reads every file again. The digests come from a wrapper around
//! the source that hashes each read's bytes; a file that could not be walked has no
//! digest. Tokens: `%h` and `%n` are the query's host, `%u` its local user, `%r` its
//! user when given, `%d` the account home; any other token is unavailable, so its
//! include is `Unresolved` in both snapshots alike.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use heimdall_contract::doctor::{ConfigTreeDifference, MAX_CONFIG_TREE_DIFFERENCES, TreeChange};
use heimdall_sshconf::eval::Query;
use heimdall_sshconf::include::{
    self, ArgError, ConfigSet, ConfigSource, Roots, SourceBytes, SourceError,
};
use heimdall_sshconf::limits::Limits;
use sha2::{Digest, Sha256};

use crate::clients::hex;
use crate::paths::display_path;

/// How one `Include` expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncludeExpansion {
    /// The glob's matches, in order (display form).
    Matches(Vec<String>),
    /// The resolved path of a literal include (display form).
    Resolved(String),
    /// Why it could not resolve (a stable reason).
    Unresolved(String),
}

/// One reached file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachedFile {
    /// Display path.
    pub path_display: String,
    /// SHA-256, or `None` when unreadable.
    pub sha256: Option<String>,
}

/// The tree as one walk saw it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreeSnapshot {
    /// Every include, in walk order, with its expansion.
    pub includes: Vec<(String, IncludeExpansion)>,
    /// Every reached file.
    pub files: Vec<ReachedFile>,
}

/// A source wrapper that remembers the digest and size of every successful read,
/// by requested and canonical path.
pub(crate) struct Digesting<'a> {
    inner: &'a dyn ConfigSource,
    digests: RefCell<BTreeMap<PathBuf, (String, u64)>>,
}

impl<'a> Digesting<'a> {
    pub(crate) fn new(inner: &'a dyn ConfigSource) -> Self {
        Self {
            inner,
            digests: RefCell::new(BTreeMap::new()),
        }
    }

    pub(crate) fn into_digests(self) -> BTreeMap<PathBuf, (String, u64)> {
        self.digests.into_inner()
    }
}

impl ConfigSource for Digesting<'_> {
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError> {
        let got = self.inner.read(path)?;
        let digest = hex(&Sha256::digest(&got.bytes));
        let len = u64::try_from(got.bytes.len()).unwrap_or(u64::MAX);
        let mut map = self.digests.borrow_mut();
        map.insert(path.to_path_buf(), (digest.clone(), len));
        map.insert(got.canonical.clone(), (digest, len));
        Ok(got)
    }

    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        self.inner.glob(pattern)
    }

    fn account_home(&self) -> &Path {
        self.inner.account_home()
    }

    fn user_dir(&self) -> &Path {
        self.inner.user_dir()
    }

    fn system_dir(&self) -> &Path {
        self.inner.system_dir()
    }

    fn env(&self, name: &str) -> Option<String> {
        self.inner.env(name)
    }
}

fn has_glob_meta(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

fn arg_reason(e: &ArgError) -> String {
    match e {
        ArgError::EnvUnset(_) => "env_unset".to_owned(),
        ArgError::TokenUnavailable(_) => "token_unavailable".to_owned(),
        ArgError::Invalid(i) => i.as_str().to_owned(),
        ArgError::Glob(g) if g.is_bound() => "bound_exceeded".to_owned(),
        ArgError::Glob(_) => "glob_unreadable".to_owned(),
        _ => "unresolved".to_owned(),
    }
}

/// Walk the tree for `query` and record it.
#[must_use]
pub fn take(
    source: &dyn ConfigSource,
    roots: &Roots,
    query: &Query,
    limits: &Limits,
) -> TreeSnapshot {
    let digesting = Digesting::new(source);
    let home = source.account_home().to_path_buf();
    let host = query.host.clone();
    let local_user = query.local_user.clone();
    let user = query.user.clone();
    let tokens = move |t: char| -> Option<String> {
        match t {
            'h' | 'n' => Some(host.clone()),
            'u' => Some(local_user.clone()),
            'r' => user.clone(),
            _ => None,
        }
    };
    let mut set = ConfigSet::new();
    let record = include::record(&mut set, &digesting, roots, limits, &tokens);
    let display = |p: &Path| display_path(&home, p);
    let digests = digesting.into_digests();
    let mut snapshot = TreeSnapshot::default();
    for inc in &record.includes {
        let file = set
            .path_of(inc.span.source)
            .map_or_else(|| "?".to_owned(), display);
        let key = format!("{file}:{}: {}", inc.span.line, inc.arg.written);
        let expansion = match (&inc.arg.pattern, &inc.arg.matches) {
            (_, Err(e)) => IncludeExpansion::Unresolved(arg_reason(e)),
            (Some(pattern), Ok(matches)) => {
                if has_glob_meta(&pattern.to_string_lossy()) {
                    IncludeExpansion::Matches(matches.iter().map(|m| display(m)).collect())
                } else {
                    IncludeExpansion::Resolved(display(pattern))
                }
            }
            (None, Ok(_)) => IncludeExpansion::Unresolved("unresolved".to_owned()),
        };
        snapshot.includes.push((key, expansion));
    }
    let mut seen = std::collections::BTreeSet::new();
    for visit in &record.visits {
        let path_display = display(&visit.canonical);
        if seen.insert(path_display.clone()) {
            snapshot.files.push(ReachedFile {
                path_display,
                sha256: digests.get(&visit.canonical).map(|(d, _)| d.clone()),
            });
        }
    }
    for failure in &record.failures {
        let path_display = display(&failure.path);
        if seen.insert(path_display.clone()) {
            snapshot.files.push(ReachedFile {
                path_display,
                sha256: None,
            });
        }
    }
    snapshot
}

/// The differences between two snapshots (at most 256 reported).
#[must_use]
pub fn compare(before: &TreeSnapshot, after: &TreeSnapshot) -> Vec<ConfigTreeDifference> {
    let index = |s: &TreeSnapshot| -> BTreeMap<String, Option<String>> {
        s.files
            .iter()
            .map(|f| (f.path_display.clone(), f.sha256.clone()))
            .collect()
    };
    let (b, a) = (index(before), index(after));
    let mut out = Vec::new();
    for f in &after.files {
        let change = match b.get(&f.path_display) {
            None => Some(TreeChange::Added),
            Some(old) if *old == f.sha256 => None,
            Some(_) if f.sha256.is_none() => Some(TreeChange::Unreadable),
            Some(_) => Some(TreeChange::Modified),
        };
        if let Some(change) = change {
            out.push(ConfigTreeDifference {
                path_display: f.path_display.clone(),
                change,
            });
        }
    }
    for f in &before.files {
        if !a.contains_key(&f.path_display) {
            out.push(ConfigTreeDifference {
                path_display: f.path_display.clone(),
                change: TreeChange::Removed,
            });
        }
    }
    out.truncate(MAX_CONFIG_TREE_DIFFERENCES);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_sshconf::eval::{Invocation, OpenSshVersion};
    use heimdall_sshconf::include::MemSource;

    fn query() -> Query {
        Query {
            host: "a".to_owned(),
            user: None,
            local_user: "u".to_owned(),
            client_version: OpenSshVersion::MINIMUM,
            invocation: Invocation::Shell,
        }
    }

    fn roots() -> Roots {
        Roots::new(Some(PathBuf::from("/h/.ssh/config")), None)
    }

    #[test]
    fn a_new_glob_member_is_added_and_an_edit_is_modified() {
        let base = MemSource::new("/h", "/h/.ssh", "/etc/ssh")
            .with_file(
                "/h/.ssh/config",
                "Include /h/.ssh/conf.d/*.conf\nHost a\n  Port 1\n",
            )
            .with_file("/h/.ssh/conf.d/10.conf", "Host b\n");
        let before = take(&base, &roots(), &query(), &Limits::default());
        assert_eq!(before.files.len(), 2);
        assert!(matches!(
            &before.includes[0].1,
            IncludeExpansion::Matches(m) if m.len() == 1
        ));
        assert!(compare(&before, &before).is_empty());

        let grown = base
            .clone()
            .with_file("/h/.ssh/conf.d/50-new.conf", "Host c\n");
        let after = take(&grown, &roots(), &query(), &Limits::default());
        let diff = compare(&before, &after);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].change, TreeChange::Added);
        assert!(diff[0].path_display.ends_with("50-new.conf"));

        let edited = base
            .clone()
            .with_file("/h/.ssh/conf.d/10.conf", "Host b\n  Port 2\n");
        let after = take(&edited, &roots(), &query(), &Limits::default());
        let diff = compare(&before, &after);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].change, TreeChange::Modified);

        let mut gone = base.clone();
        gone.remove("/h/.ssh/conf.d/10.conf");
        let after = take(&gone, &roots(), &query(), &Limits::default());
        assert_eq!(compare(&before, &after)[0].change, TreeChange::Removed);

        let denied = base.with_entry(
            "/h/.ssh/conf.d/10.conf",
            heimdall_sshconf::include::MemEntry::Denied,
        );
        let after = take(&denied, &roots(), &query(), &Limits::default());
        assert_eq!(compare(&before, &after)[0].change, TreeChange::Unreadable);
    }

    #[test]
    fn unresolvable_includes_are_recorded_with_a_reason() {
        let src = MemSource::new("/h", "/h/.ssh", "/etc/ssh").with_file(
            "/h/.ssh/config",
            "Include ${HM_UNSET}/x.conf\nInclude /h/%l.conf\n",
        );
        let s = take(&src, &roots(), &query(), &Limits::default());
        assert_eq!(
            s.includes
                .iter()
                .map(|(_, e)| e.clone())
                .collect::<Vec<_>>(),
            vec![
                IncludeExpansion::Unresolved("env_unset".to_owned()),
                IncludeExpansion::Unresolved("token_unavailable".to_owned()),
            ]
        );
    }
}
