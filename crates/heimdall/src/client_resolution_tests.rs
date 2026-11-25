//! ⟨rev7⟩ m07-plan U3 (ADR-0013 §6.3, S3): `no_internal_resolution_traverses`, a source check
//! over `crates/heimdall/src` and `crates/app/src`.
//!
//! Every production read of a list subject names `InspectSubject::<List>` in the statement
//! that sends it. A statement that reads through the point lookup (`client::lookup`, or a
//! helper named `lookup…` over it) is a resolution. Any other is a whole read, and a whole
//! read (or a traversal) is allowed only at an enumeration site in [`ENUMERATIONS`], each
//! with its reason. Patterns (`InspectSubject::X =>`, `| InspectSubject::X`) and comparisons
//! serve or route a request and read nothing. Test modules and `*_tests.rs` files are not
//! production code. The TUI (`crates/heimdall/src/tui/`) keeps its whole reads until its
//! paged loading (m07-plan U6), so it is out of this check's scope.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The list subjects (`select` and `page` apply to these only).
const LIST_SUBJECTS: &[&str] = &[
    "Environments",
    "Profiles",
    "Destinations",
    "Grants",
    "Bindings",
    "Operations",
    "Decisions",
    "Identities",
    "Projections",
    "Enrollments",
    "Connections",
    "Policies",
];

/// `(file, function, subject, reason)`: the enumeration sites that read a whole list.
const ENUMERATIONS: &[(&str, &str, &str, &str)] = &[
    (
        "app/src/remote_env.rs",
        "runner_view",
        "Environments",
        "the runner view shows the runner's own environments listing as its role reads it (one record); a runner may be an older runtime without pages/1",
    ),
    (
        "heimdall/src/catalog_cmd.rs",
        "destination_flow",
        "Destinations",
        "`destination list`: list output",
    ),
    (
        "heimdall/src/catalog_cmd.rs",
        "identity_flow",
        "Identities",
        "`identity list`: list output",
    ),
    (
        "heimdall/src/catalog_cmd.rs",
        "profile_flow",
        "Profiles",
        "`profile list`: list output",
    ),
    (
        "heimdall/src/cli.rs",
        "run_client",
        "Decisions",
        "`decision list`: list output",
    ),
    (
        "heimdall/src/cli.rs",
        "status",
        "Operations",
        "`status`: counts and listings of every record",
    ),
    (
        "heimdall/src/cli.rs",
        "status",
        "Decisions",
        "`status`: counts and listings of every record",
    ),
    (
        "heimdall/src/cli.rs",
        "status",
        "Environments",
        "`status`: counts and listings of every record",
    ),
    (
        "heimdall/src/cli.rs",
        "status",
        "Bindings",
        "`status`: counts and listings of every record",
    ),
    (
        "heimdall/src/cli.rs",
        "status",
        "Grants",
        "`status`: counts and listings of every record",
    ),
    (
        "heimdall/src/cli.rs",
        "status",
        "Policies",
        "`status`: counts and listings of every record",
    ),
    (
        "heimdall/src/connect_cmd.rs",
        "covering_profile",
        "Profiles",
        "a search by content: the one profile whose pairs contain the pair needs every profile (none, or several, refuses); no selector names it",
    ),
    (
        "heimdall/src/connections_cmd.rs",
        "list",
        "Connections",
        "`connections`: list output",
    ),
    (
        "heimdall/src/container_cmd.rs",
        "resolve",
        "Environments",
        "a label is a search over the set (an ID is a point lookup)",
    ),
    (
        "heimdall/src/enroll_cmd.rs",
        "status",
        "Enrollments",
        "`enroll status`: list output",
    ),
    (
        "heimdall/src/launch_flow.rs",
        "fresh_identities",
        "Identities",
        "the pre-launch check's view: the static selection's entries name identities by fingerprint, a search by content over every identity",
    ),
    (
        "heimdall/src/launch_flow.rs",
        "projection_record",
        "Projections",
        "the projection record rides only on the whole read until U3-3's typed `projections` view (ruled 2026-11-25; a select answers items, not the record)",
    ),
    (
        "heimdall/src/m05_cmd.rs",
        "pending_extension",
        "Decisions",
        "a search by content: the widening record raised for the policy",
    ),
    (
        "heimdall/src/m05_cmd.rs",
        "personal_delta",
        "Profiles",
        "the dry-run preview rides on the read; no item is used",
    ),
    (
        "heimdall/src/m05_cmd.rs",
        "policies",
        "Policies",
        "the policies view (every policy and the default profiles), searched by content",
    ),
    (
        "heimdall/src/setup_cmd.rs",
        "offer_personal_default",
        "Policies",
        "a search by content: a personal default that already applies here",
    ),
    (
        "heimdall/src/setup_cmd.rs",
        "offer_personal_default",
        "Environments",
        "this environment's own ID, a field of the environments view, not a list item",
    ),
    (
        "heimdall/src/setup_cmd.rs",
        "offer_personal_default",
        "Profiles",
        "\"the catalog's only profile\" needs every profile",
    ),
    (
        "heimdall/src/setup_cmd.rs",
        "status",
        "Projections",
        "`setup status`: the projection resources and record (list output)",
    ),
    (
        "heimdall/src/setup_cmd.rs",
        "status",
        "Operations",
        "`setup status`: every held setup operation, a search by state",
    ),
    (
        "heimdall/src/uninstall_cmd.rs",
        "uninstall_after_recovery",
        "Projections",
        "whether anything is still installed: every projection resource",
    ),
    (
        "heimdall/src/uninstall_cmd.rs",
        "uninstall_after_recovery",
        "Operations",
        "an open setup operation, a search by state over every operation",
    ),
    (
        "heimdall/src/wsl_cmd.rs",
        "status",
        "Environments",
        "`wsl status`: every WSL environment (list output)",
    ),
    (
        "heimdall/src/wsl_cmd.rs",
        "uninstall_distributions",
        "Environments",
        "uninstall ends every Mode A distribution: an enumeration",
    ),
];

/// `crates/`, through the repository root the tests are given (HM_REPO_ROOT; ADR-0007
/// §12.32 item 3), never the compile-time root.
fn crates_dir() -> PathBuf {
    heimdall_testkit::repo::repo_path("crates")
}

/// Every production source file under `dir` (recursively), as `(path under crates/, text)`.
fn sources(dir: &Path, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("a source directory")
        .map(|e| e.expect("an entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let rel = path
            .strip_prefix(crates_dir())
            .expect("under crates/")
            .to_string_lossy()
            .replace('\\', "/");
        if path.is_dir() {
            if rel != "heimdall/src/tui" {
                sources(&path, out);
            }
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "tests.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .expect("a source file")
            .replace("\r\n", "\n");
        out.push((rel, production(&text)));
    }
}

/// `text` without its `#[cfg(test)]` modules (inline ones end at the first column-0 `}`).
fn production(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == "#[cfg(test)]" {
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim_start().starts_with("#[") {
                j += 1;
            }
            let item = lines.get(j).copied().unwrap_or("");
            let item = item
                .strip_prefix("pub(crate) ")
                .or_else(|| item.strip_prefix("pub "))
                .unwrap_or(item);
            if item.starts_with("mod ") && item.ends_with(';') {
                i = j + 1;
                continue;
            }
            if item.starts_with("mod ") && item.ends_with('{') {
                let mut k = j + 1;
                while k < lines.len() && lines[k] != "}" {
                    k += 1;
                }
                i = k + 1;
                continue;
            }
        }
        out.push(lines[i]);
        i += 1;
    }
    out.join("\n")
}

/// A site that names a list subject.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    function: String,
    subject: String,
    lookup: bool,
}

/// The name of the last `fn` before byte `at` of `text`.
fn function_at(text: &str, at: usize) -> String {
    let before = &text[..at];
    let mut name = String::from("?");
    let mut rest = before;
    while let Some(i) = rest.find("fn ") {
        let boundary = i == 0
            || !rest.as_bytes()[i - 1].is_ascii_alphanumeric() && rest.as_bytes()[i - 1] != b'_';
        let tail = &rest[i + 3..];
        let ident: String = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if boundary && !ident.is_empty() {
            name = ident;
        }
        rest = &rest[i + 3..];
    }
    name
}

/// Whether the statement fragment reads through a point lookup (`lookup(` or `lookup_one(`).
fn is_lookup(fragment: &str) -> bool {
    fragment.contains("lookup(") || fragment.contains("lookup_one(")
}

/// Every site of `(file, text)` that names a list subject in a read.
fn sites(file: &str, text: &str) -> Vec<Site> {
    const TOKEN: &str = "InspectSubject::";
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = text[from..].find(TOKEN) {
        let start = from + i;
        let end = start + TOKEN.len();
        from = end;
        let subject: String = text[end..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if !LIST_SUBJECTS.contains(&subject.as_str()) {
            continue;
        }
        let after = text[end + subject.len()..].trim_start();
        let before = text[..start].trim_end();
        if after.starts_with("=>")
            || after.starts_with('|')
            || after.starts_with("if ")
            || before.ends_with('|')
            || before.ends_with("==")
            || before.ends_with("!=")
            || before.ends_with("matches!(")
        {
            continue;
        }
        let statement = text[..start].rfind([';', '{', '}']).map_or(0, |k| k + 1);
        out.push(Site {
            file: file.to_owned(),
            function: function_at(text, start),
            subject,
            lookup: is_lookup(&text[statement..start]),
        });
    }
    out
}

/// `no_internal_resolution_traverses` (module docs).
#[test]
fn no_internal_resolution_traverses() {
    let mut files = Vec::new();
    sources(&crates_dir().join("heimdall/src"), &mut files);
    sources(&crates_dir().join("app/src"), &mut files);
    assert!(
        files
            .iter()
            .any(|(f, _)| f == "heimdall/src/connect_cmd.rs"),
        "the scan reads the CLI's sources"
    );
    let mut whole: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut lookups = 0usize;
    for (file, text) in &files {
        for site in sites(file, text) {
            if site.lookup {
                lookups += 1;
            } else {
                whole.insert((site.file, site.function, site.subject));
            }
        }
        // A traversal is enumeration only, and none is a resolution: outside the client's own
        // definitions there is none at all yet (an enumeration that adopts it joins the list).
        if file != "heimdall/src/client.rs" {
            assert!(
                !text.contains("traverse_on(") && !text.contains(".traverse("),
                "{file}: a traversal outside the enumeration allow-list"
            );
            // Every `select` is the point lookup's.
            assert!(
                !text.contains("select: Some("),
                "{file}: a select built outside client::lookup"
            );
        }
    }
    let allowed: BTreeSet<(String, String, String)> = ENUMERATIONS
        .iter()
        .map(|(f, func, s, reason)| {
            assert!(!reason.is_empty(), "every enumeration names its reason");
            ((*f).to_owned(), (*func).to_owned(), (*s).to_owned())
        })
        .collect();
    let unexplained: Vec<_> = whole.difference(&allowed).collect();
    assert!(
        unexplained.is_empty(),
        "whole reads outside the enumeration allow-list (a resolution must use client::lookup): {unexplained:#?}"
    );
    let stale: Vec<_> = allowed.difference(&whole).collect();
    assert!(
        stale.is_empty(),
        "allow-list entries that no longer read a whole list: {stale:#?}"
    );
    // The resolutions this unit migrated (connect's alias and hop, the binding re-check, the
    // decision, profile, destination, enrollment and environment lookups) are point lookups.
    assert!(lookups >= 12, "{lookups} point lookups found");
}

/// The scanner itself: a whole read, a lookup, a pattern and a test module.
#[test]
fn the_scanner_tells_lookups_from_whole_reads() {
    let text = production(
        "fn a(s: &mut S) {\n    let x = inspect(s, InspectSubject::Profiles).await;\n}\n\
         fn b(s: &mut S) {\n    let y = crate::client::lookup(\n        s,\n        InspectSubject::Bindings,\n        &[],\n    );\n}\n\
         fn c(r: R) {\n    match r {\n        InspectSubject::Grants => 1,\n        InspectSubject::Capabilities | InspectSubject::Decisions => 2,\n    }\n}\n\
         #[cfg(test)]\nmod tests {\n    fn d() { inspect(s, InspectSubject::Policies); }\n}\n",
    );
    let found = sites("f.rs", &text);
    let short: Vec<(&str, &str, bool)> = found
        .iter()
        .map(|s| (s.function.as_str(), s.subject.as_str(), s.lookup))
        .collect();
    assert_eq!(short, [("a", "Profiles", false), ("b", "Bindings", true)]);
}
