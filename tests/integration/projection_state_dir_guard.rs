//! A guard on the writing `ProjectionConfig` constructors (ADR-0007 §12.34 item 6).
//!
//! The writer copies an original user file to `<state_dir>/backups` before its first edit
//! (§5.5, §12.32 item 2), and it can only do so when its configuration names the state
//! directory. A configuration without one writes no snapshot, silently. Every production
//! constructor of a writing `ProjectionConfig` (the runtime service's account wiring and
//! the debug test configuration) therefore sets it, and this test scans the workspace
//! source for any that does not. (Refusing an edit when a writing configuration has no
//! `state_dir` is left for M03 hardening; ADR-0007 §13.)
//!
//! **What is scanned.** Every `crates/*/src/**/*.rs`, outside `#[cfg(test)]` items, with
//! comments, strings and character literals blanked (so a mention is not a use). A
//! construction is `ProjectionConfig::new(..)` or a `ProjectionConfig { .. }` literal. A
//! `::new(..)` construction must be followed, in its function, by `.with_state_dir(..)` or
//! an assignment `<x>.state_dir = <not None>`; a literal must have a `state_dir` field that
//! is not `None`.
//!
//! **The reviewed exception.** A configuration that is only ever read (the static pass of
//! `run`, `connect` and `setup status`: passive evaluation, no writer) is listed in
//! [`PASSIVE`] with the function that builds it. The test holds that list to its word: a
//! listed constructor must still exist, and no function that calls it may wire a writer
//! (`wire_projection`, `ProjectionWiring::Config`, `ProjectionCleaner::new`) or call
//! `apply`, `reconcile` or `delete`.
//!
//! Cargo test target `integration_projection_state_dir_guard` hosted by
//! `heimdall-localenv`. The scanner is a pure function over `(path, text)` pairs; its own
//! tests run it over synthetic sources and, in memory, over the real writing constructors
//! with their state directory taken out.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ops::Range;
use std::path::Path;

use heimdall_testkit::repo::repo_path;

/// The reviewed non-writing constructors: `(file, function, why)`.
const PASSIVE: &[(&str, &str, &str)] = &[(
    "crates/heimdall/src/launch_flow.rs",
    "static_config",
    "the static pass: evaluates the user's configuration and observes held steps; no writer is wired to it",
)];

/// What a caller of a passive constructor must not do (a writer or a cleaner).
const WRITER_SEAMS: &[&str] = &[
    "wire_projection(",
    "ProjectionWiring::Config(",
    "ProjectionCleaner::new(",
    ".apply(",
    ".reconcile(",
    ".delete(",
];

// --- the source, with what is not code blanked --------------------------------------------

/// `src` with every comment, string literal and character literal replaced by spaces
/// (newlines kept), so byte offsets and line numbers are those of `src`.
fn mask(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, range: Range<usize>| {
        for i in range {
            if out[i] != b'\n' {
                out[i] = b' ';
            }
        }
    };
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            let end = b[i..]
                .iter()
                .position(|c| *c == b'\n')
                .map_or(b.len(), |n| i + n);
            blank(&mut out, i..end);
            i = end;
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let (mut depth, mut j) = (1, i + 2);
            while j < b.len() && depth > 0 {
                if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i..j);
            i = j;
        } else if (c == b'r' || (c == b'b' && b.get(i + 1) == Some(&b'r')))
            && (i == 0 || !ident(b[i - 1]))
            && {
                let mut j = i + if c == b'b' { 2 } else { 1 };
                while b.get(j) == Some(&b'#') {
                    j += 1;
                }
                b.get(j) == Some(&b'"')
            }
        {
            // A raw string: r"..", r#".."#, br#".."#.
            let mut j = i + if c == b'b' { 2 } else { 1 };
            let mut hashes = 0;
            while b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            j += 1;
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let end = b[j..]
                .windows(close.len())
                .position(|w| w == close.as_slice())
                .map_or(b.len(), |n| j + n + close.len());
            blank(&mut out, i..end);
            i = end;
        } else if c == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(b.len());
            blank(&mut out, i..end);
            i = end;
        } else if c == b'\'' {
            // A character literal ('x', '\n', '{') or a lifetime ('a, 'static).
            let literal_end = if b.get(i + 1) == Some(&b'\\') {
                let mut j = i + 3;
                while j < b.len() && b[j] != b'\'' {
                    j += 1;
                }
                Some(j + 1)
            } else {
                let width = src[i + 1..].chars().next().map_or(0, char::len_utf8);
                (width > 0 && b.get(i + 1 + width) == Some(&b'\'')).then_some(i + 2 + width)
            };
            match literal_end {
                Some(end) => {
                    let end = end.min(b.len());
                    blank(&mut out, i..end);
                    i = end;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking keeps UTF-8 whole: only whole literals are replaced")
}

/// The index of the `}` matching the `{` at `open`.
fn matching_brace(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0_usize;
    for (i, c) in text.bytes().enumerate().skip(open) {
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// `masked` with every `#[cfg(test)]` (and `#[cfg(all(test, ..))]`) item blanked: the
/// attribute, the attributes after it and the item (to its `;` or its matching `}`).
/// `None` when the whole file is test code (`#![cfg(test)]`).
fn without_test_items(masked: &str) -> Option<String> {
    let squeeze = |s: &str| s.split_whitespace().collect::<String>();
    let mut out = masked.as_bytes().to_vec();
    let mut from = 0;
    while let Some(n) = masked[from..]
        .find("#[cfg(")
        .or_else(|| masked[from..].find("#![cfg("))
    {
        let at = from + n;
        let inner = masked[at..].starts_with("#!");
        let Some(close) = masked[at..].find(']').map(|c| at + c) else {
            break;
        };
        let attr = squeeze(&masked[at..=close]);
        let is_test = attr == "#[cfg(test)]"
            || attr == "#![cfg(test)]"
            || attr.starts_with("#[cfg(all(test,")
            || attr.starts_with("#![cfg(all(test,");
        from = close + 1;
        if !is_test {
            continue;
        }
        if inner {
            return None;
        }
        // The item: skip further attributes, then to the first `;` or balanced `{..}`.
        let mut j = close + 1;
        loop {
            let rest = masked[j..].trim_start();
            let at_rest = masked.len() - rest.len();
            if rest.starts_with("#[") {
                j = masked[at_rest..]
                    .find(']')
                    .map_or(masked.len(), |c| at_rest + c + 1);
            } else {
                j = at_rest;
                break;
            }
        }
        let end = masked[j..]
            .find(['{', ';'])
            .map(|n| j + n)
            .map_or(masked.len(), |n| {
                if masked.as_bytes()[n] == b';' {
                    n + 1
                } else {
                    matching_brace(masked, n).map_or(masked.len(), |m| m + 1)
                }
            });
        for byte in &mut out[at..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        from = end;
    }
    Some(String::from_utf8(out).expect("whole items are replaced"))
}

/// A function with a body: its name and the byte range of the body's braces.
struct Func {
    name: String,
    body: Range<usize>,
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Every occurrence of the word `word` in `text`.
fn words<'a>(text: &'a str, word: &'a str) -> impl Iterator<Item = usize> + 'a {
    let b = text.as_bytes();
    text.match_indices(word).map(|(i, _)| i).filter(move |i| {
        let before = *i == 0 || !is_ident(b[i - 1]);
        let after = b.get(i + word.len()).is_none_or(|c| !is_ident(*c));
        before && after
    })
}

fn functions(masked: &str) -> Vec<Func> {
    let b = masked.as_bytes();
    let mut out = Vec::new();
    for at in words(masked, "fn") {
        let rest = &masked[at + 2..];
        let name: String = rest
            .trim_start()
            .bytes()
            .take_while(|c| is_ident(*c))
            .map(char::from)
            .collect();
        if name.is_empty() {
            continue;
        }
        let from = at + 2 + (rest.len() - rest.trim_start().len()) + name.len();
        // The body starts at the first `{` (a declaration ends at `;` first).
        let Some(open) = (from..b.len()).find(|i| b[*i] == b'{' || b[*i] == b';') else {
            continue;
        };
        if b[open] == b';' {
            continue;
        }
        if let Some(close) = matching_brace(masked, open) {
            out.push(Func {
                name,
                body: open..close + 1,
            });
        }
    }
    out
}

/// The innermost function whose body holds `offset`.
fn enclosing(funcs: &[Func], offset: usize) -> Option<&Func> {
    funcs
        .iter()
        .filter(|f| f.body.contains(&offset))
        .min_by_key(|f| f.body.len())
}

fn line_of(src: &str, offset: usize) -> usize {
    src[..offset].bytes().filter(|c| *c == b'\n').count() + 1
}

// --- constructions ------------------------------------------------------------------------

/// How a construction is written.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    /// `ProjectionConfig::new(..)`: the state directory comes from the function.
    New,
    /// `ProjectionConfig { .. }`: the literal's own braces.
    Literal(Range<usize>),
}

struct Construction {
    offset: usize,
    shape: Shape,
}

fn constructions(masked: &str) -> Vec<Construction> {
    let b = masked.as_bytes();
    let mut out = Vec::new();
    for at in words(masked, "ProjectionConfig") {
        let after = &masked[at + "ProjectionConfig".len()..];
        if after.starts_with("::new(") {
            out.push(Construction {
                offset: at,
                shape: Shape::New,
            });
            continue;
        }
        let trimmed = after.trim_start();
        if !trimmed.starts_with('{') {
            continue;
        }
        // A literal is in expression position: after `=`, `(`, `,`, `{`, `;`, `}`, `[`, a
        // field's `:` or `return`. A definition (`struct ProjectionConfig {`, `impl [T for]
        // ProjectionConfig {`) and a type before a body (`-> ProjectionConfig {`,
        // `-> &ProjectionConfig {`) are not.
        let path_start = masked[..at]
            .trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == ':')
            .len();
        let before = masked[..path_start].trim_end();
        let in_expression = before.ends_with(['=', '(', ',', '{', ';', '}', '[', ':'])
            || before.ends_with("=>")
            || before.ends_with("return");
        if !in_expression {
            continue;
        }
        let open = masked.len() - trimmed.len();
        debug_assert_eq!(b[open], b'{');
        if let Some(close) = matching_brace(masked, open) {
            out.push(Construction {
                offset: at,
                shape: Shape::Literal(open..close + 1),
            });
        }
    }
    out
}

/// Whether `scope` (a function body) sets the state directory on a `::new(..)` config:
/// `.with_state_dir(..)` or `<x>.state_dir = <not None>`.
fn sets_by_call_or_assignment(scope: &str) -> bool {
    if words(scope, "with_state_dir").any(|i| scope[i + "with_state_dir".len()..].starts_with('('))
    {
        return true;
    }
    words(scope, "state_dir").any(|i| {
        scope[..i].trim_end().ends_with('.')
            && scope[i + "state_dir".len()..]
                .trim_start()
                .strip_prefix('=')
                .is_some_and(|rhs| !rhs.starts_with('=') && !is_none(rhs))
    })
}

fn is_none(value: &str) -> bool {
    let v = value.trim_start();
    v.starts_with("None") && !v.as_bytes().get(4).is_some_and(|c| is_ident(*c))
}

/// Whether a `ProjectionConfig { .. }` literal gives `state_dir` a value (not `None`).
fn literal_sets(literal: &str) -> bool {
    words(literal, "state_dir").any(|i| {
        let rest = literal[i + "state_dir".len()..].trim_start();
        match rest.strip_prefix(':') {
            Some(value) => !value.starts_with(':') && !is_none(value),
            // Shorthand (`state_dir,` or the last field).
            None => rest.starts_with(',') || rest.starts_with('}'),
        }
    })
}

// --- the scan -----------------------------------------------------------------------------

/// One source file: its repository-relative path (`/`-separated) and text.
struct Source {
    path: String,
    text: String,
}

/// The result of one scan.
#[derive(Default, Debug)]
struct Scan {
    /// Writing-or-not constructions that set a state directory (`file`, `function`).
    set: Vec<(String, String)>,
    /// Constructions that do not, and are not in [`PASSIVE`]: the failures.
    violations: Vec<String>,
    /// Constructions without one that [`PASSIVE`] covers.
    passive: Vec<(String, String)>,
    /// Passive entries that no longer match a construction, and callers that write.
    broken_promises: Vec<String>,
}

fn scan(sources: &[Source], passive: &[(&str, &str, &str)]) -> Scan {
    let mut result = Scan::default();
    // Production code of every file, blanked and with its test items removed.
    let code: Vec<(&Source, String)> = sources
        .iter()
        .filter_map(|s| without_test_items(&mask(&s.text)).map(|m| (s, m)))
        .collect();
    for (source, masked) in &code {
        let funcs = functions(masked);
        for c in constructions(masked) {
            let function = enclosing(&funcs, c.offset);
            let name = function
                .map_or("<no function>", |f| f.name.as_str())
                .to_owned();
            let sets = match &c.shape {
                Shape::New => {
                    function.is_some_and(|f| sets_by_call_or_assignment(&masked[f.body.clone()]))
                }
                Shape::Literal(range) => literal_sets(&masked[range.clone()]),
            };
            let line = line_of(&source.text, c.offset);
            if sets {
                result.set.push((source.path.clone(), name));
            } else if passive
                .iter()
                .any(|(f, n, _)| *f == source.path && *n == name)
            {
                result.passive.push((source.path.clone(), name));
            } else {
                result.violations.push(format!(
                    "{}:{line}: `ProjectionConfig` is built in `{name}` without a state directory; \
                     set it (`.with_state_dir(paths.state_dir.clone())`) or, if the configuration is only \
                     ever read, add a reviewed entry to PASSIVE",
                    source.path
                ));
            }
        }
    }
    for (file, name, _) in passive {
        if !result.passive.iter().any(|(f, n)| f == file && n == name) {
            result.broken_promises.push(format!(
                "PASSIVE lists `{name}` in {file}, but no such constructor without a state directory is there: remove the entry"
            ));
        }
        // Every function that calls the passive constructor stays read-only.
        for (source, masked) in &code {
            let funcs = functions(masked);
            for at in words(masked, name) {
                if !masked[at + name.len()..].starts_with('(')
                    || masked[..at].trim_end().ends_with("fn")
                {
                    continue;
                }
                let Some(caller) = enclosing(&funcs, at) else {
                    continue;
                };
                let body = &masked[caller.body.clone()];
                for seam in WRITER_SEAMS {
                    if body.contains(seam) {
                        result.broken_promises.push(format!(
                            "{}: `{}` calls the passive `{name}` and also `{seam}`: a configuration that reaches a writer must set its state directory",
                            source.path, caller.name
                        ));
                    }
                }
            }
        }
    }
    result
}

/// The `crates/*/src/**/*.rs` of the repository, read through `HM_REPO_ROOT`.
fn workspace_sources() -> Vec<Source> {
    let root = repo_path("");
    let mut out = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let rel = p.strip_prefix(&root).unwrap_or(&p);
                let rel = rel.to_string_lossy().replace('\\', "/");
                // `crates/<name>/src/...` only: integration tests and benches live elsewhere.
                let in_src = Path::new(&rel)
                    .components()
                    .nth(2)
                    .is_some_and(|c| c.as_os_str() == "src");
                if in_src {
                    out.push(Source {
                        text: std::fs::read_to_string(&p).unwrap_or_default(),
                        path: rel,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

// --- tests --------------------------------------------------------------------------------

fn src(path: &str, text: &str) -> Source {
    Source {
        path: path.to_owned(),
        text: text.to_owned(),
    }
}

/// ADR-0007 §12.34 item 6: every production constructor of a writing `ProjectionConfig`
/// sets `state_dir`. The scan also finds the two writing constructors it is there to
/// guard (a scan that sees nothing guards nothing).
#[test]
fn every_production_projection_config_sets_its_state_directory() {
    let sources = workspace_sources();
    assert!(
        sources.len() > 100,
        "scanned only {} sources: is the repository root right?",
        sources.len()
    );
    let result = scan(&sources, PASSIVE);
    let mut problems = result.violations.clone();
    problems.extend(result.broken_promises.iter().cloned());
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
    for (file, function) in [
        ("crates/runtime/src/service.rs", "account_projection"),
        ("crates/heimdall/src/testcfg.rs", "projection_wiring"),
    ] {
        let found = result.set.iter().any(|(f, _)| f == file);
        assert!(
            found,
            "the writing constructor in {file} ({function}) is not seen: {result:?}"
        );
    }
    assert_eq!(
        result.passive.len(),
        PASSIVE.len(),
        "the reviewed passive constructors: {result:?}"
    );
}

/// The guard fails on the real writing constructors with their state directory taken
/// out: the scan is not a formality.
#[test]
fn taking_the_state_directory_out_of_a_real_constructor_is_caught() {
    let sources = workspace_sources();
    let mut seen = 0;
    for file in [
        "crates/runtime/src/service.rs",
        "crates/heimdall/src/testcfg.rs",
    ] {
        let real = sources.iter().find(|s| s.path == file).expect(file);
        assert!(
            real.text.contains(".with_state_dir("),
            "{file} sets it by call"
        );
        let mutated = real.text.replace(".with_state_dir(", ".with_nothing(");
        let result = scan(&[src(file, &mutated)], PASSIVE);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.contains("without a state directory")),
            "{file}: {result:?}"
        );
        seen += 1;
    }
    assert_eq!(seen, 2);
}

#[test]
fn a_new_without_a_state_directory_is_a_violation_and_with_one_is_not() {
    let bare =
        "fn wire() -> ProjectionConfig {\n    let c = ProjectionConfig::new(a, b, c);\n    c\n}\n";
    let result = scan(&[src("crates/x/src/a.rs", bare)], &[]);
    assert_eq!(result.violations.len(), 1, "{result:?}");
    assert!(
        result.violations[0].starts_with("crates/x/src/a.rs:2: "),
        "{result:?}"
    );
    assert!(result.violations[0].contains("`wire`"), "{result:?}");
    for ok in [
        "fn wire() {\n    let c = ProjectionConfig::new(a, b, c)\n        .with_state_dir(d);\n}\n",
        "fn wire() {\n    let mut c = ProjectionConfig::new(a, b, c);\n    c.state_dir = Some(d);\n}\n",
        "fn wire() { let mut c = ProjectionConfig::new(a, b, c); c.state_dir = d.clone(); }\n",
    ] {
        let result = scan(&[src("crates/x/src/a.rs", ok)], &[]);
        assert!(result.violations.is_empty(), "{ok}: {result:?}");
        assert_eq!(result.set.len(), 1);
    }
    for bad in [
        "fn wire() { let mut c = ProjectionConfig::new(a, b, c); c.state_dir = None; }\n",
        "fn wire() { let c = ProjectionConfig::new(a, b, c); let s = c.state_dir.is_some(); }\n",
        "fn wire() { let c = ProjectionConfig::new(a, b, c); if c.state_dir == x {} }\n",
        // The setting is in another function.
        "fn wire() { let c = ProjectionConfig::new(a, b, c); }\nfn other(c: C) { c.with_state_dir(d); }\n",
    ] {
        let result = scan(&[src("crates/x/src/a.rs", bad)], &[]);
        assert_eq!(result.violations.len(), 1, "{bad}: {result:?}");
    }
}

#[test]
fn a_literal_needs_a_state_directory_that_is_not_none() {
    let literal = |field: &str| {
        format!(
            "fn wire() -> ProjectionConfig {{\n    ProjectionConfig {{ paths, platform, {field} env }}\n}}\n"
        )
    };
    for ok in ["state_dir: Some(d),", "state_dir,", "state_dir: d.state(),"] {
        let result = scan(&[src("crates/x/src/a.rs", &literal(ok))], &[]);
        assert!(result.violations.is_empty(), "{ok}: {result:?}");
    }
    for bad in ["state_dir: None,", ""] {
        let result = scan(&[src("crates/x/src/a.rs", &literal(bad))], &[]);
        assert_eq!(result.violations.len(), 1, "{bad}: {result:?}");
    }
    // A definition, an impl and a return type are not constructions.
    let definitions = "pub struct ProjectionConfig { pub state_dir: Option<P> }\nimpl ProjectionConfig { fn new() -> Self { Self { state_dir: None } } }\nimpl Debug for ProjectionConfig { fn fmt(&self) {} }\nfn f() -> ProjectionConfig { todo!() }\n";
    let result = scan(&[src("crates/x/src/a.rs", definitions)], &[]);
    assert!(
        result.violations.is_empty() && result.set.is_empty(),
        "{result:?}"
    );
}

#[test]
fn tests_comments_strings_and_other_functions_are_not_constructions() {
    let text = r##"
// ProjectionConfig::new(a, b, c) in a comment
/* ProjectionConfig::new(a, b, c) /* nested */ still a comment */
const DOC: &str = "ProjectionConfig::new(a, b, c)";
const RAW: &str = r#"ProjectionConfig::new(a, b, c) "quoted" "#;
const BRACE: char = '{';
fn lifetimes<'a>(x: &'a str) -> &'a str { x }

#[cfg(test)]
fn only_in_tests() { let c = ProjectionConfig::new(a, b, c); }

#[cfg(all(test, unix))]
mod unix_tests { fn f() { let c = ProjectionConfig::new(a, b, c); } }

#[cfg(test)]
mod tests {
    fn f() { let c = ProjectionConfig::new(a, b, c); }
}
"##;
    let result = scan(&[src("crates/x/src/a.rs", text)], &[]);
    assert!(
        result.violations.is_empty() && result.set.is_empty(),
        "{result:?}"
    );
    // A test item in the middle does not hide the production code after it.
    let after = format!("{text}\nfn production() {{ let c = ProjectionConfig::new(a, b, c); }}\n");
    let result = scan(&[src("crates/x/src/a.rs", &after)], &[]);
    assert_eq!(result.violations.len(), 1, "{result:?}");
    assert!(result.violations[0].contains("`production`"), "{result:?}");
    // A file that is test code as a whole is skipped.
    let whole = "#![cfg(test)]\nfn f() { let c = ProjectionConfig::new(a, b, c); }\n";
    let result = scan(&[src("crates/x/src/a.rs", whole)], &[]);
    assert!(result.violations.is_empty(), "{result:?}");
    // `not(test)` is production code.
    let not = "#[cfg(not(test))]\nfn f() { let c = ProjectionConfig::new(a, b, c); }\n";
    let result = scan(&[src("crates/x/src/a.rs", not)], &[]);
    assert_eq!(result.violations.len(), 1, "{result:?}");
}

#[test]
fn a_passive_entry_is_held_to_its_word() {
    let passive: &[(&str, &str, &str)] = &[("crates/x/src/a.rs", "static_config", "read only")];
    let build = "fn static_config() -> ProjectionConfig { ProjectionConfig::new(a, b, c) }\n";
    // Listed and read-only: fine.
    let reads = format!("{build}fn held(x: X) {{ let c = static_config(); observe(&c); }}\n");
    let result = scan(&[src("crates/x/src/a.rs", &reads)], passive);
    assert!(
        result.violations.is_empty() && result.broken_promises.is_empty(),
        "{result:?}"
    );
    // Not listed (another function name, another file): a violation.
    let result = scan(&[src("crates/x/src/b.rs", build)], passive);
    assert_eq!(result.violations.len(), 1, "{result:?}");
    // Listed but gone, or it now sets the state directory: the entry is stale.
    let result = scan(&[src("crates/x/src/a.rs", "fn other() {}\n")], passive);
    assert_eq!(result.broken_promises.len(), 1, "{result:?}");
    let sets = "fn static_config() -> ProjectionConfig { ProjectionConfig::new(a, b, c).with_state_dir(d) }\n";
    let result = scan(&[src("crates/x/src/a.rs", sets)], passive);
    assert_eq!(result.broken_promises.len(), 1, "{result:?}");
    // A caller that reaches a writer or a cleaner breaks the promise, in any file.
    for seam in [
        "wire_projection(c)",
        "ProjectionWiring::Config(c)",
        "ProjectionCleaner::new(c)",
        "w.apply(i)",
        "w.reconcile(i)",
        "w.delete(i)",
    ] {
        let writes = format!("{build}fn held() {{ let c = static_config(); {seam}; }}\n");
        let result = scan(&[src("crates/x/src/a.rs", &writes)], passive);
        assert_eq!(result.broken_promises.len(), 1, "{seam}: {result:?}");
        let elsewhere = format!("fn run() {{ let c = static_config(); {seam}; }}\n");
        let result = scan(
            &[
                src("crates/x/src/a.rs", build),
                src("crates/x/src/c.rs", &elsewhere),
            ],
            passive,
        );
        assert_eq!(result.broken_promises.len(), 1, "{seam}: {result:?}");
    }
}
