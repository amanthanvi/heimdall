//! ⟨rev7⟩ ADR-0013 D5: the typed event payloads cover every emission site.
//!
//! `event_payload_schema_covers_every_emission_site` scans the production sources of every
//! crate for the two ways an event is made: a persisted event, through one of the
//! application's emit calls (`.event(`, `.publish(`, `.publish_in(` or `.append_in(` taking
//! an `EventType::X`), and a wire-only event, built as an `Event { event_type:
//! EventType::X, .. }` literal. Each site is keyed by its file, its enclosing function and
//! its type, and the set must equal the registry
//! `tests/contracts/golden/event-emission-sites.json` (`HM_UPDATE_GOLDENS=1` rewrites it).
//! A new site therefore fails the test until it is registered, and registering it means its
//! type's payload variant of [`EventPayload`] holds its keys (the D5 schema, checked against
//! stored rows by the replay corpus). It also checks the persistence choke point: exactly one
//! production call of `Txn::append_event` and one `INSERT INTO events`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heimdall_contract::event_payload::EventPayload;

use crate::repo_root;

const REGISTRY: &str = "tests/contracts/golden/event-emission-sites.json";

/// One emission site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    function: String,
    event_type: String,
    form: &'static str,
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.is_dir() {
            if name != "live_tests" && name != "tests" {
                sources(&p, out);
            }
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "tests.rs" {
            out.push(p);
        }
    }
}

/// The source with every `#[cfg(test)]` item (a test module, a test function) removed, by
/// brace matching from the item that follows the attribute.
fn production(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..at]);
        let after = &rest[at..];
        // The item's body starts at its first `{`, unless a `;` ends it first.
        let brace = after.find('{');
        let semi = after.find(';');
        match (brace, semi) {
            (Some(b), s) if s.is_none_or(|s| b < s) => {
                let mut depth = 0usize;
                let mut end = after.len();
                for (i, c) in after[b..].char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = b + i + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                rest = &after[end..];
            }
            (_, Some(s)) => rest = &after[s + 1..],
            _ => rest = "",
        }
    }
    out.push_str(rest);
    out
}

/// The name of the function whose body holds byte `at` of `text`: the last `fn <name>`
/// before it.
fn enclosing_fn(text: &str, at: usize) -> String {
    let head = &text[..at];
    let mut best = None;
    let mut search = head;
    while let Some(i) = search.rfind("fn ") {
        let before = search[..i].chars().last();
        if before.is_none_or(|c| !c.is_alphanumeric() && c != '_') {
            best = Some(i);
            break;
        }
        search = &search[..i];
    }
    best.map_or_else(
        || "<module>".to_owned(),
        |i| {
            head[i + 3..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect()
        },
    )
}

fn ident_after(text: &str) -> String {
    text.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

fn scan() -> (Vec<Site>, usize, usize) {
    let root = repo_root();
    let mut files = Vec::new();
    for e in std::fs::read_dir(root.join("crates")).unwrap() {
        let krate = e.unwrap().path();
        if krate.file_name().is_some_and(|n| n == "testkit") {
            continue;
        }
        let src = krate.join("src");
        if src.is_dir() {
            sources(&src, &mut files);
        }
    }
    let mut sites = Vec::new();
    let mut append_calls = 0;
    let mut inserts = 0;
    for path in &files {
        let text = production(&std::fs::read_to_string(path).unwrap());
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        append_calls += text.matches(".append_event(").count();
        inserts += text.matches("INSERT INTO events").count();
        let needle = "EventType::";
        let mut from = 0;
        while let Some(i) = text[from..].find(needle) {
            let at = from + i;
            from = at + needle.len();
            let ty = ident_after(&text[from..]);
            // What precedes the path, whitespace removed, decides the form.
            let lead: String = text[..at]
                .chars()
                .rev()
                .take(160)
                .filter(|c| !c.is_whitespace())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let lead = lead
                .strip_suffix("heimdall_contract::event::")
                .unwrap_or(&lead);
            let persisted = ["(tx,", "("].iter().any(|open| {
                lead.strip_suffix(open).is_some_and(|l| {
                    [".event", ".publish", ".publish_in", ".append_in"]
                        .iter()
                        .any(|call| l.ends_with(call))
                })
            });
            let wire = lead.ends_with("event_type:");
            if persisted || wire {
                sites.push(Site {
                    file: rel.clone(),
                    function: enclosing_fn(&text, at),
                    event_type: heck(&ty),
                    form: if wire { "wire" } else { "persisted" },
                });
            }
        }
    }
    sites.sort();
    sites.dedup();
    (sites, append_calls, inserts)
}

/// `OperationStateChanged` → `operation_state_changed`.
fn heck(ty: &str) -> String {
    let mut out = String::new();
    for (i, c) in ty.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn render(sites: &[Site]) -> String {
    let rows: Vec<serde_json::Value> = sites
        .iter()
        .map(|s| {
            serde_json::json!({
                "file": s.file,
                "function": s.function,
                "type": s.event_type,
                "form": s.form,
            })
        })
        .collect();
    let mut text = serde_json::to_string_pretty(&rows).unwrap();
    text.push('\n');
    text
}

#[test]
fn event_payload_schema_covers_every_emission_site() {
    let (sites, append_calls, inserts) = scan();
    // The choke point: one production `append_event` call (the application's event
    // publisher) besides its definition, and one `INSERT INTO events`.
    assert_eq!(append_calls, 1, "production calls of Txn::append_event");
    assert_eq!(inserts, 1, "INSERT INTO events");
    assert!(
        sites.len() >= 20,
        "the scan found only {} sites",
        sites.len()
    );
    // Every site's type has its payload variant in the D5 schema.
    let schema = serde_json::to_value(schemars::schema_for!(EventPayload)).unwrap();
    let typed: BTreeSet<String> = schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["properties"]["type"]["const"].as_str().map(str::to_owned))
        .collect();
    for s in &sites {
        assert!(
            typed.contains(&s.event_type),
            "{}::{} emits `{}`, which the payload schema does not cover",
            s.file,
            s.function,
            s.event_type
        );
    }
    let text = render(&sites);
    let path = repo_root().join(REGISTRY);
    if std::env::var_os("HM_UPDATE_GOLDENS").is_some_and(|v| v == "1") {
        std::fs::write(&path, &text).unwrap();
        return;
    }
    let golden = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (HM_UPDATE_GOLDENS=1 writes it)", path.display()));
    assert!(
        text == golden,
        "the emission sites changed: register each new site (and check its keys against \
         its payload variant), then HM_UPDATE_GOLDENS=1\n--- found\n{text}"
    );
}

/// The scanner's own pieces: a test item is removed, a function is named, a path is read.
#[test]
fn emission_scan_self_check() {
    let src = "fn live() { x.event(tx, EventType::Decision, y); }\n\
               #[cfg(test)]\nmod tests { fn t() { x.event(EventType::Route); } }\n\
               fn wire() { Event { event_type: EventType::ResyncRequired } }";
    let p = production(src);
    assert!(!p.contains("Route"));
    assert!(p.contains("fn wire"));
    let at = p.find("EventType::Decision").unwrap();
    assert_eq!(enclosing_fn(&p, at), "live");
    assert_eq!(heck("ResyncRequired"), "resync_required");
}
