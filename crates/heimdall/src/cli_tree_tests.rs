//! ⟨rev7⟩ The command-tree golden and the help lint (ADR-0013 §2.3, D3, D14; m07-plan U0).
//!
//! * [`command_tree_matches_its_golden`]: every command path and every argument of the
//!   tree, as clap defines it, equals `tests/contracts/golden/command-tree.golden.txt`
//!   (`HM_UPDATE_GOLDENS=1` rewrites it). The tree is the frozen CLI surface: paths, flags,
//!   value names, whether an argument is required, repeatable, global or hidden, its
//!   default and the arguments it conflicts with. Help wording is not part of it.
//! * [`help_text_names_no_milestone_adr_or_section`]: the rendered help of every command,
//!   short and long, names no milestone (`M0n`), no ADR (`ADR-`), no section (`§`) and no
//!   test-only wording. [`HELP_LINT_PENDING`] lists the command paths whose help is not yet
//!   clean, each with its owner; an entry that has become clean fails the test, so the list
//!   only shrinks.

use std::fmt::Write as _;

use clap::{ArgAction, CommandFactory as _};

use super::Cli;

/// The golden's location.
const GOLDEN: &str = "tests/contracts/golden/command-tree.golden.txt";

/// The rendering of one argument: its spelling, then its properties, in a fixed order.
fn arg_line(cmd: &clap::Command, arg: &clap::Arg) -> String {
    let mut line = String::from("  ");
    let values = arg
        .get_value_names()
        .map(|v| {
            v.iter()
                .map(|n| format!("<{n}>"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    if arg.is_positional() {
        line.push_str(&values);
    } else {
        let mut spellings = Vec::new();
        if let Some(s) = arg.get_short() {
            spellings.push(format!("-{s}"));
        }
        if let Some(l) = arg.get_long() {
            spellings.push(format!("--{l}"));
        }
        line.push_str(&spellings.join(", "));
        let takes_value = matches!(arg.get_action(), ArgAction::Set | ArgAction::Append);
        if takes_value && !values.is_empty() {
            line.push(' ');
            line.push_str(&values);
        }
    }
    let mut props: Vec<String> = Vec::new();
    if arg.is_positional() {
        props.push("positional".into());
    }
    if arg.is_last_set() {
        props.push("last".into());
    }
    if arg.is_required_set() {
        props.push("required".into());
    }
    if matches!(arg.get_action(), ArgAction::Append | ArgAction::Count) {
        props.push("repeatable".into());
    }
    if arg.is_global_set() {
        props.push("global".into());
    }
    if arg.is_hide_set() {
        props.push("hidden".into());
    }
    let defaults: Vec<String> = arg
        .get_default_values()
        .iter()
        .map(|v| v.to_string_lossy().into_owned())
        .collect();
    if !defaults.is_empty() && !matches!(arg.get_action(), ArgAction::SetTrue) {
        props.push(format!("default={}", defaults.join(",")));
    }
    if let Some(env) = arg.get_env() {
        props.push(format!("env={}", env.to_string_lossy()));
    }
    let possible = arg.get_possible_values();
    let values: Vec<&str> = possible
        .iter()
        .filter(|v| !v.is_hide_set())
        .map(clap::builder::PossibleValue::get_name)
        .collect();
    if !values.is_empty() && !matches!(arg.get_action(), ArgAction::SetTrue) {
        props.push(format!("values={}", values.join("|")));
    }
    // ⟨review U0-R08 d⟩ `requires` and `required_unless_present`: clap has no getter for
    // either, so they are read from the pinned clap's `Debug` rendering of the argument.
    for (field, label) in [("requires", "requires"), ("r_unless", "required_unless")] {
        let ids = debug_ids(arg, field);
        if !ids.is_empty() {
            let names: Vec<String> = ids.iter().map(|id| spelling(cmd, id)).collect();
            props.push(format!("{label}={}", names.join(",")));
        }
    }
    let mut conflicts: Vec<String> = cmd
        .get_arg_conflicts_with(arg)
        .iter()
        .map(|c| {
            c.get_long()
                .map_or_else(|| c.get_id().to_string(), |l| format!("--{l}"))
        })
        .collect();
    conflicts.sort();
    conflicts.dedup();
    if !conflicts.is_empty() {
        props.push(format!("conflicts={}", conflicts.join(",")));
    }
    if !props.is_empty() {
        line.push_str("  [");
        line.push_str(&props.join(" "));
        line.push(']');
    }
    line
}

/// The quoted IDs of field `field` in the pinned clap's `Debug` rendering of `arg`
/// (`requires: [(IsPresent, "hostname")]`, `r_unless: ["observed"]`).
fn debug_ids(arg: &clap::Arg, field: &str) -> Vec<String> {
    let text = format!("{arg:?}");
    let Some(start) = text.find(&format!("{field}: [")) else {
        return Vec::new();
    };
    let rest = &text[start + field.len() + 3..];
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };
    rest[..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// An argument ID's spelling on this command: `--long`, or the ID of a positional or group.
fn spelling(cmd: &clap::Command, id: &str) -> String {
    cmd.get_arguments()
        .find(|a| a.get_id().as_str() == id)
        .and_then(clap::Arg::get_long)
        .map_or_else(|| id.to_owned(), |l| format!("--{l}"))
}

/// Whether an argument is clap's own (`--help`, `--version`), which the tree leaves out.
fn is_builtin(arg: &clap::Arg) -> bool {
    matches!(
        arg.get_action(),
        ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong | ArgAction::Version
    )
}

fn walk(cmd: &clap::Command, path: &mut Vec<String>, hidden: bool, out: &mut String) {
    let hidden = hidden || cmd.is_hide_set();
    let mut head = path.join(" ");
    if hidden {
        head.push_str("  [hidden]");
    }
    let aliases: Vec<&str> = cmd.get_all_aliases().collect();
    if !aliases.is_empty() {
        let _ = write!(head, "  [aliases={}]", aliases.join(","));
    }
    out.push_str(&head);
    out.push('\n');
    for arg in cmd.get_arguments() {
        // A global argument is listed once, on the command that defines it.
        if is_builtin(arg) || (arg.is_global_set() && path.len() > 1) {
            continue;
        }
        out.push_str(&arg_line(cmd, arg));
        out.push('\n');
    }
    // ⟨review U0-R08 d⟩ Argument groups: their members and whether one is required. The derive
    // adds one implicit group per `Args` struct or variant, named after the Rust type (an
    // uppercase first letter); those restate the arguments and are left out.
    for group in cmd.get_groups().filter(|g| {
        !g.get_id()
            .as_str()
            .starts_with(|c: char| c.is_ascii_uppercase())
    }) {
        let members: Vec<String> = group
            .get_args()
            .map(|id| spelling(cmd, id.as_str()))
            .collect();
        let mut g = group.clone();
        let _ = writeln!(
            out,
            "  group {}: {}{}{}",
            group.get_id(),
            members.join(","),
            if group.is_required_set() {
                "  [required]"
            } else {
                ""
            },
            if g.is_multiple() { "  [multiple]" } else { "" }
        );
    }
    for sub in cmd.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        path.push(sub.get_name().to_owned());
        walk(sub, path, hidden, out);
        path.pop();
    }
}

/// The whole tree, one command path per line with its arguments indented under it.
pub(super) fn command_tree_text() -> String {
    let mut cmd = Cli::command();
    cmd.build();
    let mut out = String::new();
    walk(&cmd, &mut vec!["heimdall".to_owned()], false, &mut out);
    out
}

/// Every command path, with its built command, depth first.
fn every_command() -> Vec<(String, clap::Command)> {
    fn collect(cmd: &clap::Command, path: &str, out: &mut Vec<(String, clap::Command)>) {
        out.push((path.to_owned(), cmd.clone()));
        for sub in cmd.get_subcommands() {
            if sub.get_name() == "help" {
                continue;
            }
            collect(sub, &format!("{path} {}", sub.get_name()), out);
        }
    }
    let mut cmd = Cli::command();
    cmd.build();
    let mut out = Vec::new();
    collect(&cmd, "heimdall", &mut out);
    out
}

/// The command paths whose help is not yet clean, each with its owner. Only shrinks.
const HELP_LINT_PENDING: &[(&str, &str)] = &[];

/// What the help lint refuses, and why: a milestone, an ADR, a section sign, or wording only
/// a test or fixture needs.
fn lint(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    // Drop clap's `[env: NAME=value]`: the value is the test process's, never help text.
    let mut cleaned = String::new();
    for line in text.lines() {
        let line = match line.find("[env: ") {
            Some(i) => &line[..i],
            None => line,
        };
        cleaned.push_str(line);
        cleaned.push('\n');
    }
    let bytes = cleaned.as_bytes();
    for (i, w) in bytes.windows(3).enumerate() {
        let boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if boundary && w[0] == b'M' && w[1] == b'0' && w[2].is_ascii_digit() {
            found.push(format!("milestone `{}`", &cleaned[i..i + 3]));
        }
    }
    if cleaned.contains("ADR-") {
        found.push("an ADR reference".into());
    }
    if cleaned.contains('§') {
        found.push("a section sign".into());
    }
    for word in ["fixture", "HEIMDALL_TEST_", "test-only", "(tests)"] {
        if cleaned
            .to_ascii_lowercase()
            .contains(&word.to_ascii_lowercase())
        {
            found.push(format!("test-only wording `{word}`"));
        }
    }
    found
}

/// ADR-0013 D3: the command tree equals its golden.
#[test]
fn command_tree_matches_its_golden() {
    let text = command_tree_text();
    let path = heimdall_testkit::repo::repo_path(GOLDEN);
    if std::env::var_os("HM_UPDATE_GOLDENS").is_some_and(|v| v == "1") {
        std::fs::write(&path, &text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        return;
    }
    let golden = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (HM_UPDATE_GOLDENS=1 writes it)", path.display()));
    if text != golden {
        let first = text
            .lines()
            .zip(golden.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| text.lines().count().min(golden.lines().count()));
        panic!(
            "the command tree changed at line {} (got {:?}, golden {:?}); a changed path or \
             flag is a contract change (ADR-0013 §2.3)",
            first + 1,
            text.lines().nth(first).unwrap_or(""),
            golden.lines().nth(first).unwrap_or("")
        );
    }
}

/// ADR-0013 D14: no help text names a milestone, an ADR, a section or test-only wording,
/// with an empty exemption list (visible and hidden arguments alike).
#[test]
fn help_text_names_no_milestone_adr_or_section() {
    assert!(
        HELP_LINT_PENDING.is_empty(),
        "D14 exemption list must stay empty: {HELP_LINT_PENDING:?}"
    );
    let mut offenders = Vec::new();
    let mut pending_clean = Vec::new();
    for (path, mut cmd) in every_command() {
        let short = cmd.render_help().to_string();
        let long = cmd.render_long_help().to_string();
        let mut found = lint(&short);
        found.extend(lint(&long));
        for arg in cmd.get_arguments() {
            if let Some(h) = arg.get_help() {
                found.extend(lint(&h.to_string()));
            }
            if let Some(h) = arg.get_long_help() {
                found.extend(lint(&h.to_string()));
            }
        }
        found.sort();
        found.dedup();
        let pending = HELP_LINT_PENDING.iter().any(|(p, _)| *p == path);
        match (found.is_empty(), pending) {
            (false, false) => offenders.push(format!("{path}: {}", found.join(", "))),
            (true, true) => pending_clean.push(path),
            _ => {}
        }
    }
    assert!(
        offenders.is_empty(),
        "help text with references or test-only wording:\n{}",
        offenders.join("\n")
    );
    assert!(
        pending_clean.is_empty(),
        "these paths are clean now; remove them from HELP_LINT_PENDING: {pending_clean:?}"
    );
}

/// The lint itself refuses each kind it names, and passes ordinary text.
#[test]
fn help_lint_self_check() {
    assert!(!lint("Profiles (M02).").is_empty());
    assert!(!lint("See ADR-0007.").is_empty());
    assert!(!lint("spec §11.3").is_empty());
    assert!(!lint("Override the home (fixtures and tests).").is_empty());
    assert!(lint("Profiles: named sets of pairs.").is_empty());
    assert!(lint("--home <DIR>  [env: HEIMDALL_HOME=/tmp/M01/x]").is_empty());
    assert!(lint("IM05 is not a milestone").is_empty());
}

// --- ⟨rev7; review U0-R03⟩ every primitive-index form parses with the real CLI parser ---------

/// One node of a form: a token, or a bracketed group of alternatives (`[a | b]`).
enum Node {
    Tok(String),
    Group(Vec<Vec<Node>>),
}

fn parse_seq(tokens: &mut std::iter::Peekable<std::vec::IntoIter<String>>) -> Vec<Vec<Node>> {
    let mut alternatives = vec![Vec::new()];
    while let Some(t) = tokens.next() {
        match t.as_str() {
            "[" => {
                let group = parse_seq(tokens);
                alternatives
                    .last_mut()
                    .unwrap_or_else(|| unreachable!())
                    .push(Node::Group(group));
            }
            "]" => break,
            "|" => alternatives.push(Vec::new()),
            _ => alternatives
                .last_mut()
                .unwrap_or_else(|| unreachable!())
                .push(Node::Tok(t)),
        }
    }
    alternatives
}

/// A sample value for a placeholder, from the flag before it.
fn sample(placeholder: &str, flag: Option<&str>) -> String {
    match (placeholder, flag) {
        (_, Some("--until")) => "2026-11-24T00:00:00Z".into(),
        (_, Some("--for")) => "2h".into(),
        (_, Some("--timeout-ms" | "--limit" | "--max-events" | "--meta-fd")) => "5".into(),
        ("D:A", _) => "h1:deploy".into(),
        ("<subject>", _) => "destinations".into(),
        ("<argv>", _) => "prog".into(),
        _ => "sample".into(),
    }
}

fn is_placeholder(t: &str) -> bool {
    (t.starts_with('<') && t.ends_with('>'))
        || (!t.is_empty() && t.chars().all(|c| c.is_ascii_uppercase() || c == ':'))
}

/// Every concrete command line a form stands for: each alternative of a group, each `a|b` of a
/// path word, every optional group included (so each of its flags is checked), placeholders
/// filled.
fn expand(seq: &[Node], prefix: &[String]) -> Vec<Vec<String>> {
    let Some((first, rest)) = seq.split_first() else {
        return vec![prefix.to_vec()];
    };
    let mut out = Vec::new();
    match first {
        Node::Group(alternatives) => {
            for alt in alternatives {
                for head in expand(alt, prefix) {
                    out.extend(expand(rest, &head));
                }
            }
        }
        Node::Tok(t) if t == "…" => out.extend(expand(rest, prefix)),
        Node::Tok(t) if t == "--require-*" => {
            let mut p = prefix.to_vec();
            p.push("--require-unattended".into());
            out.extend(expand(rest, &p));
        }
        Node::Tok(t) if is_placeholder(t) => {
            let mut p = prefix.to_vec();
            let flag = prefix
                .last()
                .filter(|f| f.starts_with("--"))
                .map(String::as_str);
            p.push(sample(t, flag));
            out.extend(expand(rest, &p));
        }
        Node::Tok(t) if t.contains('|') && !t.starts_with('-') => {
            for word in t.split('|') {
                let mut p = prefix.to_vec();
                p.push(word.to_owned());
                out.extend(expand(rest, &p));
            }
        }
        Node::Tok(t) => {
            let mut p = prefix.to_vec();
            p.push(t.clone());
            out.extend(expand(rest, &p));
        }
    }
    out
}

/// ADR-0013 D7 (review U0-R03): every CLI form the primitive index publishes parses with this
/// build's own parser, each alternative and each optional flag included, so the index cannot
/// drift from the command tree.
#[test]
fn every_primitive_index_form_parses() {
    use clap::Parser as _;
    let mut checked = 0;
    for group in heimdall_contract::primitives::GROUPS {
        for form in group.forms {
            if form.cli.starts_with('(') {
                continue; // a wire-only form
            }
            let spaced = form.cli.replace('[', " [ ").replace(']', " ] ");
            let tokens: Vec<String> = spaced.split_whitespace().map(str::to_owned).collect();
            let mut iter = tokens.into_iter().peekable();
            let tree = parse_seq(&mut iter);
            assert_eq!(tree.len(), 1, "{}: a top-level `|`", form.cli);
            for line in expand(&tree[0], &[]) {
                assert_eq!(
                    line.first().map(String::as_str),
                    Some("heimdall"),
                    "{}",
                    form.cli
                );
                if let Err(e) = super::Cli::try_parse_from(&line) {
                    panic!("{} does not parse as {line:?}: {e}", form.cli);
                }
                checked += 1;
            }
        }
    }
    assert!(checked >= 12, "only {checked} command lines checked");
}
