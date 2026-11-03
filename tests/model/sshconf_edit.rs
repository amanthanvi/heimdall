//! `heimdall-sshconf` block editors for the user's OpenSSH file and the global Git
//! file, and the Git scanner (M02-U2; m02-plan U2; ADR-0007 §2, §3, §4, §5.6).
//!
//! Cargo test target `model_sshconf_edit` hosted by `heimdall-sshconf`. Pure byte
//! functions; no file is touched. Canary values are built at run time and only their
//! absence is asserted. Properties use proptest with 256 cases, a fixed seed unless
//! `PROPTEST_RNG_SEED` is set, and failures persisted beside this file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use heimdall_sshconf::edit::{
    BlockPosition, EditRefusal, IncludeBlock, InsertPlan, detect_newline, find_blocks, plan_insert,
    plan_remove,
};
use heimdall_sshconf::gitedit::{self, scan};
use heimdall_sshconf::render::{
    MarkerId, Newline, RenderPath, render_git_include_block, render_include_block,
};
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};

const MARKER: &str = "hm-00112233445566ff";

fn config() -> ProptestConfig {
    let mut c = ProptestConfig {
        cases: 256,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(0x5353_4843_4f4e_4545);
    }
    c
}

fn marker() -> MarkerId {
    MarkerId::parse(MARKER).unwrap()
}

fn ssh_block(nl: Newline) -> IncludeBlock {
    IncludeBlock {
        marker: marker(),
        bytes: render_include_block(
            &marker(),
            &RenderPath::unix(Path::new("/hm/home/.config/heimdall/ssh_config")).unwrap(),
            nl,
        )
        .unwrap(),
    }
}

fn git_block(nl: Newline) -> IncludeBlock {
    IncludeBlock {
        marker: marker(),
        bytes: render_git_include_block(
            &marker(),
            &RenderPath::unix(Path::new("/hm/home/.config/heimdall/gitconfig")).unwrap(),
            nl,
        )
        .unwrap(),
    }
}

/// The plan leaves every byte outside the block as it was.
fn assert_outside_unchanged(x: &[u8], plan: &InsertPlan, block: &[u8]) {
    let end = plan.offset + block.len();
    assert_eq!(&plan.bytes[..plan.offset], &x[..plan.offset]);
    assert_eq!(&plan.bytes[plan.offset..end], block);
    assert_eq!(&plan.bytes[end..], &x[plan.offset..]);
}

// --- the user file ------------------------------------------------------------------------

#[test]
fn insertion_goes_before_the_first_section_line_or_top_level_directive() {
    let x = b"# my config\n\n# more\nIdentityAgent ~/a.sock\nHost box\n    User u\n";
    let plan = plan_insert(Some(x), &ssh_block(Newline::Lf)).unwrap();
    assert_eq!(plan.offset, "# my config\n\n# more\n".len());
    assert_outside_unchanged(x, &plan, &ssh_block(Newline::Lf).bytes);
    let x = b"\n# c\n  host=box\n    User u\n";
    let plan = plan_insert(Some(x), &ssh_block(Newline::Lf)).unwrap();
    assert_eq!(plan.offset, "\n# c\n".len());
    let found = find_blocks(&plan.bytes);
    assert_eq!(found.len(), 1);
    assert!(found[0].intact);
    assert_eq!(found[0].position, BlockPosition::BeforeFirstSection);
}

#[test]
fn round_trip_crlf_bom_no_trailing_newline_empty_and_missing() {
    let cases: [&[u8]; 6] = [
        b"Host a\r\n    User u\r\n",
        b"\xEF\xBB\xBF# c\nHost a\n",
        b"# only a comment",
        b"Host a\n    User u",
        b"",
        b"\xEF\xBB\xBF",
    ];
    for x in cases {
        let nl = detect_newline(x).unwrap_or(Newline::Lf);
        let block = ssh_block(nl);
        let plan = plan_insert(Some(x), &block).unwrap();
        assert_eq!(plan.had_bom, x.starts_with(b"\xEF\xBB\xBF"));
        assert_eq!(plan.newline, nl);
        assert_outside_unchanged(x, &plan, &block.bytes);
        assert_eq!(
            plan_remove(&plan.bytes, &marker(), &block.bytes).unwrap(),
            x
        );
    }
    // An unterminated final comment goes below B, never joined to it.
    let plan = plan_insert(Some(b"# a\n# b"), &ssh_block(Newline::Lf)).unwrap();
    assert_eq!(plan.offset, 4);
    assert!(
        plan.bytes
            .ends_with(b"<<< heimdall managed include (id hm-00112233445566ff)\n# b")
    );
    // The BOM stays first.
    let plan = plan_insert(Some(b"\xEF\xBB\xBFHost a\n"), &ssh_block(Newline::Lf)).unwrap();
    assert_eq!(plan.offset, 3);
    // A missing file: the block alone, and its removal leaves nothing.
    let block = ssh_block(Newline::Lf);
    let plan = plan_insert(None, &block).unwrap();
    assert_eq!(plan.bytes, block.bytes);
    assert_eq!(plan.offset, 0);
    assert!(
        plan_remove(&plan.bytes, &marker(), &block.bytes)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn line_ending_mismatch_and_wide_encodings_are_refused() {
    assert_eq!(
        plan_insert(Some(b"Host a\r\n"), &ssh_block(Newline::Lf)),
        Err(EditRefusal::UnsupportedEncoding)
    );
    assert_eq!(
        plan_insert(Some(b"\xFF\xFEH\x00"), &ssh_block(Newline::Lf)),
        Err(EditRefusal::UnsupportedEncoding)
    );
}

#[test]
fn a_duplicate_marker_is_refused() {
    let block = ssh_block(Newline::Lf);
    let once = plan_insert(Some(b"Host a\n"), &block).unwrap().bytes;
    assert_eq!(
        plan_insert(Some(&once), &block),
        Err(EditRefusal::DuplicateMarker)
    );
    let mut twice = block.bytes.clone();
    twice.extend_from_slice(&once);
    assert_eq!(
        plan_remove(&twice, &marker(), &block.bytes),
        Err(EditRefusal::DuplicateMarker)
    );
    assert_eq!(
        plan_remove(b"Host a\n", &marker(), &block.bytes),
        Err(EditRefusal::MarkerMissing)
    );
}

#[test]
fn an_edited_marker_block_is_marker_edited_with_its_lines() {
    let block = ssh_block(Newline::Lf);
    let x = b"# top\nHost a\n";
    let mut edited = plan_insert(Some(x), &block).unwrap().bytes;
    let text = String::from_utf8(edited.clone()).unwrap();
    let text = text.replace("Include \"/hm/home/.config", "Include \"/hm/home/.other");
    edited = text.into_bytes();
    // `find_blocks` knows no expected path: a block Heimdall could have rendered is
    // structurally intact. The removal against the recorded bytes catches the edit.
    let found = find_blocks(&edited);
    assert_eq!(found.len(), 1);
    assert!(found[0].intact);
    assert_eq!(
        plan_remove(&edited, &marker(), &block.bytes),
        Err(EditRefusal::MarkerEdited { lines: vec![3] })
    );
    // A line added inside the block is a structural edit: not intact.
    let text = String::from_utf8(plan_insert(Some(x), &block).unwrap().bytes).unwrap();
    let added = text.replacen("Include", "User injected\nInclude", 1);
    let found = find_blocks(added.as_bytes());
    assert_eq!(found.len(), 1);
    assert!(!found[0].intact);
    assert_eq!(
        plan_remove(added.as_bytes(), &marker(), &block.bytes),
        Err(EditRefusal::MarkerEdited {
            lines: vec![3, 4, 5]
        })
    );
    // A removed end marker: the begin line alone is reported, never intact.
    let text = String::from_utf8(plan_insert(Some(x), &block).unwrap().bytes).unwrap();
    let cut: String = text
        .lines()
        .filter(|l| !l.starts_with("# <<<"))
        .map(|l| format!("{l}\n"))
        .collect();
    let found = find_blocks(cut.as_bytes());
    assert_eq!(found.len(), 1);
    assert!(!found[0].intact);
    assert!(matches!(
        plan_remove(cut.as_bytes(), &marker(), &block.bytes),
        Err(EditRefusal::MarkerEdited { .. })
    ));
    assert_eq!(
        plan_insert(Some(cut.as_bytes()), &block),
        Err(EditRefusal::DuplicateMarker)
    );
}

#[test]
fn a_marker_moved_below_host_is_conditional() {
    let block = String::from_utf8(ssh_block(Newline::Lf).bytes).unwrap();
    let moved = format!("# top\nHost a\n    User u\n{block}Host b\n");
    let found = find_blocks(moved.as_bytes());
    assert_eq!(found.len(), 1);
    assert!(found[0].intact);
    match &found[0].position {
        BlockPosition::Conditional(span) => assert_eq!(span.line, 2),
        other => panic!("{other:?}"),
    }
    // Removal still restores the rest exactly (removal is narrowing).
    let out = plan_remove(moved.as_bytes(), &marker(), block.as_bytes()).unwrap();
    assert_eq!(out, b"# top\nHost a\n    User u\nHost b\n");
    // Below a top-level directive it is not where ADR-0007 §3 puts it either.
    let below = format!("IdentityAgent ~/x.sock\n{block}");
    assert!(matches!(
        find_blocks(below.as_bytes())[0].position,
        BlockPosition::Conditional(_)
    ));
}

#[test]
fn a_malformed_block_to_insert_is_refused() {
    let mut block = ssh_block(Newline::Lf);
    block.bytes.extend_from_slice(b"User extra\n");
    assert!(matches!(
        plan_insert(Some(b"Host a\n"), &block),
        Err(EditRefusal::MarkerEdited { .. })
    ));
}

/// Lines of a user file, as bytes: directives, sections, comments, blanks, odd bytes.
fn ssh_line() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(b"Host box".to_vec()),
        Just(b"  match host x exec \"y\"".to_vec()),
        Just(b"HostName=h.example".to_vec()),
        Just(b"    User u".to_vec()),
        Just(b"# comment".to_vec()),
        Just(b"".to_vec()),
        Just(b"   ".to_vec()),
        Just(b"\t# indented comment".to_vec()),
        Just(b"Include other.conf".to_vec()),
        Just(b"# caf\xE9 latin-1".to_vec()),
        prop::collection::vec(
            any::<u8>().prop_filter("no newline", |b| *b != b'\n'),
            0..12
        ),
    ]
}

fn ssh_file() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<bool>(),
        prop::collection::vec(ssh_line(), 0..8),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(bom, lines, crlf, trailing)| {
            let mut out = Vec::new();
            if bom {
                out.extend_from_slice(b"\xEF\xBB\xBF");
            }
            let nl: &[u8] = if crlf { b"\r\n" } else { b"\n" };
            for (i, l) in lines.iter().enumerate() {
                out.extend_from_slice(l);
                if i + 1 < lines.len() || trailing {
                    out.extend_from_slice(nl);
                }
            }
            out
        })
}

fn git_line() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(b"[core]".to_vec()),
        Just(b"[includeIf \"gitdir:~/w/\"]".to_vec()),
        Just(b"\teditor = vi".to_vec()),
        Just(b"; semicolon comment".to_vec()),
        Just(b"# hash comment".to_vec()),
        Just(b"".to_vec()),
        Just(b"\tpath = x \\".to_vec()),
        prop::collection::vec(
            any::<u8>().prop_filter("no newline", |b| *b != b'\n'),
            0..12
        ),
    ]
}

fn git_file() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<bool>(),
        prop::collection::vec(git_line(), 0..8),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(bom, lines, crlf, trailing)| {
            let mut out = Vec::new();
            if bom {
                out.extend_from_slice(b"\xEF\xBB\xBF");
            }
            let nl: &[u8] = if crlf { b"\r\n" } else { b"\n" };
            for (i, l) in lines.iter().enumerate() {
                out.extend_from_slice(l);
                if i + 1 < lines.len() || trailing {
                    out.extend_from_slice(nl);
                }
            }
            out
        })
}

proptest! {
    #![proptest_config(config())]

    /// `plan_remove(plan_insert(x)) == x` byte for byte, the block lands before the
    /// first directive and is found intact there, and no byte outside it changes.
    #[test]
    fn ssh_insert_then_remove_is_identity(x in ssh_file(), missing in prop::bool::weighted(0.05)) {
        let nl = detect_newline(&x).unwrap_or(Newline::Lf);
        let block = ssh_block(nl);
        let existing = if missing { None } else { Some(x.as_slice()) };
        match plan_insert(existing, &block) {
            Ok(plan) => {
                let base: &[u8] = existing.unwrap_or_default();
                assert_outside_unchanged(base, &plan, &block.bytes);
                let found = find_blocks(&plan.bytes);
                prop_assert_eq!(found.len(), 1);
                prop_assert!(found[0].intact);
                prop_assert_eq!(&found[0].position, &BlockPosition::BeforeFirstSection);
                prop_assert_eq!(found[0].range.clone(), plan.offset..plan.offset + block.bytes.len());
                prop_assert_eq!(plan_remove(&plan.bytes, &marker(), &block.bytes).unwrap(), base);
            }
            Err(refusal) => {
                // Only wide encodings refuse; the generator never writes a marker.
                prop_assert_eq!(refusal, EditRefusal::UnsupportedEncoding);
                prop_assert!(x.starts_with(b"\xFF\xFE") || x.starts_with(b"\xFE\xFF") || x.starts_with(b"\x00\x00\xFE\xFF"));
            }
        }
    }

    /// The same contract for Git configuration text.
    #[test]
    fn git_insert_then_remove_is_identity(x in git_file(), missing in prop::bool::weighted(0.05)) {
        let nl = detect_newline(&x).unwrap_or(Newline::Lf);
        let block = git_block(nl);
        let existing = if missing { None } else { Some(x.as_slice()) };
        match gitedit::plan_insert_top(existing, &block) {
            Ok(plan) => {
                let base: &[u8] = existing.unwrap_or_default();
                assert_outside_unchanged(base, &plan, &block.bytes);
                let found = gitedit::find_blocks(&plan.bytes);
                prop_assert_eq!(found.len(), 1);
                prop_assert!(found[0].intact);
                prop_assert_eq!(&found[0].position, &BlockPosition::BeforeFirstSection);
                prop_assert_eq!(gitedit::plan_remove(&plan.bytes, &marker(), &block.bytes).unwrap(), base);
                // The scanner sees exactly Heimdall's include among the includes.
                let s = scan(&plan.bytes);
                prop_assert!(s.includes.iter().any(|i| i.path == "/hm/home/.config/heimdall/gitconfig" && !i.conditional));
            }
            Err(refusal) => {
                prop_assert_eq!(refusal, EditRefusal::UnsupportedEncoding);
            }
        }
    }
}

// --- Git configuration text --------------------------------------------------------------

#[test]
fn git_insertion_goes_before_the_first_section_after_comments() {
    let x = b"\xEF\xBB\xBF# hash\n; semi\n\n[user]\n\tname = fixture\n";
    let block = git_block(Newline::Lf);
    let plan = gitedit::plan_insert_top(Some(x), &block).unwrap();
    assert_eq!(plan.offset, 3 + "# hash\n; semi\n\n".len());
    assert_outside_unchanged(x, &plan, &block.bytes);
    let x = b"[core]\r\n\teditor = vi\r\n";
    let block = git_block(Newline::CrLf);
    let plan = gitedit::plan_insert_top(Some(x), &block).unwrap();
    assert_eq!(plan.offset, 0);
    assert_eq!(
        gitedit::plan_remove(&plan.bytes, &marker(), &block.bytes).unwrap(),
        x
    );
    // Refusals mirror the user-file editor.
    assert_eq!(
        gitedit::plan_insert_top(Some(&plan.bytes), &block),
        Err(EditRefusal::DuplicateMarker)
    );
    let moved = format!(
        "[core]\n\teditor = vi\n{}",
        String::from_utf8(git_block(Newline::Lf).bytes).unwrap()
    );
    let found = gitedit::find_blocks(moved.as_bytes());
    assert!(found[0].intact);
    assert!(matches!(found[0].position, BlockPosition::Conditional(_)));
    let edited = moved.replace("\tpath = \"/hm", "\tpath = \"/xx");
    assert_eq!(
        gitedit::plan_remove(edited.as_bytes(), &marker(), &git_block(Newline::Lf).bytes),
        Err(EditRefusal::MarkerEdited { lines: vec![5] })
    );
}

fn canary() -> String {
    // Built at run time: the literal never appears in the source.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(7);
    format!("{}_CANARY_U2_{nanos:08x}", "HEIMDALL")
}

#[test]
fn scan_reports_includes_conditional_includes_and_keys_never_values() {
    let secret = canary();
    let text = format!(
        "[include]\n\tpath = /hm/inc/a.conf\n\tnote = {secret}\n\
         [includeIf \"gitdir:~/work/\"]\n\tpath = \"/hm/inc/work conf\" ; trailing\n\
         [core]\n\tsshCommand = \"ssh -o {secret}\"\n\teditor = vi \\\n\t\tcontinued {secret}\n\
         [Core \"Sub\"]\n\tSSHCommand\n\
         [core.old]\n\tsshcommand = {secret}\n\
         [include] path = /hm/inc/same-line.conf\n"
    );
    let s = scan(text.as_bytes());
    let rendered = format!("{s:?}");
    assert!(
        !rendered.contains("HEIMDALL_CANARY_"),
        "a value leaked: {rendered}"
    );
    let paths: Vec<(&str, bool)> = s
        .includes
        .iter()
        .map(|i| (i.path.as_str(), i.conditional))
        .collect();
    assert_eq!(
        paths,
        vec![
            ("/hm/inc/a.conf", false),
            ("/hm/inc/work conf", true),
            ("/hm/inc/same-line.conf", false),
        ]
    );
    let ssh_commands: Vec<(&str, Option<&str>, u32)> = s
        .keys
        .iter()
        .filter(|k| k.key == "sshcommand")
        .map(|k| (k.section.as_str(), k.subsection.as_deref(), k.span.line))
        .collect();
    assert_eq!(
        ssh_commands,
        vec![
            ("core", None, 7),
            ("core", Some("Sub"), 11),
            ("core", Some("old"), 13)
        ]
    );
    // The non-path key of an include section is a key, never an include.
    assert!(
        s.keys
            .iter()
            .any(|k| k.section == "include" && k.key == "note")
    );
    // The continuation line is part of `editor`, not a key of its own.
    assert!(!s.keys.iter().any(|k| k.key == "continued"));
    assert!(s.keys.iter().any(|k| k.key == "editor" && k.span.line == 8));
    // An unterminated quote in an include path is reported with an empty path, which
    // the caller cannot resolve (fail closed).
    let s = scan(b"[include]\n\tpath = \"/hm/unterminated\n");
    assert_eq!(s.includes.len(), 1);
    assert_eq!(s.includes[0].path, "");
}
