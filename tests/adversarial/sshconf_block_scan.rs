//! The managed-block scan behind `edit::find_blocks` and `gitedit::find_blocks` grows
//! linearly with the line count (M08-W2-F1, found by fuzzing: it was quadratic, with
//! a fresh end-marker `String` for every later line of every unterminated begin marker
//! and a reclassification of every earlier line for every block).
//!
//! Cargo test target `adversarial_sshconf_block_scan` hosted by `heimdall-sshconf`, in
//! its own binary because it installs a counting global allocator. Deterministic: it
//! counts allocations, never time. The allocator counts only on the thread that asked,
//! so tests running in parallel do not disturb each other's counts. Pure byte
//! functions; no file is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use heimdall_sshconf::edit::{self, BlockPosition, EditRefusal, FoundBlock};
use heimdall_sshconf::gitedit;
use heimdall_sshconf::render::MarkerId;

// --- a counting allocator ------------------------------------------------------------

/// [`System`], counting allocations (including reallocations) on threads that ask.
struct Counting;

thread_local! {
    /// This thread's allocation count, `None` when it is not counting. A `const`
    /// initializer and no destructor, so reading it never allocates.
    static COUNT: Cell<Option<u64>> = const { Cell::new(None) };
}

fn bump() {
    // `try_with`: a thread being torn down still allocates and must not panic here.
    let _ = COUNT.try_with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + 1));
        }
    });
}

// `GlobalAlloc` is an `unsafe` trait. Every method forwards its arguments unchanged to
// `System`, whose contract is the caller's; the only addition is `bump`, which touches a
// thread-local `Cell` and never allocates.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump();
        // SAFETY: forwarded unchanged; the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump();
        // SAFETY: as `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump();
        // SAFETY: `ptr` came from this allocator, which is `System`; forwarded unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator, which is `System`; forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// `f()` and the allocations it made on this thread.
fn allocations<T>(f: impl FnOnce() -> T) -> (T, u64) {
    COUNT.with(|c| c.set(Some(0)));
    let out = f();
    let n = COUNT.with(|c| c.replace(None));
    (out, n.unwrap_or(0))
}

// --- marker lines ----------------------------------------------------------------------

fn marker(k: usize) -> String {
    format!("hm-{k:016x}")
}

fn begin(id: &str) -> String {
    format!("# >>> heimdall managed include (id {id}); remove with `heimdall setup rollback`")
}

fn end(id: &str) -> String {
    format!("# <<< heimdall managed include (id {id})")
}

// --- growth with unterminated begin markers --------------------------------------------

const SIZES: [usize; 3] = [2_000, 4_000, 8_000];

/// `n` lines, each the begin marker of a different block, none with an end marker.
fn unterminated(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for k in 0..n {
        out.extend_from_slice(begin(&marker(k)).as_bytes());
        out.push(b'\n');
    }
    out
}

/// The scan of `unterminated(n)` for each size: each begin line is its own block, not
/// intact (an unterminated begin marker fails closed), before the first section (a
/// marker line is a comment in both languages). Allocations at twice the lines stay
/// under 2.5 times as many.
fn assert_linear(flavor: &str, find: fn(&[u8]) -> Vec<FoundBlock>) {
    let mut counts = Vec::new();
    for n in SIZES {
        let input = unterminated(n);
        let (blocks, allocs) = allocations(|| find(&input));
        assert_eq!(
            blocks.len(),
            n,
            "{flavor}: one block per begin line at n = {n}"
        );
        let mut offset = 0;
        for (k, b) in blocks.iter().enumerate() {
            let id = marker(k);
            let len = begin(&id).len() + 1;
            assert_eq!(b.marker.as_str(), id, "{flavor}: block {k} at n = {n}");
            assert_eq!(
                b.range,
                offset..offset + len,
                "{flavor}: block {k} at n = {n}"
            );
            assert!(!b.intact, "{flavor}: block {k} at n = {n} is not intact");
            assert_eq!(
                b.position,
                BlockPosition::BeforeFirstSection,
                "{flavor}: block {k} at n = {n}"
            );
            offset += len;
        }
        assert_eq!(offset, input.len());
        counts.push(allocs);
    }
    for (pair, sizes) in counts.windows(2).zip(SIZES.windows(2)) {
        assert!(
            pair[1] * 2 < pair[0] * 5,
            "{flavor}: {} allocations at {} lines is not under 2.5 x {} at {} lines \
             (counts at {SIZES:?}: {counts:?})",
            pair[1],
            sizes[1],
            pair[0],
            sizes[0],
        );
    }
}

#[test]
fn ssh_block_scan_allocations_grow_linearly_with_unterminated_begin_markers() {
    assert_linear("ssh", edit::find_blocks);
}

#[test]
fn git_block_scan_allocations_grow_linearly_with_unterminated_begin_markers() {
    assert_linear("git", gitedit::find_blocks);
}

// --- mixed blocks, pinned to the pre-fix scan --------------------------------------------
//
// The expected values below are what the quadratic scan (main at f0ee5c87) returned for
// these inputs, captured before the fix: the linear scan must report the same blocks,
// ranges, intact flags, positions and order, and `plan_remove` the same results.

const A: &str = "hm-00000000000000a1";
const B: &str = "hm-00000000000000b2";
const C: &str = "hm-00000000000000c3";
const D: &str = "hm-00000000000000d4";
const E: &str = "hm-00000000000000e5";
const F: &str = "hm-00000000000000f6";
const G: &str = "hm-0000000000000007";
const H: &str = "hm-0000000000000008";

fn text(lines: &[&[u8]]) -> Vec<u8> {
    lines.concat()
}

fn line(s: &str) -> Vec<u8> {
    format!("{s}\n").into_bytes()
}

fn crlf(s: &str) -> Vec<u8> {
    format!("{s}\r\n").into_bytes()
}

/// One line per block: marker, byte range, intact, position.
fn summary(blocks: &[FoundBlock]) -> Vec<String> {
    blocks
        .iter()
        .map(|b| {
            format!(
                "{} {}..{} intact={} {:?}",
                b.marker.as_str(),
                b.range.start,
                b.range.end,
                b.intact,
                b.position
            )
        })
        .collect()
}

/// An OpenSSH file with terminated and unterminated blocks interleaved: an intact block,
/// an unterminated begin with a near-miss end line, a block inside a section with an
/// extra line, a block that swallows another block's begin, an orphan end, a begin
/// whose only end is above it, a non-UTF-8 line, an indented begin, a CRLF block, a
/// duplicate marker, and a final end marker without a newline.
fn mixed_ssh() -> Vec<u8> {
    text(&[
        &line("# a user comment"),
        &line(""),
        &line(&begin(A)),
        &line("Include \"/hm/p\""),
        &line(&end(A)),
        &line(&begin(B)),
        &line(&format!("{})", end(B))),
        &line("Host one"),
        &line("  User x"),
        &line(&begin(C)),
        &line("Include \"/hm/p\""),
        &line("ForwardAgent no"),
        &line(&end(C)),
        &line(&begin(D)),
        &line(&begin(E)),
        &line(&format!("  {} \t", end(D))),
        &line(&end(E)),
        &line(&begin(E)),
        b"\xff\xfe not utf-8\n",
        &line(&format!("   {}", begin(F))),
        &line("Include \"/hm/q\""),
        &line(&end(F)),
        &line("Match all"),
        &crlf(&begin(G)),
        &crlf("Include \"/hm/p\""),
        &crlf(&end(G)),
        &line(&begin(A)),
        &line("Include \"/hm/p\""),
        &line(&end(A)),
        &line(&begin(H)),
        &line("Include \"/hm/p\""),
        end(H).as_bytes(),
    ])
}

/// The same shapes in Git configuration text, after a BOM.
fn mixed_git() -> Vec<u8> {
    text(&[
        b"\xEF\xBB\xBF",
        &line("# a git comment"),
        &line("; another"),
        &line(&begin(A)),
        &line("[include]"),
        &line("\tpath = \"/hm/p\""),
        &line(&end(A)),
        &line(&begin(B)),
        &line(&format!("{})", end(B))),
        &line("[core]"),
        &line("\teditor = vi"),
        &line(&begin(C)),
        &line("[include]"),
        &line("\tpath = \"/hm/p\""),
        &line(&end(C)),
        &line(&begin(D)),
        &line(&begin(E)),
        &line(&format!("\t{} ", end(D))),
        &line(&end(E)),
        &line(&begin(E)),
        b"\xff\xfe = not utf-8\n",
        &line(&format!("  {}", begin(F))),
        &line("[include]"),
        &line("\tpath = \"/hm/q\""),
        &line(&end(F)),
        &line("[user]"),
        &crlf(&begin(G)),
        &crlf("[include]"),
        &crlf("\tpath = \"/hm/p\""),
        &crlf(&end(G)),
        &line(&begin(A)),
        &line("[include]"),
        &line("\tpath = \"/hm/p\""),
        &line(&end(A)),
        &line(&begin(H)),
        &line("[include]"),
        &line("\tpath = \"/hm/p\""),
        end(H).as_bytes(),
    ])
}

fn ssh_block(id: &str) -> Vec<u8> {
    text(&[
        &line(&begin(id)),
        &line("Include \"/hm/p\""),
        &line(&end(id)),
    ])
}

fn git_block(id: &str) -> Vec<u8> {
    text(&[
        &line(&begin(id)),
        &line("[include]"),
        &line("\tpath = \"/hm/p\""),
        &line(&end(id)),
    ])
}

/// `edit::plan_remove` or `gitedit::plan_remove`.
type PlanRemove = fn(&[u8], &MarkerId, &[u8]) -> Result<Vec<u8>, EditRefusal>;

/// `plan_remove` of every marker with its canonical block: one line each, marker and
/// result (the remaining length when the block is removed).
fn removals(x: &[u8], block: fn(&str) -> Vec<u8>, remove: PlanRemove) -> Vec<String> {
    [A, B, C, D, E, F, G, H]
        .iter()
        .map(|id| {
            let marker = MarkerId::parse(id).unwrap();
            let r = remove(x, &marker, &block(id)).map(|out| out.len());
            format!("{id} {r:?}")
        })
        .collect()
}

#[test]
fn mixed_ssh_blocks_match_the_pre_fix_scan() {
    let x = mixed_ssh();
    assert_eq!(
        summary(&edit::find_blocks(&x)),
        [
            "hm-00000000000000a1 18..185 intact=true BeforeFirstSection",
            "hm-00000000000000b2 185..280 intact=false Conditional(Span { source: SourceId(0), line: 4 })",
            "hm-00000000000000c3 355..538 intact=false Conditional(Span { source: SourceId(0), line: 8 })",
            "hm-00000000000000d4 538..788 intact=false Conditional(Span { source: SourceId(0), line: 8 })",
            "hm-00000000000000e5 844..939 intact=false Conditional(Span { source: SourceId(0), line: 8 })",
            "hm-00000000000000f6 952..1122 intact=false Conditional(Span { source: SourceId(0), line: 8 })",
            "hm-0000000000000007 1132..1302 intact=true Conditional(Span { source: SourceId(0), line: 23 })",
            "hm-00000000000000a1 1302..1469 intact=true Conditional(Span { source: SourceId(0), line: 23 })",
            "hm-0000000000000008 1469..1635 intact=false Conditional(Span { source: SourceId(0), line: 23 })",
        ]
    );
    // The edited lines are counted from the block's first line, so they pin it too.
    assert_eq!(
        removals(&x, ssh_block, edit::plan_remove),
        [
            "hm-00000000000000a1 Err(DuplicateMarker)",
            "hm-00000000000000b2 Err(MarkerEdited { lines: [7, 8] })",
            "hm-00000000000000c3 Err(MarkerEdited { lines: [12, 13] })",
            "hm-00000000000000d4 Err(MarkerEdited { lines: [15, 16] })",
            "hm-00000000000000e5 Err(MarkerEdited { lines: [19, 20] })",
            "hm-00000000000000f6 Err(MarkerEdited { lines: [20, 21] })",
            "hm-0000000000000007 Err(MarkerEdited { lines: [24, 25, 26] })",
            "hm-0000000000000008 Err(MarkerEdited { lines: [32] })",
        ]
    );
}

#[test]
fn mixed_git_blocks_match_the_pre_fix_scan() {
    let x = mixed_git();
    assert_eq!(
        summary(&gitedit::find_blocks(&x)),
        [
            "hm-00000000000000a1 29..206 intact=true BeforeFirstSection",
            "hm-00000000000000b2 206..301 intact=false Conditional(Span { source: SourceId(0), line: 4 })",
            "hm-00000000000000c3 378..555 intact=true Conditional(Span { source: SourceId(0), line: 9 })",
            "hm-00000000000000d4 555..803 intact=false Conditional(Span { source: SourceId(0), line: 12 })",
            "hm-00000000000000e5 859..954 intact=false Conditional(Span { source: SourceId(0), line: 12 })",
            "hm-00000000000000f6 969..1148 intact=false Conditional(Span { source: SourceId(0), line: 12 })",
            "hm-0000000000000007 1155..1336 intact=true Conditional(Span { source: SourceId(0), line: 25 })",
            "hm-00000000000000a1 1336..1513 intact=true Conditional(Span { source: SourceId(0), line: 27 })",
            "hm-0000000000000008 1513..1689 intact=false Conditional(Span { source: SourceId(0), line: 31 })",
        ]
    );
    assert_eq!(
        removals(&x, git_block, gitedit::plan_remove),
        [
            "hm-00000000000000a1 Err(DuplicateMarker)",
            "hm-00000000000000b2 Err(MarkerEdited { lines: [8, 9, 10] })",
            "hm-00000000000000c3 Ok(1512)",
            "hm-00000000000000d4 Err(MarkerEdited { lines: [16, 17, 18] })",
            "hm-00000000000000e5 Err(MarkerEdited { lines: [20, 21, 22] })",
            "hm-00000000000000f6 Err(MarkerEdited { lines: [21, 23] })",
            "hm-0000000000000007 Err(MarkerEdited { lines: [26, 27, 28, 29] })",
            "hm-0000000000000008 Err(MarkerEdited { lines: [37] })",
        ]
    );
}
