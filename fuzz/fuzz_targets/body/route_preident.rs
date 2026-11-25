//! Boundary 14 (ADR-0014 §2.1), the route helper's pre-identification buffer: the bytes a
//! server (or a relay in front of it) sends before its SSH identification line, scanned by
//! the public `heimdall_app::routes::failover::scan_identification` with the helper's own
//! bounds (8 KiB and 32 lines before the line, the line at most 255 bytes).
//!
//! The first byte is the read size the helper sees; the rest is the server's stream. The
//! invariants: the scan never asks for more past its bounds; an identification it reports
//! ends a line that starts with `SSH-`, within the bounds; and scanning after every read
//! decides exactly what scanning the whole stream decides (the helper scans as bytes arrive).
//!
//! Shared by the fuzz target `route_preident` and the seed test
//! `tests/adversarial/m08_fuzz_seeds.rs`.

use heimdall_app::routes::FailoverConfig;
use heimdall_app::routes::failover::{IDENTIFICATION_LINE_MAX, Scan, scan_identification};

/// Scan `data` (module docs) and return the whole stream's answer; panics (a finding) when an
/// invariant breaks.
pub fn run(data: &[u8]) -> Scan {
    let Some((&step, stream)) = data.split_first() else {
        return Scan::NeedMore;
    };
    let config = FailoverConfig::default();
    let bound = config.max_pre_identification_bytes + IDENTIFICATION_LINE_MAX;
    let whole = scan_identification(stream, &config);
    match whole {
        Scan::NeedMore => assert!(
            stream.len() < bound,
            "the scan asks for more past its bounds"
        ),
        Scan::Identified { end } => {
            assert!(
                end <= stream.len() && end <= bound,
                "an identification past the bounds"
            );
            let before = stream.get(..end.saturating_sub(1)).unwrap_or_default();
            let start = before
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |i| i + 1);
            assert!(
                stream.get(end.saturating_sub(1)) == Some(&b'\n')
                    && stream.get(start..).is_some_and(|l| l.starts_with(b"SSH-")),
                "an identification that is not an `SSH-` line"
            );
            assert!(
                before.iter().filter(|b| **b == b'\n').count()
                    <= config.max_pre_identification_lines,
                "an identification after more lines than the bound"
            );
        }
        Scan::Overflow => {}
    }
    let step = usize::from(step).max(1);
    let mut len = 0;
    while len < stream.len() {
        len = (len + step).min(stream.len());
        let now = scan_identification(stream.get(..len).unwrap_or_default(), &config);
        if now != Scan::NeedMore {
            assert_eq!(
                now, whole,
                "a scan after a read decided otherwise than the whole stream"
            );
            break;
        }
    }
    whole
}
