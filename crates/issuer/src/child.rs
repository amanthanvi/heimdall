//! The issuer child process, `heimdall internal issuer` (ADR-0008 D3 items 1, 4–6;
//! m03-plan U3 `child::run`): it refuses a terminal stdin, speaks
//! [`crate::protocol`] on its stdin and stdout pipes, opens the state database
//! read-only, signs by reservation (D3 item 4 steps 1–5), and zeroizes K_ca on EOF,
//! on `unload` and on `shutdown`.
//!
//! The signature of [`run`] is frozen in wave 0 (U0); the body is U3's. **Wave 0:**
//! [`run`] reads nothing, loads no key, and returns [`EXIT_UNAVAILABLE`].

use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::sync::Arc;

use heimdall_domain::time::Clock;

use crate::store::SecretStore;

/// The child's exit status when the issuer is not in this build (wave 0), or cannot
/// serve at all (`EX_UNAVAILABLE`, 69). The runtime's supervisor reads any nonzero
/// exit as `crashed` (ADR-0008 D3 item 7).
pub const EXIT_UNAVAILABLE: i32 = 69;

/// Run the issuer over `stdin`/`stdout` until EOF or `shutdown`, reading CA keys
/// from `store` and reservations from the database at `db` (opened read-only), with
/// time from `clock`. Returns the process exit status.
///
/// **Wave 0:** returns [`EXIT_UNAVAILABLE`] without reading `stdin`, writing
/// `stdout`, touching `store` or opening `db`.
#[must_use]
pub fn run<R, W>(
    stdin: R,
    stdout: W,
    store: Box<dyn SecretStore>,
    db: &Path,
    clock: Arc<dyn Clock>,
) -> i32
where
    R: Read + IsTerminal,
    W: Write,
{
    let _ = (stdin, stdout, store, db, clock);
    EXIT_UNAVAILABLE
}
