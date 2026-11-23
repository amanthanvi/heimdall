//! Heimdall's store generations (M08 U2b, the provisional core; ADR-0014 §3.6).
//!
//! **What is here.**
//!
//! * [`StateDir`]: generation directories under `generations/`, the `CURRENT` pointer and
//!   its switch (temporary file, sync, rename, directory sync), the per-generation
//!   [`OperationRecord`], the staging [`Intent`], the adoption order
//!   ([`StateDir::adopt`]: intent, fence, copy, publication, completion) and start-up
//!   recovery that trusts only the pointer ([`StateDir::open`]).
//! * [`Ledger`]: the append-only request ledger outside every generation, with the
//!   retention rule of ADR-0006 §7.4 ([`ledger::may_trim`]).
//! * [`Fs`]: the file-system calls, as a trait. [`RealFs`] is the real one; [`FaultFs`]
//!   fails, stops or parks the process at any one step, for the fault tests.
//!
//! **What is not here.** The crate has no workspace edge and never touches SQLite. The
//! store copy is a function the caller supplies, and the rule that every copy goes through
//! SQLite is the caller's. The restore's sanitization, the carry-forward, the quarantine
//! states, the epoch on requests, the fence records in the store, identity binding of a
//! backup and the instance lock all belong to the store and the runtime, and wait for the
//! contract handoff (m08-plan rule 2, U0).
//!
//! **Decisions this crate makes that ADR-0014 does not spell out.** The contract owner
//! ruled on them on 2026-11-23: items 1 to 3 and the first sentence of item 4 are accepted;
//! recovery from `state_corrupt` (item 4) is deferred to U0; item 5 is accepted
//! provisionally (ADR-0014 §7, delta H15); item 6 is accepted with the progress mark.
//!
//! 1. *A staging intent for every operation,* not only for adoption. Start-up removes a
//!    staged leftover, and the only safe way to know one is that a durable intent named
//!    it before it was created. Without that, start-up would judge a directory by its
//!    content or name, which the ADR forbids.
//! 2. *Generations live in `generations/`,* one level under the state directory, so the
//!    directory's own entry is synced as well as the state directory's.
//! 3. *Migration notes are a separate append-only file* in the generation, so noting a
//!    migration never rewrites the operation record.
//! 4. *A missing pointer with generations present is `state_corrupt`,* never an empty
//!    state. Recovery from `state_corrupt` (restore or reset with no trusted current
//!    record) is not implemented here: what the epoch and the identity are bound to in
//!    that case is an authority question, deferred to U0. Until then every operation is
//!    refused in that state. The expected direction, not built: an attended recovery
//!    with a typed confirmation, never non-interactive, that says the epoch and the
//!    identity binding start fresh; restore from a backup the owner names, reset otherwise.
//! 5. *Windows:* the pointer's rename is `std::fs::rename` followed by a flush of the
//!    renamed file. **Windows durability is therefore weaker than ADR-0014 §3.6 asks
//!    until the product wiring lands:** the ADR's write-through rename (`MoveFileExW`
//!    with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`) needs an FFI call. It
//!    goes into the existing Windows platform module that already holds the workspace's
//!    other `unsafe` Windows calls, when this crate is wired into the product (U2b), and
//!    reaches this crate through [`Fs::rename_over`]. No `unsafe` module is added here.
//! 6. *An interrupted first publication (install or adoption) is discarded and run again,*
//!    the ADR's rule for an adoption applied to an install too, **but only when the pointer
//!    was never written** (ruled 2026-11-23). The intent records its progress durably: it
//!    is marked `switching` after the temporary pointer is synced and before the rename.
//!    With no pointer, a pending intent, or a switching one whose temporary pointer is
//!    still there naming its generation, means the rename never happened: the staged
//!    generation is discarded. A switching intent without the temporary pointer, or a
//!    complete one, means the pointer was written and removed from outside: that is
//!    `state_corrupt`, and nothing is removed.
//!
//! **Not established by any test:** durability across power loss. The fault tests inject
//! I/O errors, stop the process in place and kill a child process at each step; they cut
//! no power.

pub mod fs;
pub mod generations;
pub mod ledger;
pub mod record;

pub use fs::{Action, Fault, FaultFs, Fs, Kind, Point, RealFs, When};
pub use generations::{
    CorruptReason, Current, MigrationNote, Plan, PublishError, Recovered, Refusal, Residue,
    Startup, StateDir, StateError,
};
pub use ledger::{Entry, Ledger, LedgerError, LedgerRead, Settlement};
pub use record::{GenerationName, Intent, IntentState, Operation, OperationRecord};
