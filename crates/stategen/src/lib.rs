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
//!   A damaged ledger (anything but a torn tail) refuses every append and writes nothing
//!   (ruled 2026-11-23); recovery is the attended `state repair` (⟨M08 U2b-3b⟩
//!   [`Ledger::scan`] and [`Ledger::cut`]). ⟨M08 U2b-3a⟩ A caller that keeps
//!   the entries in memory reads it whole once ([`Ledger::load`]) and appends at the length it
//!   last saw, reading nothing ([`Ledger::append_at`]); [`Ledger::trim_entries`] reports what a
//!   trim dropped.
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
//!    state. ⟨M08 U2b-3b; ADR-0006 §19.4, the ruling on U0-Q8⟩ Recovery from
//!    `state_corrupt` is the attended [`StateDir::recover`]: a restore from a backup the
//!    owner names, or a reset, by the same switch, with the identity binding and the epoch
//!    the caller chose and the owner confirmed (the store's `restore` module). Nothing picks
//!    a generation.
//! 5. *Windows:* [`RealFs`]'s rename is `std::fs::rename` followed by a flush of the
//!    renamed file. ⟨M08 U2b-1, delta H15⟩ The product does not use it for a write: the
//!    store's layout (`heimdall_store::layout`) makes every call through the runtime's
//!    `heimdall_runtime::state_store::PlatformFs`. Its [`Fs::rename_over`] is the ADR's
//!    write-through rename (`MoveFileExW` with `MOVEFILE_REPLACE_EXISTING |
//!    MOVEFILE_WRITE_THROUGH`, in the runtime's platform module beside the workspace's
//!    other `unsafe` Windows calls). No `unsafe` module is added here.
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
pub use ledger::{Entry, Ledger, LedgerError, LedgerRead, LedgerScan, Settlement, Trimmed};
pub use record::{GenerationName, Intent, IntentState, Operation, OperationRecord};
