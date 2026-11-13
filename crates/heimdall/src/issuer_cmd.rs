//! `heimdall issuer init|status|unlock|rotate begin|retire|restore|bundle` (m03-plan
//! U12, §5 item 24; ADR-0008 D3, D4; §17.22 item 12, §17.23 items 2–4).
//!
//! * **The ceremonies** (`init` with or without `--replace-orphan`, `rotate begin`,
//!   `restore`, `unlock`) run `heimdall_issuer::ceremony` on the **controlling
//!   terminal** ([`session`]): `--non-interactive` and a process without a terminal are
//!   refused (exit 3) before any store or runtime contact. The owner session is the
//!   IPC [`crate::client::Client`] on this module's own current-thread executor, one
//!   `block_on` per request. The passphrase is written only through the terminal:
//!   never stdout, stderr, an argument, an environment variable or a log.
//! * **R2B** (ADR-0008 §17.22 item 12; `.m03-wave5-api.md` R3). Registration sends the
//!   registration without a locator, shows the decision, takes the typed `yes`,
//!   writes the backup, shows the passphrase, puts K_ca in the store, re-sends the
//!   identical registration with `store_locator`, then `Decide approve` (the ceremony's
//!   order). Retirement ([`retire`]): `issuer.retire` → the `RetireIssuer` decision →
//!   the typed `yes` → `Decide approve` → `issuer.status` until the CA is `unloaded`
//!   with its recorded locator L → this process deletes exactly L
//!   (`retire::delete_awaiting`) → the attended `issuer.retire {ca_fingerprint,
//!   deleted_locator: L}`. A restore's displaced items (`orphan_store_items`) are
//!   resolved the same way. Neither the runtime nor the issuer child writes or deletes
//!   the store: only this owner-present process does.
//! * **`status`** is the runtime's `issuer.status`, plus the store items no registration
//!   names, which only this process can list (the runtime holds no store handle).
//! * **`unlock`** never triggers a store prompt (U4-Q2 (b)): a locked store is reported
//!   with how to unlock it, and nothing is sent.
//! * **`bundle`** asks the runtime for the bundle (read-only; never starts a runtime)
//!   and writes the file itself, owner-only and never over an existing name.
//!
//! **Fail closed (S3, `.m03-wave5-questions.md` Q-IS1).** A test-configuration store
//! (the scratch store of a test-configured debug build) cannot be registered on the
//! wire (`TestStoreNotRegistrable`), and its items are not deleted through the product
//! deletion path ([`S3_TEST_STORE_DELETION`] is `false`) until the orchestrator rules.

mod render;
mod session;

use std::path::Path;
use std::sync::Arc;

use heimdall_contract::envelope::{Envelope, reason};
use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::{
    CaState, CaStatus, IssuerRequest, IssuerStatus, OrphanStoreItem, RECOVERY_BUNDLE_SCHEMA,
    RecoveryBundle, StoreKind,
};
use heimdall_contract::request::Request;
use heimdall_contract::{Code, ExitCode};
use heimdall_issuer::retire::{self, RetireError};
use heimdall_issuer::store::{SecretStore, StoreError, StoreItemRef};

use crate::cli::{IssuerCommand, Prompter, Session, TerminalPrompt};
use crate::client::Ctx;
use crate::output;
use crate::setup_cmd::{self, Outcome, failure};

/// ⟨S3, Q-IS1⟩ Whether a **test-configuration** store's item (the scratch store of a
/// test-configured debug build) may be deleted by exact locator after an `unloaded`
/// retirement. `false` (the fail-closed reading, `retire::delete_awaiting`'s): such an
/// item is never deleted and the retirement waits at `unloaded`. A product store is
/// never affected by this switch, and a release build never selects a test store.
pub(crate) const S3_TEST_STORE_DELETION: bool = false;

/// How long `retire` waits for the issuer to unload the CA after the approval.
const UNLOAD_WAIT: std::time::Duration = std::time::Duration::from_secs(60);
/// How often `retire` polls `issuer.status` meanwhile.
const UNLOAD_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// Handle `issuer` (module docs).
pub(crate) fn run(ctx: &Ctx, command: IssuerCommand) -> ExitCode {
    match command {
        IssuerCommand::Status => setup_cmd::block(ctx, status(ctx)),
        IssuerCommand::Bundle { out, redact } => {
            setup_cmd::block(ctx, bundle(ctx, &out, redact.is_some()))
        }
        IssuerCommand::Retire { fingerprint } => setup_cmd::block(ctx, retire(ctx, &fingerprint)),
        command @ (IssuerCommand::Init { .. }
        | IssuerCommand::Rotate(_)
        | IssuerCommand::Restore { .. }
        | IssuerCommand::Unlock) => session::ceremony(ctx, command).emit(ctx),
    }
}

// --- shared -----------------------------------------------------------------------------

/// The test configuration this CLI process honours: `Ok(true)` when the scratch store is
/// selected (`HEIMDALL_TEST_SECRET_STORE=scratch`, debug builds). A release build refuses
/// every `HEIMDALL_TEST_*` variable; a test configuration needs an explicit home.
pub(crate) fn test_config(ctx: &Ctx) -> Result<bool, Outcome> {
    let env = |name: &str| std::env::var_os(name);
    let m03 = crate::testcfg::m03_config(&env).map_err(|m| setup_cmd::usage(&m))?;
    if let Some(msg) =
        crate::testcfg::home_refusal(crate::testcfg::requested_by(&env), ctx.home.is_some())
    {
        return Err(setup_cmd::usage(msg));
    }
    Ok(m03.scratch_secret_store)
}

/// This installation's K_ca store (`m03_cmd::issuer_store`, scoped to the environment the
/// state database names). Opened only after the runtime answered, so the database exists.
pub(crate) fn open_store(ctx: &Ctx, scratch: bool) -> Result<Box<dyn SecretStore>, Outcome> {
    let paths = ctx
        .paths()
        .map_err(|e| Outcome::of(output::error_value(*e)))?;
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    let environment =
        heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults))
            .and_then(|s| s.transaction(|tx| tx.self_environment()));
    let Ok(Some(environment)) = environment else {
        return Err(Outcome::of(failure(
            Code::ServiceUnavailable,
            "the installation's state cannot be read, so its CA key store cannot be selected",
            None,
        )));
    };
    crate::m03_cmd::issuer_store(ctx, &paths, &environment, scratch).ok_or_else(|| {
        Outcome::of(failure(
            Code::CapabilityUnavailable,
            "no CA key store is available on this platform (there is no plaintext fallback)",
            Some(reason::ISSUER_STORE_UNAVAILABLE),
        ))
    })
}

/// A shown path: under the account home as `~/…` (`localenv::paths::display_path`).
pub(crate) fn shown(path: &Path) -> String {
    match heimdall_localenv::sys::account_home() {
        Ok(home) => heimdall_localenv::paths::display_path(&home, path),
        Err(_) => heimdall_localenv::paths::display_path(Path::new(""), path),
    }
}

/// The `issuer.status` data of a successful envelope.
pub(crate) fn status_of(env: &Envelope<serde_json::Value>) -> Option<IssuerStatus> {
    if env.code.is_success() {
        serde_json::from_value(env.data.clone()).ok()
    } else {
        None
    }
}

fn unreadable_status() -> Outcome {
    Outcome::of(failure(
        Code::InternalError,
        "the runtime's issuer status could not be read",
        None,
    ))
}

/// Why a deletion by exact locator was refused, as the command's answer (nothing was
/// deleted, nothing confirmed).
fn deletion_refused(e: &RetireError) -> Envelope<serde_json::Value> {
    match e {
        RetireError::LocatorMismatch | RetireError::LocatorNotRecorded => failure(
            Code::ConfigConflict,
            "the recorded store item is not this CA's item in this store: nothing was deleted, and the retirement waits at unloaded",
            None,
        ),
        RetireError::Store(StoreError::Unavailable(a)) => failure(
            Code::CapabilityUnavailable,
            heimdall_app::issuer::unlock_guidance(a.refusal_reason().unwrap_or_default())
                .unwrap_or("the CA key store is not available: nothing was deleted"),
            a.refusal_reason(),
        ),
        _ => failure(
            Code::CapabilityUnavailable,
            "the store item could not be deleted, or a re-read still finds it: nothing was confirmed, and the retirement waits at unloaded",
            Some(reason::ISSUER_STORE_UNAVAILABLE),
        ),
    }
}

/// Delete exactly `locator`, the item `issuer.status` names for `ca` in a store of kind
/// `kind`, then re-read the store (`retire::delete_awaiting`). A test-configuration
/// store is refused unless [`S3_TEST_STORE_DELETION`] (debug builds).
pub(crate) fn delete_exact(
    store: &dyn SecretStore,
    ca: &CaFingerprint,
    kind: StoreKind,
    locator: &str,
) -> Result<(), Envelope<serde_json::Value>> {
    if store.kind().product().is_some() {
        return retire::delete_awaiting(store, ca, kind, locator).map_err(|e| deletion_refused(&e));
    }
    if !(S3_TEST_STORE_DELETION && cfg!(debug_assertions)) {
        return Err(failure(
            Code::CapabilityUnavailable,
            "this is a test-configuration CA key store, whose items the product deletion path never deletes (S3, awaiting a ruling): nothing was deleted, and the retirement waits at unloaded",
            Some(reason::ISSUER_STORE_UNAVAILABLE),
        ));
    }
    // ⟨S3 switch⟩ The same exact-identity rule on the test store: a listing that shows
    // `locator` holding another CA refuses; only `locator` is deleted, then re-read.
    let listed = store
        .list()
        .map_err(|e| deletion_refused(&RetireError::Store(e)))?;
    if locator.is_empty()
        || listed
            .iter()
            .any(|i| i.locator == locator && i.fingerprint != *ca)
    {
        return Err(deletion_refused(&RetireError::LocatorMismatch));
    }
    let item = StoreItemRef {
        kind: store.kind(),
        fingerprint: ca.clone(),
        locator: locator.to_owned(),
    };
    retire::delete_recorded(store, ca, Some(&item)).map_err(|e| deletion_refused(&e))
}

/// The items a restore displaced for `ca` (`orphan_store_items` with a locator).
pub(crate) fn displaced_of<'a>(
    status: &'a IssuerStatus,
    ca: &'a CaFingerprint,
) -> impl Iterator<Item = &'a OrphanStoreItem> + 'a {
    status
        .orphan_store_items
        .iter()
        .filter(move |o| o.fingerprint.as_ref() == Some(ca) && o.locator.is_some())
}

/// A CA's row in `status`.
fn ca_in<'a>(status: &'a IssuerStatus, ca: &CaFingerprint) -> Option<&'a CaStatus> {
    status.cas.iter().find(|c| c.fingerprint == *ca)
}

// --- status -----------------------------------------------------------------------------

/// `issuer status [--json]`: read-only; never starts a runtime.
async fn status(ctx: &Ctx) -> Outcome {
    let scratch = match test_config(ctx) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let mut client = match setup_cmd::session(ctx, false).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let mut env = client.request(Request::Issuer(IssuerRequest::Status)).await;
    let Some(mut st) = status_of(&env) else {
        return if env.code.is_success() {
            unreadable_status()
        } else {
            Outcome::of(env)
        };
    };
    let mut notes = Vec::new();
    // The store items no registration names (D4 item 1's crash point between steps 6
    // and 7): only this process can list them. Listing never prompts.
    match open_store(ctx, scratch) {
        Ok(store) => match heimdall_issuer::ceremony::orphans(store.as_ref(), &st) {
            Ok(items) => {
                let mut test_kind = 0usize;
                for item in items {
                    let Some(kind) = item.kind.product() else {
                        test_kind += 1;
                        continue;
                    };
                    let entry = OrphanStoreItem {
                        fingerprint: Some(item.fingerprint),
                        store: kind,
                        locator: Some(item.locator),
                    };
                    if !st.orphan_store_items.contains(&entry) {
                        st.orphan_store_items.push(entry);
                    }
                }
                if test_kind > 0 {
                    notes.push(format!(
                        "{test_kind} item(s) in the test-configuration store are named by no registration (not listed in the data: a test store kind is not in the public schema)"
                    ));
                }
            }
            Err(_) => notes.push(
                "the CA key store could not be listed (it may be locked): store items no registration names are not shown"
                    .to_owned(),
            ),
        },
        Err(_) => notes.push(
            "the CA key store could not be opened: store items no registration names are not shown"
                .to_owned(),
        ),
    }
    if let Ok(data) = serde_json::to_value(&st) {
        env.data = data;
    }
    let human = render::status(&st, &notes);
    Outcome::of(env).with_human(human)
}

// --- bundle -----------------------------------------------------------------------------

/// `issuer bundle --out <path> [--redact hostnames]` (D4 item 5): the runtime builds the
/// bundle (read-only); this process writes the file, owner-only, never over an existing
/// name.
async fn bundle(ctx: &Ctx, out: &Path, redact_hostnames: bool) -> Outcome {
    if let Err(o) = test_config(ctx) {
        return o;
    }
    let exists_refusal = || {
        setup_cmd::usage(&format!(
            "{} already exists; Heimdall never overwrites a file (choose a new path)",
            shown(out)
        ))
    };
    if std::fs::symlink_metadata(out).is_ok() {
        return exists_refusal();
    }
    let mut client = match setup_cmd::session(ctx, false).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let env = client
        .request(Request::Issuer(IssuerRequest::Bundle { redact_hostnames }))
        .await;
    if !env.code.is_success() {
        return Outcome::of(env);
    }
    let bundle: RecoveryBundle = match serde_json::from_value(env.data.clone()) {
        Ok(b) => b,
        Err(_) => {
            return Outcome::of(failure(
                Code::InternalError,
                "the runtime's recovery bundle could not be read; nothing was written",
                None,
            ));
        }
    };
    if bundle.schema != RECOVERY_BUNDLE_SCHEMA {
        return Outcome::of(failure(
            Code::SchemaUnsupported,
            "the runtime answered a recovery bundle of another schema; nothing was written",
            None,
        ));
    }
    let Ok(mut bytes) = serde_json::to_vec_pretty(&bundle) else {
        return Outcome::of(failure(
            Code::InternalError,
            "the recovery bundle could not be encoded; nothing was written",
            None,
        ));
    };
    bytes.push(b'\n');
    if let Err(e) = write_owner_only(out, &bytes) {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            return exists_refusal();
        }
        return setup_cmd::usage(&format!(
            "the recovery bundle could not be written to {} ({:?})",
            shown(out),
            e.kind()
        ));
    }
    let human = render::bundle(&bundle, &shown(out));
    Outcome::of(env).with_human(human)
}

/// Write `bytes` to a new owner-only file at `path` (`O_EXCL`, mode 0600 or an owner-only
/// DACL), then `fsync`. A partial file is removed.
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut file = heimdall_localenv::sys::create_owner_only_exclusive(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if written.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    written
}

// --- retire -----------------------------------------------------------------------------

/// The preface of the `RetireIssuer` confirmation.
const RETIRE_PREFACE: &str = "Retire this CA (ADR-0008 D4 item 3): issuance under it stops, the issuer unloads its key, and this command then deletes its store item by exact identity. Lines of abandoned enrollments stay on their servers (pending_until_line_removed).";

/// `issuer retire <fingerprint>` (D4 item 3; R2B).
async fn retire(ctx: &Ctx, fingerprint: &str) -> Outcome {
    let Ok(ca) = CaFingerprint::parse(fingerprint) else {
        return setup_cmd::usage("invalid CA fingerprint (expected SHA256:<43 base64 characters>)");
    };
    if let Err(o) = test_config(ctx) {
        return o;
    }
    let mut client = match setup_cmd::session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    retire_to_retired(&mut client, &mut TerminalPrompt, ctx, &ca).await
}

/// R2B's retirement of `ca` on a connected session (`issuer retire`; reusable by
/// `uninstall`, U-R4): attend first (interactive TTY only), `issuer.retire`, the
/// `RetireIssuer` decision with the owner's typed `yes` through `p`, `Decide approve`,
/// `issuer.status` until `unloaded`, the exact deletion of the recorded locator by this
/// process, the attended `deleted_locator` confirmation, then the CA's displaced items.
/// Unattended (`--non-interactive`, a non-TTY stdin) the request leaves the decision
/// pending and answers exit 3 with `next.decision_ref`; nothing more is sent.
pub(crate) async fn retire_to_retired<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    ca: &CaFingerprint,
) -> Outcome {
    let scratch = match test_config(ctx) {
        Ok(s) => s,
        Err(o) => return o,
    };
    if let Err(refused) = setup_cmd::attend_first(s, ctx).await {
        return Outcome::of(refused);
    }
    let env = s
        .request(Request::Issuer(IssuerRequest::Retire {
            ca_fingerprint: ca.clone(),
            deleted_locator: None,
        }))
        .await;
    if let Some(decision) = setup_cmd::pending_decision(&env) {
        if !ctx.interactive() {
            // The pending decision stays pending; nothing more is sent (exit 3).
            return Outcome::of(env);
        }
        let decided =
            setup_cmd::confirm_and_decide(s, p, ctx, &decision, RETIRE_PREFACE, None, None).await;
        if decided.code != Code::Ok {
            return Outcome::of(decided);
        }
    } else if !env.code.is_success() {
        return Outcome::of(env);
    }
    let (env, st) = match wait_unloaded(s, ca).await {
        Ok(v) => v,
        Err(o) => return o,
    };
    finish_retirement(ctx, s, scratch, ca, env, st).await
}

/// Poll `issuer.status` until `ca` leaves `active`/`pending`/`retiring` (the issuer
/// child confirmed the unload), bounded by [`UNLOAD_WAIT`].
async fn wait_unloaded<S: Session>(
    s: &mut S,
    ca: &CaFingerprint,
) -> Result<(Envelope<serde_json::Value>, IssuerStatus), Outcome> {
    let deadline = tokio::time::Instant::now() + UNLOAD_WAIT;
    loop {
        let env = s.request(Request::Issuer(IssuerRequest::Status)).await;
        let Some(st) = status_of(&env) else {
            return Err(if env.code.is_success() {
                unreadable_status()
            } else {
                Outcome::of(env)
            });
        };
        let Some(row) = ca_in(&st, ca) else {
            return Err(Outcome::of(failure(
                Code::NotFound,
                "no registered CA has that fingerprint",
                None,
            )));
        };
        if matches!(
            row.state,
            CaState::Unloaded | CaState::Deleted | CaState::Retired
        ) {
            return Ok((env, st));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Outcome::of(failure(
                Code::ServiceUnavailable,
                "the issuer has not confirmed unloading the CA yet; the retirement resumes on its own: run `heimdall issuer retire <fingerprint>` again to delete its store item",
                Some(reason::ISSUER_UNAVAILABLE),
            )));
        }
        tokio::time::sleep(UNLOAD_POLL).await;
    }
}

/// R2B's last steps: delete exactly the recorded locator of an `unloaded` CA, confirm it
/// on an attended `issuer.retire`, then the CA's displaced items the same way.
async fn finish_retirement<S: Session>(
    ctx: &Ctx,
    s: &mut S,
    scratch: bool,
    ca: &CaFingerprint,
    mut env: Envelope<serde_json::Value>,
    mut st: IssuerStatus,
) -> Outcome {
    let Some(row) = ca_in(&st, ca).cloned() else {
        return unreadable_status();
    };
    let mut work: Vec<(StoreKind, String)> = Vec::new();
    if row.state != CaState::Retired {
        let Some(locator) = row.store_locator.clone() else {
            return Outcome::of(failure(
                Code::CapabilityUnavailable,
                "this CA's store item was never recorded, so Heimdall cannot delete it by exact identity: the retirement stays at unloaded and the item stays in the store (`heimdall issuer status` lists it)",
                Some(reason::ISSUER_STORE_LOCATOR_UNRECORDED),
            ))
            .with_human(render::status(&st, &[]));
        };
        work.push((row.store, locator));
    }
    for o in displaced_of(&st, ca) {
        if let Some(l) = &o.locator {
            work.push((o.store, l.clone()));
        }
    }
    if !work.is_empty() {
        if !ctx.interactive() {
            return Outcome::of(setup_cmd::not_confirmed(
                None,
                None,
                "deleting the CA's store item needs the owner at a terminal; nothing was deleted",
            ));
        }
        let store = match open_store(ctx, scratch) {
            Ok(store) => store,
            Err(o) => return o,
        };
        for (kind, locator) in work {
            if let Err(refused) = delete_exact(store.as_ref(), ca, kind, &locator) {
                return Outcome::of(refused).with_human(render::status(&st, &[]));
            }
            env = s
                .request(Request::Issuer(IssuerRequest::Retire {
                    ca_fingerprint: ca.clone(),
                    deleted_locator: Some(locator),
                }))
                .await;
            match status_of(&env) {
                Some(next) => st = next,
                None if env.code.is_success() => return unreadable_status(),
                None => {
                    return Outcome::of(env).with_human(
                        "The store item was deleted, but the runtime did not record it: run `heimdall issuer retire <fingerprint>` again (an absent item counts as deleted).".to_owned(),
                    );
                }
            }
        }
    }
    let human = render::retired(&st, ca);
    Outcome::of(env).with_human(human)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use heimdall_contract::Timestamp;
    use heimdall_contract::issuer::{EnrollmentCounts, IssuerState};
    use heimdall_contract::managed::IssuerIsolation;
    use heimdall_testkit::scratch_store::ScratchSecretStore;

    fn status_with(ca: &CaFingerprint, state: CaState, locator: Option<&str>) -> IssuerStatus {
        IssuerStatus {
            state: IssuerState::Ready,
            reason: None,
            cas: vec![CaStatus {
                fingerprint: ca.clone(),
                state,
                store: StoreKind::LinuxSecretService,
                backup_sha256: "ab".repeat(32),
                backup_created_at: Timestamp::now(),
                restored_without_log: false,
                enrollments: EnrollmentCounts::default(),
                store_locator: locator.map(str::to_owned),
            }],
            orphan_store_items: Vec::new(),
            issuer_isolation: IssuerIsolation::SameUserProcess,
            bundle_stale: false,
        }
    }

    /// The displaced items of one CA are exactly its `orphan_store_items` with a locator.
    #[test]
    fn displaced_items_are_those_of_the_ca_with_a_locator() {
        let a = CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap();
        let b = CaFingerprint::parse(&format!("SHA256:{}", "B".repeat(43))).unwrap();
        let mut st = status_with(&a, CaState::Active, Some("new"));
        for (fp, l) in [
            (Some(&a), Some("old")),
            (Some(&b), Some("x")),
            (Some(&a), None),
        ] {
            st.orphan_store_items.push(OrphanStoreItem {
                fingerprint: fp.cloned(),
                store: StoreKind::LinuxSecretService,
                locator: l.map(str::to_owned),
            });
        }
        let got: Vec<_> = displaced_of(&st, &a)
            .map(|o| o.locator.clone().unwrap())
            .collect();
        assert_eq!(got, vec!["old".to_owned()]);
    }

    /// ⟨S3⟩ With the switch off, a test-configuration store's item is never deleted by
    /// the R2B path: the refusal names the store, and the item stays.
    #[test]
    fn test_store_items_are_not_deleted_while_s3_is_unruled() {
        let dir = tempfile::tempdir().unwrap();
        let store = ScratchSecretStore::new(dir.path().join("s"));
        let fp = CaFingerprint::parse(&format!("SHA256:{}", "C".repeat(43))).unwrap();
        std::fs::create_dir_all(dir.path().join("s")).unwrap();
        let before = store.list().unwrap();
        let env = delete_exact(&store, &fp, StoreKind::LinuxSecretService, "loc").unwrap_err();
        const { assert!(!S3_TEST_STORE_DELETION) };
        assert_eq!(env.code, Code::CapabilityUnavailable);
        assert_eq!(
            env.data["error"]["reason"],
            reason::ISSUER_STORE_UNAVAILABLE
        );
        assert_eq!(store.list().unwrap(), before);
    }
}
