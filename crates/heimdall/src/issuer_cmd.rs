//! `heimdall issuer init|status|unlock|rotate begin|retire|restore|bundle` (m03-plan
//! U12, §5 item 24; ADR-0008 D3, D4; §17.22 item 12, §17.23 items 2–4).
//!
//! * **The ceremonies** (`init` with or without `--replace-orphan`, `rotate begin`,
//!   `restore`, `unlock`) run `heimdall_issuer::ceremony` on the **controlling
//!   terminal** ([`session`]): `--non-interactive`, a stdin that is not a terminal
//!   (ADR-0008 §17.27 item 5) and a process without a terminal are refused (exit 3) before
//!   any store or runtime contact. Every prompt is bounded by the CLI's prompt timeout, and
//!   Ctrl-C and end of input cancel at once (§17.27 items 6, 7); every ceremony text is
//!   sanitized (item 8). The owner session is the
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
//! **Test stores (ADR-0008 §17.25 item 7).** A test-configured debug build selects its CA
//! key store through `HEIMDALL_TEST_SECRET_STORE` ([`crate::testcfg::test_store`]): the
//! scratch store (a test kind: never registrable on the wire, but its items are deleted by
//! exact locator, `retire::delete_awaiting`, item 7 (d)), or `product-file:<abs path>`, a
//! disposable store of a **product** kind the test created in its scratch home (item 7
//! (b)), on which the whole registration, passphrase and R2B chain runs. A release build
//! refuses every `HEIMDALL_TEST_*` variable.
//!
//! **The shared retire entry (§17.25 item 9).** [`retire_to_retired`] is the one entry
//! `issuer retire` and `uninstall` (inline, on the session it already holds, before the
//! runtime stops) both run.

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
use heimdall_issuer::store::{SecretStore, StoreError};

use crate::cli::{IssuerCommand, Prompter, Session, TerminalPrompt};
use crate::client::Ctx;
use crate::output;
use crate::setup_cmd::{self, Outcome, failure};
use crate::testcfg::TestStore;

/// How long `retire` waits for the issuer to unload the CA after the approval.
const UNLOAD_WAIT: std::time::Duration = std::time::Duration::from_secs(60);
/// How often `retire` polls `issuer.status` meanwhile.
const UNLOAD_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// Handle `issuer` (module docs).
pub(crate) fn run(ctx: &Ctx, command: IssuerCommand) -> ExitCode {
    match command {
        IssuerCommand::Status => setup_cmd::block(ctx, async { with_next(status(ctx).await) }),
        IssuerCommand::Bundle { out, redact } => setup_cmd::block(ctx, async {
            with_next(bundle(ctx, &out, redact.is_some()).await)
        }),
        IssuerCommand::Retire { fingerprint } => {
            setup_cmd::block(ctx, async { with_next(retire(ctx, &fingerprint).await) })
        }
        command @ (IssuerCommand::Init { .. }
        | IssuerCommand::Rotate(_)
        | IssuerCommand::Restore { .. }
        | IssuerCommand::Unlock) => with_next(session::ceremony(ctx, command)).emit(ctx),
    }
}

/// ⟨ADR-0008 §17.28 item 6⟩ An `issuer_store_access_denied` refusal (from this process's
/// store read or the runtime's) names its next command in `data.next_command`: the
/// log-intact restore, `heimdall issuer restore --backup <file>`. Every other outcome is
/// unchanged.
fn with_next(mut outcome: Outcome) -> Outcome {
    let denied = outcome
        .env
        .data
        .pointer("/error/reason")
        .and_then(serde_json::Value::as_str)
        == Some(reason::ISSUER_STORE_ACCESS_DENIED);
    if denied && let serde_json::Value::Object(map) = &mut outcome.env.data {
        map.insert(
            "next_command".to_owned(),
            serde_json::Value::String(heimdall_app::issuer::STORE_ACCESS_DENIED_NEXT.to_owned()),
        );
    }
    outcome
}

// --- shared -----------------------------------------------------------------------------

/// The test configuration this CLI process honours: the CA key store it selects
/// ([`crate::testcfg::test_store`]; the platform's product store without one). A release
/// build refuses every `HEIMDALL_TEST_*` variable; a test configuration needs an explicit
/// home, and a product-file store a path that `test_product::refusal` accepts.
pub(crate) fn test_config(ctx: &Ctx) -> Result<TestStore, Outcome> {
    let env = |name: &str| std::env::var_os(name);
    let m03 = crate::testcfg::m03_config(&env).map_err(|m| setup_cmd::usage(&m))?;
    if let Some(msg) =
        crate::testcfg::home_refusal(crate::testcfg::requested_by(&env), ctx.home.is_some())
    {
        return Err(setup_cmd::usage(msg));
    }
    crate::testcfg::test_store(&m03, ctx.home.as_deref()).map_err(|m| setup_cmd::usage(&m))
}

/// This installation's K_ca store (`m03_cmd::issuer_store`, scoped to the environment the
/// state database names). Opened only after the runtime answered, so the database exists.
pub(crate) fn open_store(ctx: &Ctx, test: &TestStore) -> Result<Box<dyn SecretStore>, Outcome> {
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
    crate::m03_cmd::issuer_store(ctx, &paths, &environment, test).ok_or_else(|| {
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
/// `kind`, then re-read the store (`retire::delete_awaiting`; a test-configuration store's
/// item too, in a debug build, ADR-0008 §17.25 item 7 (d)).
pub(crate) fn delete_exact(
    store: &dyn SecretStore,
    ca: &CaFingerprint,
    kind: StoreKind,
    locator: &str,
) -> Result<(), Envelope<serde_json::Value>> {
    retire::delete_awaiting(store, ca, kind, locator).map_err(|e| deletion_refused(&e))
}

/// ⟨ADR-0008 §17.28 item 7⟩ [`delete_exact`] for an item a restore displaced, except one
/// this executable cannot read (`issuer_store_access_denied`): that one is never deleted
/// (the store reads an item before deleting it, so nothing was touched) and `Ok(false)`
/// says it was kept, for the owner to delete in Keychain Access.
pub(crate) fn delete_displaced(
    store: &dyn SecretStore,
    ca: &CaFingerprint,
    kind: StoreKind,
    locator: &str,
) -> Result<bool, Envelope<serde_json::Value>> {
    match retire::delete_awaiting(store, ca, kind, locator) {
        Ok(()) => Ok(true),
        Err(RetireError::Store(StoreError::Unavailable(
            heimdall_issuer::store::StoreAvailability::AccessDenied,
        ))) => Ok(false),
        Err(e) => Err(deletion_refused(&e)),
    }
}

/// ⟨ADR-0008 §17.28 item 7⟩ What the owner does with a kept unreadable item: its exact
/// service and account, deleted in Keychain Access (Heimdall never deletes it).
pub(crate) fn keep_instruction(locator: &str) -> String {
    match render::keychain_parts(locator) {
        Some((service, account)) => format!(
            "this Heimdall executable cannot read it, so Heimdall never deletes it: delete it yourself in Keychain Access (service {service}, account {account})"
        ),
        None => format!(
            "this Heimdall executable cannot read it, so Heimdall never deletes it: delete it yourself in the platform store ({locator})"
        ),
    }
}

/// ⟨ADR-0008 §17.31 item 5⟩ What the owner does with a displaced item Heimdall did not
/// delete once its CA is retired (no later command deletes it): delete it in the store.
pub(crate) fn manual_delete_instruction(locator: &str) -> String {
    match render::keychain_parts(locator) {
        Some((service, account)) => {
            format!("delete it yourself in Keychain Access (service {service}, account {account})")
        }
        None => format!("delete it yourself in the platform store ({locator})"),
    }
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
    let test = match test_config(ctx) {
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
    match open_store(ctx, &test) {
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
    // ⟨ADR-0008 §17.25 item 8⟩ The file is completely written and fsynced: confirm it, so
    // the runtime records `last_bundle_at` and this digest (never the path). A redacted
    // bundle cannot serve foreign removal or uninstall, so it is never confirmed.
    if !bundle.redacted {
        let confirmed = client
            .request(Request::Issuer(IssuerRequest::BundleWritten {
                created_at: bundle.created_at,
                sha256: heimdall_issuer::backup::sha256_hex(&bytes),
            }))
            .await;
        if !confirmed.code.is_success() {
            return Outcome::of(confirmed).with_human(format!(
                "{human}The bundle was written to {}, but the runtime did not record it, so `heimdall uninstall --bundle` will not accept this file: run `heimdall issuer bundle --out <new path>` again.\n",
                shown(out)
            ));
        }
    }
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
        return written;
    }
    // The new name too (Unix: fsync the directory); best effort, the bytes are synced.
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
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

/// ⟨ADR-0008 §17.25 item 9⟩ **The one retire entry**: `issuer retire` and `uninstall`
/// (inline, behind uninstall's own typed confirmation, on the session it already holds and
/// before the runtime stops) both run it. R2B's retirement of `ca` on a connected session:
/// attend first (interactive TTY only), `issuer.retire`, the
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
    let test = match test_config(ctx) {
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
    finish_retirement(ctx, s, &test, ca, env, st).await
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
///
/// ⟨ADR-0008 §17.28 item 7, §17.31 item 5 (W5-C05)⟩ The current item and the displaced
/// ones are distinct work. A refused deletion of the **current** item answers the refusal
/// (nothing was confirmed). Once it is deleted and confirmed (the CA `retired`), a displaced
/// item is never a failure: one this executable cannot read (`issuer_store_access_denied`,
/// after a new-item restore) is never deleted and stays in `orphan_store_items` with its
/// Keychain Access instruction ([`delete_displaced`]); any other refused deletion leaves it
/// listed too. Each is a note with its next step, and the command reports the completed
/// retirement (exit 0), never effect `none` and never a restore.
async fn finish_retirement<S: Session>(
    ctx: &Ctx,
    s: &mut S,
    test: &TestStore,
    ca: &CaFingerprint,
    mut env: Envelope<serde_json::Value>,
    mut st: IssuerStatus,
) -> Outcome {
    let Some(row) = ca_in(&st, ca).cloned() else {
        return unreadable_status();
    };
    // (store kind, locator, whether it is the CA's current item)
    let mut work: Vec<(StoreKind, String, bool)> = Vec::new();
    if row.state != CaState::Retired {
        let Some(locator) = row.store_locator.clone() else {
            return Outcome::of(failure(
                Code::CapabilityUnavailable,
                "this CA's store item was never recorded, so Heimdall cannot delete it by exact identity: the retirement stays at unloaded and the item stays in the store (`heimdall issuer status` lists it)",
                Some(reason::ISSUER_STORE_LOCATOR_UNRECORDED),
            ))
            .with_human(render::status(&st, &[]));
        };
        work.push((row.store, locator, true));
    }
    for o in displaced_of(&st, ca) {
        if let Some(l) = &o.locator {
            work.push((o.store, l.clone(), false));
        }
    }
    let mut notes: Vec<String> = Vec::new();
    if !work.is_empty() {
        if !ctx.interactive() {
            return Outcome::of(setup_cmd::not_confirmed(
                None,
                None,
                "deleting the CA's store item needs the owner at a terminal; nothing was deleted",
            ));
        }
        let store = match open_store(ctx, test) {
            Ok(store) => store,
            Err(o) => return o,
        };
        for (kind, locator, current) in work {
            if current {
                if let Err(refused) = delete_exact(store.as_ref(), ca, kind, &locator) {
                    return Outcome::of(refused).with_human(render::status(&st, &[]));
                }
            } else {
                match delete_displaced(store.as_ref(), ca, kind, &locator) {
                    Ok(true) => {}
                    // Never deleted: listed, for the owner to delete in Keychain Access.
                    Ok(false) => {
                        notes.push(format!(
                            "the old store item ({locator}) stays listed under orphan store items: {}",
                            keep_instruction(&locator)
                        ));
                        continue;
                    }
                    Err(_) => {
                        notes.push(format!(
                            "the old store item ({locator}) could not be deleted and stays listed under orphan store items: {}",
                            manual_delete_instruction(&locator)
                        ));
                        continue;
                    }
                }
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
    let human = render::retired(&st, ca, &notes);
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

    /// ⟨ADR-0008 §17.25 item 7 (d)⟩ In a debug build a test-configuration store's item is
    /// deleted by its exact locator through the CLI's deletion, and only that item; a
    /// locator naming another CA is refused with nothing deleted.
    #[test]
    fn test_store_items_are_deleted_by_exact_locator_in_debug_builds() {
        let dir = tempfile::tempdir().unwrap();
        let store = ScratchSecretStore::new(dir.path().join("s"));
        std::fs::create_dir_all(dir.path().join("s")).unwrap();
        let (k1, k2) = (
            heimdall_credential::cert::SecretCaKey::generate().unwrap(),
            heimdall_credential::cert::SecretCaKey::generate().unwrap(),
        );
        let (f1, f2) = (k1.fingerprint().unwrap(), k2.fingerprint().unwrap());
        let i1 = store.put(&f1, &k1).unwrap();
        let i2 = store.put(&f2, &k2).unwrap();
        let env =
            delete_exact(&store, &f1, StoreKind::LinuxSecretService, &i2.locator).unwrap_err();
        assert_eq!(env.code, Code::ConfigConflict);
        assert_eq!(store.list().unwrap().len(), 2, "nothing was deleted");
        delete_exact(&store, &f1, StoreKind::LinuxSecretService, &i1.locator).unwrap();
        assert_eq!(store.list().unwrap(), vec![i2]);
    }
}
