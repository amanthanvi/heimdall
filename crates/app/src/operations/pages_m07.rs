//! ⟨rev7⟩ m07-plan U3 (ADR-0013 §6.1, §6.2; D2, D21): `inspect`'s `select` and `page` forms
//! and their page tokens.
//!
//! **What a form reads.** Both forms run the subject's whole-read arm
//! ([`Operations::inspect_rows`]) with the same caller, so subject authorization and
//! visibility are the whole read's: a role selects and pages only what it could read whole.
//! The catalog subjects with a keyset store read (destinations, profiles, identities) read
//! only their page's `limit + 1` rows, or the selected rows by point lookup ([`Rows`]); the
//! others still compute their whole visible list and are cut here. Either way the items are
//! ordered by their immutable unique ID (byte order), strictly after the token's position,
//! so a stable item is never repeated or skipped.
//!
//! **Answers.** `select` answers `{items, missing}`; `page` answers `{items, more,
//! next_page_token?}`, `next_page_token` present exactly when `more`, within
//! [`PAGE_BUDGET_BYTES`]; a `preview` asked for rides along as in the whole read. Content is
//! complete: an item alone over the budget is `USAGE_ERROR` / `response_too_large` naming it.
//!
//! **Tokens** (§6.2). `base64url(version ‖ scope tag ‖ position ‖ HMAC-SHA256)`, at most
//! [`MAX_PAGE_TOKEN_LEN`] characters. The scope is the reader (principal, role,
//! `remote_client`), the environment, the canonical query (subject, `cwd`, `preview`,
//! `redact`, sort) and the store's restore epoch, digested; the position is the last item's
//! ID, which is also its sort key (the one sort is by ID). The MAC covers the version, the
//! whole scope digest and the position, under the store's 32-byte key
//! ([`heimdall_store::Txn::page_token_key`]); it is checked with `verify_slice` (constant
//! time). A token carries a position, never authority: each page re-reads as the current
//! caller.

use std::collections::BTreeSet;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::{DestinationId, EnvironmentId, IdentityId, MAX_ID_LEN, ProfileId};
use heimdall_contract::page::{
    MAX_PAGE_TOKEN_LEN, PAGE_BUDGET_BYTES, PAGE_LIMIT_DEFAULT, PAGE_LIMIT_MAX, PageRequest,
    PageToken, Select,
};
use heimdall_contract::request::{InspectRequest, InspectSubject};
use heimdall_domain::catalog::{DestinationRecord, IdentityRecord};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::profile::ProfileDefinition;
use heimdall_store::{PageTokenKey, Txn};
use hmac::{Hmac, Mac as _};

use super::{Caller, Code, Completed, OpError, OpResult, Operations, internal};

/// The one sort every list subject pages in: by the item's immutable unique ID.
pub(super) const SORT_BY_ID: &str = "id";
/// The token layout's version.
const TOKEN_VERSION: u8 = 1;
/// The scope digest's prefix carried in the token (the MAC covers the whole digest).
const SCOPE_TAG_LEN: usize = 16;
/// HMAC-SHA256's output.
const MAC_LEN: usize = 32;
/// The MAC's domain separation.
const MAC_CONTEXT: &[u8] = b"heimdall-page-token/1\0";

type HmacSha256 = Hmac<sha2::Sha256>;

/// Which rows an `inspect` arm with a keyset store read reads. Every other arm reads its
/// whole list whatever this says, and the form cuts it.
#[derive(Debug, Clone, Default)]
pub(super) enum Rows {
    /// The whole list (a whole read).
    #[default]
    All,
    /// At most `take` rows whose ID sorts after `after`, by ID.
    After {
        /// The previous page's last ID.
        after: Option<String>,
        /// The page's `limit + 1`.
        take: usize,
    },
    /// The selected rows, by point lookup.
    Pick {
        /// Selected IDs.
        ids: Vec<String>,
        /// Selected aliases (destinations only).
        aliases: Vec<String>,
    },
}

impl Rows {
    /// The catalog destinations this read covers.
    pub(super) fn destinations(
        &self,
        tx: &mut Txn<'_>,
    ) -> heimdall_store::Result<Vec<DestinationRecord>> {
        match self {
            Rows::All => tx.destinations(),
            Rows::After { after, take } => tx.destinations_after(after.as_deref(), *take),
            Rows::Pick { ids, aliases } => {
                let mut out: Vec<DestinationRecord> = Vec::new();
                for id in ids {
                    if let Ok(id) = DestinationId::parse(id)
                        && let Some(d) = tx.destination(&id)?
                    {
                        out.push(d);
                    }
                }
                for alias in aliases {
                    if let Some(d) = tx.destination_by_alias(alias)? {
                        out.push(d);
                    }
                }
                let mut seen = BTreeSet::new();
                out.retain(|d| seen.insert(d.id.clone()));
                Ok(out)
            }
        }
    }

    /// The current profile definitions this read covers.
    pub(super) fn profiles(
        &self,
        tx: &mut Txn<'_>,
    ) -> heimdall_store::Result<Vec<ProfileDefinition>> {
        match self {
            Rows::All => tx.profiles(),
            Rows::After { after, take } => tx.profiles_after(after.as_deref(), *take),
            Rows::Pick { ids, .. } => {
                let mut out: Vec<ProfileDefinition> = Vec::new();
                for id in ids {
                    if let Ok(id) = ProfileId::parse(id)
                        && let Some(p) = tx.profile(&id)?
                        && !out.iter().any(|o| o.id == p.id)
                    {
                        out.push(p);
                    }
                }
                Ok(out)
            }
        }
    }

    /// The catalog identities this read covers.
    pub(super) fn identities(
        &self,
        tx: &mut Txn<'_>,
    ) -> heimdall_store::Result<Vec<IdentityRecord>> {
        match self {
            Rows::All => tx.identities(),
            Rows::After { after, take } => tx.identities_after(after.as_deref(), *take),
            Rows::Pick { ids, .. } => {
                let mut out: Vec<IdentityRecord> = Vec::new();
                for id in ids {
                    if let Ok(id) = IdentityId::parse(id)
                        && let Some(i) = tx.identity(&id)?
                        && !out.iter().any(|o| o.id == i.id)
                    {
                        out.push(i);
                    }
                }
                Ok(out)
            }
        }
    }
}

/// ⟨rev7; S2, ruled 2026-11-25⟩ A keyset read that keeps only some rows: `read(tx, after,
/// take)` gives at most `take` rows after `after` by ID, and `map` turns each into its item or
/// drops it. Chunks of `take` are read until `take` items are kept or the rows end, so a page
/// never comes back short while rows remain, and when `map` keeps every row (the owner's
/// reads) exactly `take` rows are read.
pub(super) fn keyset_map<T, U>(
    tx: &mut Txn<'_>,
    after: Option<&str>,
    take: usize,
    mut read: impl FnMut(&mut Txn<'_>, Option<&str>, usize) -> heimdall_store::Result<Vec<T>>,
    id: impl Fn(&T) -> String,
    mut map: impl FnMut(&mut Txn<'_>, T) -> heimdall_store::Result<Option<U>>,
) -> heimdall_store::Result<Vec<U>> {
    let mut out = Vec::new();
    let mut position = after.map(str::to_owned);
    while out.len() < take {
        let chunk = read(tx, position.as_deref(), take)?;
        let full = chunk.len() == take;
        for row in chunk {
            position = Some(id(&row));
            if let Some(item) = map(tx, row)? {
                out.push(item);
                if out.len() == take {
                    break;
                }
            }
        }
        if !full {
            break;
        }
    }
    Ok(out)
}

impl Rows {
    /// ⟨S2⟩ The operations `inspect operations` lists (not settled) that `keep` keeps.
    pub(super) fn operations(
        &self,
        tx: &mut Txn<'_>,
        keep: impl Fn(&heimdall_domain::operation::OperationRecord) -> bool,
    ) -> heimdall_store::Result<Vec<heimdall_domain::operation::OperationRecord>> {
        match self {
            Rows::All => {
                let mut ops = tx.open_operations()?;
                ops.extend(tx.unresolved_operations()?);
                ops.retain(|o| keep(o));
                Ok(ops)
            }
            Rows::After { after, take } => keyset_map(
                tx,
                after.as_deref(),
                *take,
                |tx, after, take| tx.listed_operations_after(after, take),
                |o| o.id.to_string(),
                |_, o| Ok(keep(&o).then_some(o)),
            ),
            Rows::Pick { ids, .. } => {
                let mut out = Vec::new();
                for id in ids {
                    if let Ok(id) = heimdall_contract::ids::OperationId::parse(id)
                        && let Some(o) = tx.operation(&id)?
                        && !o.state.is_settled()
                        && keep(&o)
                        && !out
                            .iter()
                            .any(|x: &heimdall_domain::operation::OperationRecord| x.id == o.id)
                    {
                        out.push(o);
                    }
                }
                Ok(out)
            }
        }
    }

    /// ⟨S2⟩ The pending decision records.
    pub(super) fn decisions(
        &self,
        tx: &mut Txn<'_>,
    ) -> heimdall_store::Result<Vec<heimdall_domain::decision::DecisionRecord>> {
        match self {
            Rows::All => tx.pending_decisions(),
            Rows::After { after, take } => tx.pending_decisions_after(after.as_deref(), *take),
            Rows::Pick { ids, .. } => {
                let mut out: Vec<heimdall_domain::decision::DecisionRecord> = Vec::new();
                for id in ids {
                    if let Ok(id) = heimdall_contract::ids::DecisionId::parse(id)
                        && let Some(d) = tx.decision(&id)?
                        && d.state == heimdall_domain::decision::DecisionState::Pending
                        && !out.iter().any(|x| x.id == d.id)
                    {
                        out.push(d);
                    }
                }
                Ok(out)
            }
        }
    }

    /// ⟨S2⟩ The live owned connections (`up`, `closing`), each mapped to its item by `map`
    /// (which drops a row it cannot list).
    pub(super) fn connections<U>(
        &self,
        tx: &mut Txn<'_>,
        mut map: impl FnMut(
            &mut Txn<'_>,
            heimdall_domain::managed::OwnedConnection,
        ) -> heimdall_store::Result<Option<U>>,
    ) -> heimdall_store::Result<Vec<U>> {
        use heimdall_domain::managed::OwnedConnectionState as S;
        let live =
            |c: &heimdall_domain::managed::OwnedConnection| matches!(c.state, S::Up | S::Closing);
        match self {
            Rows::All => {
                let mut out = Vec::new();
                for c in tx.owned_connections()? {
                    if live(&c)
                        && let Some(item) = map(tx, c)?
                    {
                        out.push(item);
                    }
                }
                Ok(out)
            }
            Rows::After { after, take } => keyset_map(
                tx,
                after.as_deref(),
                *take,
                |tx, after, take| tx.live_owned_connections_after(after, take),
                |c| c.id.to_string(),
                map,
            ),
            Rows::Pick { ids, .. } => {
                let mut out = Vec::new();
                let mut seen = BTreeSet::new();
                for id in ids {
                    if let Ok(id) = heimdall_contract::ids::ConnectionId::parse(id)
                        && seen.insert(id.clone())
                        && let Some(c) = tx.owned_connection(&id)?
                        && live(&c)
                        && let Some(item) = map(tx, c)?
                    {
                        out.push(item);
                    }
                }
                Ok(out)
            }
        }
    }

    /// ⟨S2⟩ `environment`'s projection resources.
    pub(super) fn projections(
        &self,
        tx: &mut Txn<'_>,
        environment: &EnvironmentId,
    ) -> heimdall_store::Result<Vec<heimdall_domain::resource::ManagedResource>> {
        match self {
            Rows::All => tx.projection_resources(environment),
            Rows::After { after, take } => {
                tx.projection_resources_after(environment, after.as_deref(), *take)
            }
            Rows::Pick { ids, .. } => {
                use heimdall_domain::resource::{OwnerRef, ResourceKind};
                let mut out: Vec<heimdall_domain::resource::ManagedResource> = Vec::new();
                for id in ids {
                    if let Ok(id) = heimdall_contract::ids::ResourceId::parse(id)
                        && let Some(r) = tx.resource(&id)?
                        && r.kind == ResourceKind::ConfigProjection
                        && matches!(&r.owner, OwnerRef::Projection { environment: e } if e == environment)
                        && !out.iter().any(|x| x.id == r.id)
                    {
                        out.push(r);
                    }
                }
                Ok(out)
            }
        }
    }

    /// ⟨S2⟩ The enrollment records `inspect enrollments` lists, or `None` for the whole read
    /// (its own reader, `enrollment_m03::enrollments_view_in`, lists them).
    pub(super) fn enrollments(
        &self,
        tx: &mut Txn<'_>,
    ) -> heimdall_store::Result<Option<Vec<heimdall_domain::enrollment::EnrollmentRecord>>> {
        match self {
            Rows::All => Ok(None),
            Rows::After { after, take } => tx.enrollments_after(after.as_deref(), *take).map(Some),
            Rows::Pick { ids, .. } => {
                let mut out: Vec<heimdall_domain::enrollment::EnrollmentRecord> = Vec::new();
                for id in ids {
                    if let Ok(id) = heimdall_contract::ids::EnrollmentId::parse(id)
                        && let Some(r) = tx.enrollment(&id)?
                        && !out.iter().any(|x| x.id == r.id)
                    {
                        out.push(r);
                    }
                }
                Ok(Some(out))
            }
        }
    }
}

/// Where a list subject's items are in its whole-read answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Listing {
    /// The key of the item array.
    key: &'static str,
    /// Each item's ID field.
    id: &'static str,
    /// Each item's alias field, for the subjects that have aliases.
    alias: Option<&'static str>,
}

/// Whether `subject` is a list (otherwise `select` and `page` are refused).
fn is_list(subject: &InspectSubject) -> bool {
    !matches!(
        subject,
        InspectSubject::Capabilities
            | InspectSubject::Issuer
            | InspectSubject::Workspace
            | InspectSubject::Export
    )
}

/// The subject's item array in `data`, the whole read's answer for this caller. `None` for a
/// subject that is not a list.
fn listing(subject: &InspectSubject, data: &serde_json::Value) -> Option<Listing> {
    let (key, id, alias) = match subject {
        // ⟨M04 U5⟩ The owner's view lists every environment (`items`); any other role reads
        // its own environment's record alone (`environments`, M01's key).
        InspectSubject::Environments if data.get("items").is_some() => {
            ("items", "environment_id", None)
        }
        InspectSubject::Environments => ("environments", "id", None),
        InspectSubject::Profiles => ("items", "profile_id", None),
        InspectSubject::Destinations => ("items", "destination_id", Some("alias")),
        InspectSubject::Grants => ("grants", "grant_id", None),
        InspectSubject::Bindings => ("bindings", "binding_id", None),
        InspectSubject::Operations => ("operations", "operation_id", None),
        InspectSubject::Decisions => ("decisions", "decision_id", None),
        InspectSubject::Identities => ("identities", "identity_id", None),
        InspectSubject::Projections => ("projections", "id", None),
        InspectSubject::Enrollments => ("enrollments", "enrollment_id", None),
        InspectSubject::Connections => ("connections", "id", None),
        InspectSubject::Policies => ("items", "policy_id", None),
        InspectSubject::Capabilities
        | InspectSubject::Issuer
        | InspectSubject::Workspace
        | InspectSubject::Export => return None,
    };
    Some(Listing { key, id, alias })
}

/// `USAGE_ERROR` / `selector_invalid`, effect `none`.
fn selector_invalid(message: &str) -> OpError {
    OpError::new(Code::UsageError, message.to_owned())
        .with_reason(reason::SELECTOR_INVALID)
        .with_effect(EffectStatus::None)
}

/// `USAGE_ERROR` / `page_token_invalid`, effect `none`. The message names no part of the
/// token.
fn token_invalid() -> OpError {
    OpError::new(
        Code::UsageError,
        "the page token is not valid for this reader, environment, query or sort",
    )
    .with_reason(reason::PAGE_TOKEN_INVALID)
    .with_effect(EffectStatus::None)
}

/// `USAGE_ERROR` / `response_too_large`, effect `none`, naming the item.
fn too_large(subject: &InspectSubject, id: &str, message: &str) -> OpError {
    let kind = serde_json::to_value(subject)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "item".to_owned());
    OpError::new(Code::UsageError, message.to_owned())
        .with_reason(reason::RESPONSE_TOO_LARGE)
        .with_effect(EffectStatus::None)
        .with_resource(&kind, Some(id.to_owned()))
}

/// The form a request uses, checked: `select` and `page` one at a time (`selector_invalid`),
/// a selector of 1 to 64 entries (`selector_invalid`), a page limit of 1 to
/// [`PAGE_LIMIT_MAX`] (`USAGE_ERROR`).
#[derive(Debug, Clone)]
enum Form {
    Select(Select),
    Page {
        limit: usize,
        token: Option<PageToken>,
    },
}

impl Form {
    fn of(req: &InspectRequest) -> Result<Self, OpError> {
        match (&req.select, &req.page) {
            (Some(_), Some(_)) => Err(selector_invalid(
                "an inspect takes select or page, one at a time",
            )),
            (Some(s), None) if !s.is_well_formed() => {
                Err(selector_invalid("a selector names 1 to 64 entries"))
            }
            (Some(s), None) => Ok(Form::Select(s.clone())),
            (None, Some(PageRequest { limit, token })) => {
                let limit = limit.unwrap_or(PAGE_LIMIT_DEFAULT);
                if !(1..=PAGE_LIMIT_MAX).contains(&limit) {
                    return Err(OpError::new(
                        Code::UsageError,
                        format!("a page limit is 1 to {PAGE_LIMIT_MAX}"),
                    )
                    .with_effect(EffectStatus::None));
                }
                Ok(Form::Page {
                    limit: usize::try_from(limit).map_err(|_| internal("page limit"))?,
                    token: token.clone(),
                })
            }
            (None, None) => Err(internal("an inspect form without select or page")),
        }
    }
}

/// The digest of a page's scoped tuple (§6.2): the reader, the environment, the canonical
/// query and the sort, and the store's restore epoch.
pub(super) fn scope_digest(
    reader: &CallerContext,
    environment: &EnvironmentId,
    req: &InspectRequest,
    sort: &str,
    restore_epoch: u64,
) -> Result<[u8; 32], OpError> {
    let tuple = serde_json::json!({
        "version": TOKEN_VERSION,
        "reader": reader,
        "environment": environment,
        "subject": req.subject,
        "cwd": req.cwd,
        "preview": req.preview,
        "redact": req.redact,
        "sort": sort,
        "restore_epoch": restore_epoch,
    });
    heimdall_contract::canonical::request_hash("page-token-scope", &tuple)
        .map(|h| h.0)
        .map_err(|_| internal("the page scope could not be digested"))
}

fn mac(key: &PageTokenKey, scope: &[u8; 32], position: &[u8]) -> Result<HmacSha256, OpError> {
    let mut m = <HmacSha256 as hmac::Mac>::new_from_slice(key.expose())
        .map_err(|_| internal("the page token key is unusable"))?;
    m.update(MAC_CONTEXT);
    m.update(&[TOKEN_VERSION]);
    m.update(scope);
    m.update(&[u8::try_from(position.len()).map_err(|_| internal("page position"))?]);
    m.update(position);
    Ok(m)
}

/// Mint the token for the page after `position` (the last item's ID).
pub(super) fn seal(
    key: &PageTokenKey,
    scope: &[u8; 32],
    position: &str,
) -> Result<PageToken, OpError> {
    let pos = position.as_bytes();
    if pos.is_empty() || pos.len() > MAX_ID_LEN {
        return Err(internal("an item ID does not fit a page token"));
    }
    let tag = mac(key, scope, pos)?.finalize().into_bytes();
    let mut raw = Vec::with_capacity(1 + SCOPE_TAG_LEN + 1 + pos.len() + MAC_LEN);
    raw.push(TOKEN_VERSION);
    raw.extend_from_slice(&scope[..SCOPE_TAG_LEN]);
    raw.push(u8::try_from(pos.len()).map_err(|_| internal("page position"))?);
    raw.extend_from_slice(pos);
    raw.extend_from_slice(&tag);
    let text = Base64UrlUnpadded::encode_string(&raw);
    debug_assert!(text.len() <= MAX_PAGE_TOKEN_LEN);
    PageToken::parse(&text).map_err(|_| internal("a page token is out of bounds"))
}

/// Open a token for this scope: its position, or `page_token_invalid` when it was tampered
/// with or minted for another scope.
pub(super) fn open(
    key: &PageTokenKey,
    scope: &[u8; 32],
    token: &PageToken,
) -> Result<String, OpError> {
    let raw = Base64UrlUnpadded::decode_vec(token.as_str()).map_err(|_| token_invalid())?;
    let (&version, rest) = raw.split_first().ok_or_else(token_invalid)?;
    if version != TOKEN_VERSION || rest.len() < SCOPE_TAG_LEN + 1 + MAC_LEN {
        return Err(token_invalid());
    }
    let (tag, rest) = rest.split_at(SCOPE_TAG_LEN);
    let (&len, rest) = rest.split_first().ok_or_else(token_invalid)?;
    let len = usize::from(len);
    if len == 0 || rest.len() != len + MAC_LEN {
        return Err(token_invalid());
    }
    let (pos, sent) = rest.split_at(len);
    // The tag is a public digest prefix: a mismatch is a rescoped token, refused before the
    // MAC; the MAC, checked in constant time, is what binds the whole scope.
    if tag != &scope[..SCOPE_TAG_LEN] {
        return Err(token_invalid());
    }
    mac(key, scope, pos)?
        .verify_slice(sent)
        .map_err(|_| token_invalid())?;
    String::from_utf8(pos.to_vec()).map_err(|_| token_invalid())
}

/// The whole-read answer's items, each with its ID, ordered by ID with no duplicate, and the
/// rest of the answer (`preview`).
fn items_by_id(
    data: &mut serde_json::Value,
    listing: Listing,
) -> Result<Vec<(String, serde_json::Value)>, OpError> {
    let list = match data.get_mut(listing.key).map(serde_json::Value::take) {
        Some(serde_json::Value::Array(list)) => list,
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(_) => return Err(internal("a list subject answered without its list")),
    };
    let mut items = Vec::with_capacity(list.len());
    for item in list {
        let id = item
            .get(listing.id)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| internal("a listed item has no ID"))?
            .to_owned();
        items.push((id, item));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items.dedup_by(|a, b| a.0 == b.0);
    Ok(items)
}

impl Operations {
    /// The page tokens' key and the restore epoch (ADR-0013 §6.2; ruled 2026-11-25): read in a
    /// read transaction; only when no key exists yet is a write transaction opened, and
    /// [`Txn::page_token_key`] re-checks under its write lock, so two first readers create one
    /// key (the second finds the first's and its fresh bytes are dropped).
    pub(super) async fn page_key(&self) -> Result<(PageTokenKey, u64), OpError> {
        let store = std::sync::Arc::clone(&self.inner.config.store);
        let (stored, epoch) = tokio::task::spawn_blocking(move || store.read_page_token_key())
            .await
            .map_err(|_| internal("the page key read failed"))??;
        if let Some(key) = stored {
            return Ok((key, epoch));
        }
        let mut fresh = [0u8; 32];
        getrandom::fill(&mut fresh).map_err(|_| internal("no randomness for the page key"))?;
        self.write(move |tx, _| Ok((tx.page_token_key(move || fresh)?, tx.restore_epoch()?)))
            .await
    }

    /// `inspect` with `select` or `page` (ADR-0013 §6.1), on a session that negotiated
    /// `pages/1` (the IPC gate refuses any other with `SCHEMA_UNSUPPORTED` first).
    pub(super) async fn inspect_form(
        &self,
        caller: &Caller,
        req: InspectRequest,
    ) -> OpResult<serde_json::Value> {
        let form = Form::of(&req)?;
        // ADR-0013 §6.1 names no answer for a subject that is not a list: `selector_invalid`,
        // as for every other form that cannot apply.
        if !is_list(&req.subject) {
            return Err(selector_invalid(
                "select and page apply to list subjects only",
            ));
        }
        let whole = InspectRequest {
            select: None,
            page: None,
            ..req.clone()
        };
        match form {
            Form::Select(select) => self.inspect_select(caller, whole, select).await,
            Form::Page { limit, token } => self.inspect_page(caller, whole, limit, token).await,
        }
    }

    async fn inspect_select(
        &self,
        caller: &Caller,
        whole: InspectRequest,
        select: Select,
    ) -> OpResult<serde_json::Value> {
        let subject = whole.subject;
        if !select.aliases.is_empty() && subject != InspectSubject::Destinations {
            return Err(selector_invalid("only destinations are selected by alias"));
        }
        let rows = Rows::Pick {
            ids: select.ids.clone(),
            aliases: select.aliases.clone(),
        };
        let done = self.inspect_rows(caller, whole, rows).await?;
        let mut data = done.data;
        let listing = listing(&subject, &data).ok_or_else(|| internal("a list subject"))?;
        let items = items_by_id(&mut data, listing)?;
        let mut chosen: Vec<serde_json::Value> = Vec::new();
        let mut taken: BTreeSet<String> = BTreeSet::new();
        let mut missing: Vec<String> = Vec::new();
        let mut used = 0usize;
        let mut take = |id: &str, item: &serde_json::Value| -> Result<(), OpError> {
            if !taken.insert(id.to_owned()) {
                return Ok(());
            }
            used = used.saturating_add(serde_json::to_vec(item).map_or(usize::MAX, |b| b.len()));
            if used > PAGE_BUDGET_BYTES {
                return Err(too_large(
                    &subject,
                    id,
                    "the selected items do not fit one answer; select fewer",
                ));
            }
            chosen.push(item.clone());
            Ok(())
        };
        for id in &select.ids {
            match items.iter().find(|(i, _)| i == id) {
                Some((i, item)) => take(i, item)?,
                None => missing.push(id.clone()),
            }
        }
        for alias in &select.aliases {
            let found = listing.alias.and_then(|field| {
                items
                    .iter()
                    .find(|(_, item)| item.get(field).and_then(|a| a.as_str()) == Some(alias))
            });
            match found {
                Some((i, item)) => take(i, item)?,
                None => missing.push(alias.clone()),
            }
        }
        let mut answer = serde_json::json!({ "items": chosen, "missing": missing });
        carry_preview(&mut data, &mut answer);
        Ok(Completed {
            warnings: done.warnings,
            ..Completed::ok(Code::Ok, answer)
        })
    }

    async fn inspect_page(
        &self,
        caller: &Caller,
        whole: InspectRequest,
        limit: usize,
        token: Option<PageToken>,
    ) -> OpResult<serde_json::Value> {
        let subject = whole.subject;
        let (key, epoch) = self.page_key().await?;
        let scope = scope_digest(
            &caller.context,
            &self.inner.config.environment,
            &whole,
            SORT_BY_ID,
            epoch,
        )?;
        let after = token.as_ref().map(|t| open(&key, &scope, t)).transpose()?;
        let take = limit.saturating_add(1);
        let rows = Rows::After {
            after: after.clone(),
            take,
        };
        let done = self.inspect_rows(caller, whole, rows).await?;
        let mut data = done.data;
        let listing = listing(&subject, &data).ok_or_else(|| internal("a list subject"))?;
        let mut items = items_by_id(&mut data, listing)?;
        if let Some(after) = &after {
            items.retain(|(id, _)| id.as_str() > after.as_str());
        }
        let mut page: Vec<serde_json::Value> = Vec::new();
        let mut last: Option<String> = None;
        let mut used = 0usize;
        let mut more = false;
        for (id, item) in items {
            if page.len() == limit {
                more = true;
                break;
            }
            let n = serde_json::to_vec(&item).map_or(usize::MAX, |b| b.len());
            if used.saturating_add(n) > PAGE_BUDGET_BYTES {
                if page.is_empty() {
                    return Err(too_large(
                        &subject,
                        &id,
                        "this item does not fit a page; edit or remove it by ID",
                    ));
                }
                more = true;
                break;
            }
            used += n;
            page.push(item);
            last = Some(id);
        }
        let mut answer = serde_json::json!({ "items": page, "more": more });
        if more {
            let last = last.ok_or_else(|| internal("a page with more has a last item"))?;
            let next = seal(&key, &scope, &last)?;
            if let serde_json::Value::Object(map) = &mut answer {
                map.insert(
                    "next_page_token".to_owned(),
                    serde_json::Value::String(next.as_str().to_owned()),
                );
            }
        }
        carry_preview(&mut data, &mut answer);
        Ok(Completed {
            warnings: done.warnings,
            ..Completed::ok(Code::Ok, answer)
        })
    }
}

/// The whole read's `preview`, when one was asked for, rides along unchanged.
fn carry_preview(data: &mut serde_json::Value, answer: &mut serde_json::Value) {
    if let Some(preview) = data.get_mut("preview").map(serde_json::Value::take)
        && let serde_json::Value::Object(map) = answer
    {
        map.insert("preview".to_owned(), preview);
    }
}

#[cfg(test)]
#[path = "pages_m07_tests.rs"]
mod tests;
