//! ⟨rev7⟩ m07-plan U3 "Lists and pages" (ADR-0013 §6.1, §6.2; D2, D21): `pages_m07` over a
//! real in-memory store and a real `Operations`, callers in every read role.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use base64ct::Base64UrlUnpadded;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    ClientId, DestinationId, DeviceId, EnvironmentId, PolicyId, ProfileId,
};
use heimdall_contract::page::{PageRequest, PageToken, SELECT_MAX, Select};
use heimdall_contract::request::{InspectRequest, InspectSubject};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::Scope;
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_store::Store;
use heimdall_testkit::{ScriptedTimeSync, VirtualClock, assert_no_canary};
use proptest::prelude::*;
use proptest::test_runner::{RngSeed, TestRunner};

use super::*;
use crate::ensure::NoStageHook;
use crate::operations::{Limits, OperationsConfig};

fn t0() -> Timestamp {
    "2026-11-25T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([9; 16])
}

fn store() -> Arc<Store> {
    let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
    store
        .transaction(|tx| {
            tx.init_self_environment(&env_id())?;
            tx.upsert_environment(&EnvironmentRecord {
                id: env_id(),
                device: DeviceId::from_random_bytes([8; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            })
        })
        .unwrap();
    store
}

/// A runtime over `store` serving `environment`.
async fn ops_on(store: Arc<Store>, environment: EnvironmentId) -> Operations {
    Operations::start(OperationsConfig {
        store,
        clock: VirtualClock::at(t0()),
        time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
        time_policy: TimePolicy::default(),
        environment,
        adapters: Vec::new(),
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: Duration::from_secs(3600),
        projection: None,
    })
    .await
    .unwrap()
}

fn caller(uid: u32, role: ClientRole, client: Option<u8>) -> Caller {
    Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid },
        role,
        remote_client: client.map(|b| ClientId::from_random_bytes([b; 16])),
    })
}

fn owner() -> Caller {
    caller(501, ClientRole::Owner, None)
}

/// A paired `requester` and a paired `viewer` (both a limited role; distinct clients).
fn requester() -> Caller {
    caller(501, ClientRole::LimitedConsumer, Some(1))
}

fn viewer() -> Caller {
    caller(501, ClientRole::LimitedConsumer, Some(2))
}

fn destination(id: &str) -> DestinationRecord {
    DestinationRecord {
        id: DestinationId::parse(id).unwrap(),
        alias: format!("alias-{id}"),
        revision: 1,
        definition: DestinationDefinition::Observed,
        label: None,
        updated_at: t0(),
    }
}

fn seed_destinations(store: &Store, ids: impl IntoIterator<Item = String>) {
    let ids: Vec<String> = ids.into_iter().collect();
    store
        .transaction(move |tx| {
            for id in &ids {
                tx.upsert_destination(&destination(id))?;
            }
            Ok(())
        })
        .unwrap();
}

fn remove_destinations(store: &Store, ids: impl IntoIterator<Item = String>) {
    let ids: Vec<String> = ids.into_iter().collect();
    store
        .transaction(move |tx| {
            for id in &ids {
                tx.remove_destination(&DestinationId::parse(id).unwrap())?;
            }
            Ok(())
        })
        .unwrap();
}

fn seed_catalog(store: &Store) {
    seed_destinations(store, ["dst-a", "dst-b", "dst-c"].map(str::to_owned));
    store
        .transaction(|tx| {
            for p in ["dev", "ops"] {
                tx.upsert_profile(&ProfileDefinition {
                    id: ProfileId::parse(p).unwrap(),
                    revision: 1,
                    scope: Scope::default(),
                    label: None,
                })?;
            }
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol").unwrap(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope: Scope::default(),
                    environments: [env_id()].into_iter().collect(),
                    max_window: Duration::from_secs(3600),
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: Default::default(),
                    connection: Default::default(),
                    default: false,
                },
                false,
            )?;
            Ok(())
        })
        .unwrap();
}

fn whole(subject: InspectSubject) -> InspectRequest {
    InspectRequest {
        subject,
        preview: None,
        cwd: None,
        redact: false,
        select: None,
        page: None,
    }
}

fn paged(subject: InspectSubject, limit: Option<u32>, token: Option<PageToken>) -> InspectRequest {
    InspectRequest {
        page: Some(PageRequest { limit, token }),
        ..whole(subject)
    }
}

fn selected(subject: InspectSubject, ids: &[&str], aliases: &[&str]) -> InspectRequest {
    InspectRequest {
        select: Some(Select {
            ids: ids.iter().map(|s| (*s).to_owned()).collect(),
            aliases: aliases.iter().map(|s| (*s).to_owned()).collect(),
        }),
        ..whole(subject)
    }
}

/// Every answer and refusal a test saw, serialized as the wire carries it.
#[derive(Default)]
struct Seen(Vec<String>);

impl Seen {
    fn ok(&mut self, r: &OpResult<serde_json::Value>) {
        let text = match r {
            Ok(done) => serde_json::to_string(&done.data).unwrap(),
            Err(e) => serde_json::to_string(&e.clone().into_envelope()).unwrap(),
        };
        self.0.push(text);
    }
}

async fn inspect(
    ops: &Operations,
    who: &Caller,
    req: InspectRequest,
    seen: &mut Seen,
) -> OpResult<serde_json::Value> {
    let r = ops.inspect(who, req).await;
    seen.ok(&r);
    r
}

fn refusal(r: OpResult<serde_json::Value>) -> (Code, Option<String>) {
    let e = r.expect_err("refused");
    assert_eq!(e.effect_status, EffectStatus::None);
    (e.code, e.reason)
}

/// One traversal: every page's answer, checked for the page form.
async fn traverse(
    ops: &Operations,
    who: &Caller,
    subject: InspectSubject,
    limit: Option<u32>,
    seen: &mut Seen,
) -> Vec<serde_json::Value> {
    let mut pages = Vec::new();
    let mut token = None;
    loop {
        let page = inspect(ops, who, paged(subject, limit, token), seen)
            .await
            .unwrap()
            .data;
        let more = page["more"].as_bool().unwrap();
        assert_eq!(more, page.get("next_page_token").is_some(), "{page}");
        token = page
            .get("next_page_token")
            .map(|t| serde_json::from_value::<PageToken>(t.clone()).unwrap());
        pages.push(page);
        if !more {
            return pages;
        }
    }
}

fn ids_of(pages: &[serde_json::Value], id: &str) -> Vec<String> {
    pages
        .iter()
        .flat_map(|p| p["items"].as_array().unwrap().iter())
        .map(|i| i[id].as_str().unwrap().to_owned())
        .collect()
}

const LISTS: [InspectSubject; 12] = [
    InspectSubject::Environments,
    InspectSubject::Profiles,
    InspectSubject::Destinations,
    InspectSubject::Bindings,
    InspectSubject::Grants,
    InspectSubject::Operations,
    InspectSubject::Decisions,
    InspectSubject::Identities,
    InspectSubject::Projections,
    InspectSubject::Enrollments,
    InspectSubject::Connections,
    InspectSubject::Policies,
];

/// `limited_roles_page_their_visible_subjects`: for every list subject and every read role
/// (owner, requester, viewer), the traversal holds exactly the items of that role's whole
/// read, each complete and once, in strict ID order; and the limited roles see none of the
/// owner's catalog. Also every whole read stays as it was: its list is still under its own
/// key with its own extra fields.
#[tokio::test]
async fn limited_roles_page_their_visible_subjects() {
    let store = store();
    seed_catalog(&store);
    let ops = ops_on(store, env_id()).await;
    let mut seen = Seen::default();
    for who in [owner(), requester(), viewer()] {
        for subject in LISTS {
            let mut data = inspect(&ops, &who, whole(subject), &mut seen)
                .await
                .unwrap()
                .data;
            let listing = listing(&subject, &data).unwrap();
            let want = items_by_id(&mut data, listing).unwrap();
            for limit in [Some(1), None] {
                let pages = traverse(&ops, &who, subject, limit, &mut seen).await;
                let got: Vec<serde_json::Value> = pages
                    .iter()
                    .flat_map(|p| p["items"].as_array().unwrap().clone())
                    .collect();
                let want_items: Vec<serde_json::Value> =
                    want.iter().map(|(_, v)| v.clone()).collect();
                assert_eq!(got, want_items, "{subject:?} {:?}", who.context);
                let ids = ids_of(&pages, listing.id);
                assert!(ids.windows(2).all(|w| w[0] < w[1]), "{subject:?}");
            }
        }
        let destinations =
            traverse(&ops, &who, InspectSubject::Destinations, Some(2), &mut seen).await;
        let n = ids_of(&destinations, "destination_id").len();
        assert_eq!(n, if who.context.is_owner() { 3 } else { 0 });
        let profiles = traverse(&ops, &who, InspectSubject::Profiles, Some(1), &mut seen).await;
        assert_eq!(
            ids_of(&profiles, "profile_id").len(),
            if who.context.is_owner() { 2 } else { 0 }
        );
        let policies = traverse(&ops, &who, InspectSubject::Policies, None, &mut seen).await;
        assert_eq!(
            ids_of(&policies, "policy_id").len(),
            usize::from(who.context.is_owner())
        );
        // A limited role reads its own environment's record alone, the owner every one.
        let envs = traverse(&ops, &who, InspectSubject::Environments, Some(1), &mut seen).await;
        let id = if who.context.is_owner() {
            "environment_id"
        } else {
            "id"
        };
        assert_eq!(ids_of(&envs, id), vec![env_id().to_string()]);
    }
    for text in &seen.0 {
        assert_no_canary(text);
    }
}

/// `last_row_reachable_with_the_right_count`: 20,000 destinations; the traversal reaches the
/// last one, each once, ending at the first page with `more: false`. With 1000 per page that
/// page is full; when the remaining rows go before the last page is asked for, it is empty.
#[tokio::test]
async fn last_row_reachable_with_the_right_count() {
    let store = store();
    let ids: Vec<String> = (0..20_000).map(|i| format!("dst-{i:05}")).collect();
    seed_destinations(&store, ids.clone());
    let ops = ops_on(store.clone(), env_id()).await;
    let mut seen = Seen::default();
    let pages = traverse(
        &ops,
        &owner(),
        InspectSubject::Destinations,
        Some(1000),
        &mut seen,
    )
    .await;
    assert_eq!(pages.len(), 20);
    assert_eq!(ids_of(&pages, "destination_id"), ids);
    assert_eq!(
        pages.last().unwrap()["items"].as_array().unwrap().len(),
        1000
    );

    // 200 per page (the default): delete the last 200 after page 99, so page 100 is empty.
    let mut token = None;
    let mut got = Vec::new();
    for n in 1..=100 {
        if n == 100 {
            remove_destinations(&store, ids[19_800..].iter().cloned());
        }
        let page = inspect(
            &ops,
            &owner(),
            paged(InspectSubject::Destinations, None, token),
            &mut seen,
        )
        .await
        .unwrap()
        .data;
        got.extend(ids_of(std::slice::from_ref(&page), "destination_id"));
        let more = page["more"].as_bool().unwrap();
        assert_eq!(more, n < 100, "page {n}");
        if n == 100 {
            assert!(page["items"].as_array().unwrap().is_empty());
            assert!(page.get("next_page_token").is_none());
        }
        token = page
            .get("next_page_token")
            .map(|t| serde_json::from_value(t.clone()).unwrap());
    }
    assert_eq!(got.len(), 19_800);
    assert_eq!(got, ids[..19_800]);
}

/// The pagination proptest (fixed seed): between pages, destinations are inserted and
/// deleted. A stable item (present before the traversal, never deleted) is returned exactly
/// once; nothing is returned twice; the order is strictly increasing; an item deleted before
/// the traversal reached it is not returned.
#[test]
fn pagination_never_repeats_or_skips_a_stable_item() {
    const POOL: u8 = 40;
    let name = |i: u8| format!("dst-{i:02}");
    let step = prop_oneof![
        (0..POOL).prop_map(|i| (true, i)),
        (0..POOL).prop_map(|i| (false, i)),
    ];
    let case = (
        prop::collection::btree_set(0..POOL, 0..30),
        1u32..6,
        prop::collection::vec(prop::collection::vec(step, 0..6), 0..20),
    );
    let mut config = ProptestConfig {
        cases: 48,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    if matches!(config.rng_seed, RngSeed::Random) {
        config.rng_seed = RngSeed::Fixed(0x5533_5041_4745_5331);
    }
    let mut runner = TestRunner::new(config);
    let result = runner.run(&case, |(initial, limit, between)| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let store = store();
                seed_destinations(&store, initial.iter().map(|i| name(*i)));
                let ops = ops_on(store.clone(), env_id()).await;
                let mut present: BTreeSet<u8> = initial.clone();
                let mut ever_deleted: BTreeSet<u8> = BTreeSet::new();
                let mut got: Vec<String> = Vec::new();
                let mut token = None;
                let mut seen = Seen::default();
                for n in 0.. {
                    let page = inspect(
                        &ops,
                        &owner(),
                        paged(InspectSubject::Destinations, Some(limit), token),
                        &mut seen,
                    )
                    .await
                    .unwrap()
                    .data;
                    got.extend(ids_of(std::slice::from_ref(&page), "destination_id"));
                    if page["more"] == false {
                        break;
                    }
                    token = Some(serde_json::from_value(page["next_page_token"].clone()).unwrap());
                    for (insert, i) in between.get(n).cloned().unwrap_or_default() {
                        if insert && present.insert(i) {
                            seed_destinations(&store, [name(i)]);
                        } else if !insert && present.remove(&i) {
                            ever_deleted.insert(i);
                            remove_destinations(&store, [name(i)]);
                        }
                    }
                }
                prop_assert!(
                    got.windows(2).all(|w| w[0] < w[1]),
                    "strictly increasing: {got:?}"
                );
                for i in &initial {
                    if !ever_deleted.contains(i) {
                        prop_assert_eq!(got.iter().filter(|g| **g == name(*i)).count(), 1);
                    }
                }
                Ok(())
            })
    });
    if let Err(e) = result {
        panic!("{e}");
    }
}

/// `page_token_tampered_or_rescoped_is_refused`: a flipped byte; another sort, reader, role,
/// environment, query or restore epoch: `USAGE_ERROR` / `page_token_invalid`. The token
/// itself still pages for its own scope.
#[tokio::test]
async fn page_token_tampered_or_rescoped_is_refused() {
    let store = store();
    seed_catalog(&store);
    let ops = ops_on(store.clone(), env_id()).await;
    let mut seen = Seen::default();
    let first = inspect(
        &ops,
        &owner(),
        paged(InspectSubject::Destinations, Some(1), None),
        &mut seen,
    )
    .await
    .unwrap()
    .data;
    let token: PageToken = serde_json::from_value(first["next_page_token"].clone()).unwrap();
    assert!(token.as_str().len() <= heimdall_contract::page::MAX_PAGE_TOKEN_LEN);
    let invalid = |r: OpResult<serde_json::Value>| {
        assert_eq!(
            refusal(r),
            (
                Code::UsageError,
                Some(reason::PAGE_TOKEN_INVALID.to_owned())
            )
        );
    };
    let dest = InspectSubject::Destinations;

    // Its own scope: the next page.
    let next = inspect(
        &ops,
        &owner(),
        paged(dest, Some(1), Some(token.clone())),
        &mut seen,
    )
    .await
    .unwrap()
    .data;
    assert_eq!(next["items"][0]["destination_id"], "dst-b");

    // A flipped byte, anywhere.
    let raw = Base64UrlUnpadded::decode_vec(token.as_str()).unwrap();
    for at in [0, 1, 17, 18, raw.len() / 2, raw.len() - 1] {
        let mut bad = raw.clone();
        bad[at] ^= 0x01;
        let bad = PageToken::parse(&Base64UrlUnpadded::encode_string(&bad)).unwrap();
        invalid(inspect(&ops, &owner(), paged(dest, Some(1), Some(bad)), &mut seen).await);
    }
    // A truncated token.
    let short = PageToken::parse(&Base64UrlUnpadded::encode_string(&raw[..raw.len() - 1])).unwrap();
    invalid(inspect(&ops, &owner(), paged(dest, Some(1), Some(short)), &mut seen).await);

    // Another reader (principal), role, paired client.
    for who in [
        caller(502, ClientRole::Owner, None),
        caller(501, ClientRole::LimitedConsumer, None),
        caller(501, ClientRole::Owner, Some(1)),
        requester(),
    ] {
        invalid(
            inspect(
                &ops,
                &who,
                paged(dest, Some(1), Some(token.clone())),
                &mut seen,
            )
            .await,
        );
    }
    // Another query: subject, `cwd`, `redact`, `preview`. A changed limit is not a new query.
    invalid(
        inspect(
            &ops,
            &owner(),
            paged(InspectSubject::Profiles, Some(1), Some(token.clone())),
            &mut seen,
        )
        .await,
    );
    let mut with_preview = paged(dest, Some(1), Some(token.clone()));
    with_preview.preview = Some(heimdall_contract::request::EnsurePreview {
        profile: ProfileId::parse("dev").unwrap(),
        environment: None,
        until: None,
        required_capabilities: Default::default(),
    });
    invalid(inspect(&ops, &owner(), with_preview, &mut seen).await);
    let scope = |req: &InspectRequest, sort: &str, epoch: u64| {
        scope_digest(&owner().context, &env_id(), req, sort, epoch).unwrap()
    };
    let base = whole(dest);
    let mut with_cwd = base.clone();
    with_cwd.cwd = Some("/scratch".to_owned());
    let mut redacted = base.clone();
    redacted.redact = true;
    assert_ne!(scope(&base, SORT_BY_ID, 0), scope(&with_cwd, SORT_BY_ID, 0));
    assert_ne!(scope(&base, SORT_BY_ID, 0), scope(&redacted, SORT_BY_ID, 0));
    assert!(
        inspect(
            &ops,
            &owner(),
            paged(dest, Some(5), Some(token.clone())),
            &mut seen
        )
        .await
        .is_ok()
    );

    // Another sort, and another restore epoch: a token minted (under the same key) for that
    // scope is refused for this one.
    let key = store
        .transaction(|tx| tx.page_token_key(|| unreachable!("the key exists")))
        .unwrap();
    for (sort, epoch) in [("alias", 0), (SORT_BY_ID, 1)] {
        let other = seal(&key, &scope(&base, sort, epoch), "dst-a").unwrap();
        invalid(inspect(&ops, &owner(), paged(dest, Some(1), Some(other)), &mut seen).await);
    }
    // The same position minted for this scope pages: the refusals above are the scope's.
    let same = seal(&key, &scope(&base, SORT_BY_ID, 0), "dst-a").unwrap();
    assert_eq!(same, token);

    // Another environment. A runtime refuses a store of another environment, so the token is
    // minted under this store's key for the same reader, query and sort in another one.
    let elsewhere = scope_digest(
        &owner().context,
        &EnvironmentId::from_random_bytes([3; 16]),
        &base,
        SORT_BY_ID,
        0,
    )
    .unwrap();
    let other = seal(&key, &elsewhere, "dst-a").unwrap();
    invalid(inspect(&ops, &owner(), paged(dest, Some(1), Some(other)), &mut seen).await);

    // `page_key_never_leaves_the_store`: no answer or refusal here carries the key.
    key_absent(&key, &seen);
}

/// The key, in every form it could leak in, appears in no answer or refusal.
fn key_absent(key: &PageTokenKey, seen: &Seen) {
    let bytes = key.expose();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let forms = [
        hex.clone(),
        hex.to_uppercase(),
        Base64UrlUnpadded::encode_string(bytes),
        base64ct::Base64::encode_string(bytes),
        serde_json::to_string(&bytes.to_vec()).unwrap(),
    ];
    assert!(!seen.0.is_empty());
    for text in &seen.0 {
        assert_no_canary(text);
        for form in &forms {
            assert!(!text.contains(form.as_str()), "the page key left the store");
        }
    }
    assert!(!format!("{key:?}").contains(&hex[..8]));
}

/// `page_key_never_leaves_the_store`: over every form (whole, select, pages, refusals), the
/// key's bytes, read back from the store, appear in no answer and no refusal.
#[tokio::test]
async fn page_key_never_leaves_the_store() {
    let store = store();
    seed_catalog(&store);
    let ops = ops_on(store.clone(), env_id()).await;
    let mut seen = Seen::default();
    for who in [owner(), requester()] {
        for subject in LISTS {
            let _ = traverse(&ops, &who, subject, Some(1), &mut seen).await;
            let _ = inspect(&ops, &who, whole(subject), &mut seen).await;
            let _ = inspect(
                &ops,
                &who,
                selected(subject, &["dst-a", "nope"], &[]),
                &mut seen,
            )
            .await;
        }
    }
    let bad = PageToken::parse("AAAA").unwrap();
    let _ = inspect(
        &ops,
        &owner(),
        paged(InspectSubject::Destinations, None, Some(bad)),
        &mut seen,
    )
    .await;
    let key = store
        .transaction(|tx| tx.page_token_key(|| unreachable!("the key exists")))
        .unwrap();
    key_absent(&key, &seen);
}

/// `select_with_page_and_empty_selector_are_refused` (`selector_invalid`), a selector over 64
/// entries and a subject that is not a list too; and `select` answers `missing` for an absent
/// entry and for one the caller cannot see.
#[tokio::test]
async fn select_with_page_and_empty_selector_are_refused() {
    let store = store();
    seed_catalog(&store);
    let ops = ops_on(store, env_id()).await;
    let mut seen = Seen::default();
    let selector_invalid = (Code::UsageError, Some(reason::SELECTOR_INVALID.to_owned()));
    let dest = InspectSubject::Destinations;

    let mut both = selected(dest, &["dst-a"], &[]);
    both.page = Some(PageRequest::default());
    assert_eq!(
        refusal(inspect(&ops, &owner(), both, &mut seen).await),
        selector_invalid
    );
    assert_eq!(
        refusal(inspect(&ops, &owner(), selected(dest, &[], &[]), &mut seen).await),
        selector_invalid
    );
    let many: Vec<String> = (0..=SELECT_MAX).map(|i| format!("dst-{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(
        refusal(inspect(&ops, &owner(), selected(dest, &many, &[]), &mut seen).await),
        selector_invalid
    );
    for subject in [
        InspectSubject::Capabilities,
        InspectSubject::Issuer,
        InspectSubject::Workspace,
        InspectSubject::Export,
    ] {
        assert_eq!(
            refusal(inspect(&ops, &owner(), paged(subject, None, None), &mut seen).await),
            selector_invalid,
            "{subject:?}"
        );
        assert_eq!(
            refusal(inspect(&ops, &owner(), selected(subject, &["x"], &[]), &mut seen).await),
            selector_invalid,
            "{subject:?}"
        );
    }
    assert_eq!(
        refusal(
            inspect(
                &ops,
                &owner(),
                selected(InspectSubject::Profiles, &[], &["dev"]),
                &mut seen
            )
            .await
        ),
        selector_invalid
    );
    for limit in [0, heimdall_contract::page::PAGE_LIMIT_MAX + 1] {
        let (code, reason) =
            refusal(inspect(&ops, &owner(), paged(dest, Some(limit), None), &mut seen).await);
        assert_eq!((code, reason), (Code::UsageError, None), "{limit}");
    }

    // Absent and invisible entries are `missing`; present ones answer once, in full.
    let picked = inspect(
        &ops,
        &owner(),
        selected(
            dest,
            &["dst-b", "dst-nope", "dst-b"],
            &["alias-dst-c", "alias-nope"],
        ),
        &mut seen,
    )
    .await
    .unwrap()
    .data;
    let items = picked["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["destination_id"], "dst-b");
    assert_eq!(items[1]["destination_id"], "dst-c");
    assert_eq!(items[1]["alias"], "alias-dst-c");
    assert_eq!(
        picked["missing"],
        serde_json::json!(["dst-nope", "alias-nope"])
    );
    let mut data = inspect(&ops, &owner(), whole(dest), &mut seen)
        .await
        .unwrap()
        .data;
    let listed = listing(&dest, &data).unwrap();
    let all = items_by_id(&mut data, listed).unwrap();
    assert_eq!(
        items[0], all[1].1,
        "a selected item is the whole read's, complete"
    );
    for who in [requester(), viewer()] {
        let hidden = inspect(
            &ops,
            &who,
            selected(dest, &["dst-a"], &["alias-dst-b"]),
            &mut seen,
        )
        .await
        .unwrap()
        .data;
        assert_eq!(hidden["items"], serde_json::json!([]));
        assert_eq!(
            hidden["missing"],
            serde_json::json!(["dst-a", "alias-dst-b"])
        );
    }
    let profile = inspect(
        &ops,
        &owner(),
        selected(InspectSubject::Profiles, &["ops", "not a valid id!"], &[]),
        &mut seen,
    )
    .await
    .unwrap()
    .data;
    assert_eq!(profile["items"][0]["profile_id"], "ops");
    assert_eq!(profile["missing"], serde_json::json!(["not a valid id!"]));
}

/// A whole read (neither form) answers exactly as it did: the same document whatever the
/// pages a runtime served before it.
#[tokio::test]
async fn whole_reads_are_unchanged_by_pages() {
    let store = store();
    seed_catalog(&store);
    let ops = ops_on(store, env_id()).await;
    let mut seen = Seen::default();
    for subject in LISTS {
        let before = inspect(&ops, &owner(), whole(subject), &mut seen)
            .await
            .unwrap()
            .data;
        let _ = traverse(&ops, &owner(), subject, Some(1), &mut seen).await;
        let after = inspect(&ops, &owner(), whole(subject), &mut seen)
            .await
            .unwrap()
            .data;
        assert_eq!(before, after, "{subject:?}");
        assert!(before.get("more").is_none() && before.get("next_page_token").is_none());
    }
    // The destinations whole read stays in alias order under `items`.
    let d = inspect(
        &ops,
        &owner(),
        whole(InspectSubject::Destinations),
        &mut seen,
    )
    .await
    .unwrap()
    .data;
    let aliases: Vec<&str> = d["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["alias"].as_str().unwrap())
        .collect();
    assert_eq!(aliases, ["alias-dst-a", "alias-dst-b", "alias-dst-c"]);
}

/// ⟨U3-1b; ruled 2026-11-25⟩ `two_first_pages_create_one_key`: the page key is read in a read
/// transaction and created only when absent, re-checked under the write lock.
/// 1. The store: two first readers both find no key (held at a barrier after their read),
///    then both take the write path with different fresh bytes; the re-check keeps the first
///    writer's key, so both get the same key and it is the stored one.
/// 2. Two concurrent first pages through `Operations` on a fresh store: both answer the same
///    next-page token (same scope, same position, one key), the stored key verifies it, and a
///    later page reads the key without writing (the stored key is unchanged).
#[tokio::test]
async fn two_first_pages_create_one_key() {
    let store = store();
    assert!(
        store.read_page_token_key().unwrap().0.is_none(),
        "no key yet"
    );
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = [[1u8; 32], [2u8; 32]]
        .into_iter()
        .map(|bytes| {
            let (store, barrier) = (store.clone(), barrier.clone());
            std::thread::spawn(move || {
                let (read, epoch) = store.read_page_token_key().unwrap();
                assert!(read.is_none(), "both readers find no key");
                assert_eq!(epoch, 0);
                barrier.wait();
                store.transaction(|tx| tx.page_token_key(|| bytes)).unwrap()
            })
        })
        .collect();
    let keys: Vec<PageTokenKey> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let (stored, _) = store.read_page_token_key().unwrap();
    let stored = stored.expect("one key was created");
    assert_eq!(keys[0], keys[1], "both writers get the one key");
    assert_eq!(keys[0], stored);
    assert!(
        stored.expose() == &[1u8; 32] || stored.expose() == &[2u8; 32],
        "the key is one writer's fresh bytes"
    );

    let store = self::store();
    seed_catalog(&store);
    let ops = ops_on(store.clone(), env_id()).await;
    let who = owner();
    let first = || ops.inspect(&who, paged(InspectSubject::Destinations, Some(1), None));
    let (a, b) = tokio::join!(first(), first());
    let (a, b) = (a.unwrap().data, b.unwrap().data);
    assert_eq!(a["more"], true);
    assert_eq!(
        a["next_page_token"], b["next_page_token"],
        "one key seals both first pages"
    );
    let (key, _) = store.read_page_token_key().unwrap();
    let key = key.expect("the first page created the key");
    let token = PageToken::parse(a["next_page_token"].as_str().unwrap()).unwrap();
    let next = ops
        .inspect(
            &owner(),
            paged(InspectSubject::Destinations, Some(1), Some(token)),
        )
        .await
        .unwrap();
    assert_eq!(next.data["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(store.read_page_token_key().unwrap().0, Some(key));
}

// --- ⟨rev7; D20⟩ maximal records and legacy rows (m07-plan U3 "Bounds and refusals") -----

fn item_bytes(v: &impl serde::Serialize) -> usize {
    serde_json::to_vec(v).unwrap().len()
}

/// The one item a point `inspect` (`select` by ID) answers, through the real view builder.
async fn selected_item(ops: &Operations, subject: InspectSubject, id: &str) -> serde_json::Value {
    let mut seen = Seen::default();
    let data = inspect(ops, &owner(), selected(subject, &[id], &[]), &mut seen)
        .await
        .unwrap()
        .data;
    assert_eq!(data["missing"], serde_json::json!([]), "{data}");
    data["items"][0].clone()
}

/// A string of exactly `n` bytes in an ID's alphabet, unique per `seed`.
fn filled(seed: usize, n: usize) -> String {
    let head = format!("{seed:04}");
    format!("{head}{}", "x".repeat(n - head.len()))
}

/// ⟨D20⟩ Each catalog item kind at its bounds at once, at its worst-case escaping (a label of
/// `"`), read back through the item's own view (`select` by ID), leaves `ITEM_SPARE_BYTES`
/// under `MAX_ITEM_BYTES`: a profile of 200 pairs of 128-byte IDs; a destination (255-byte
/// alias and host name, 128-byte jump and account) with its 8 approved routes, each an
/// external-roost Iroh route with 3 canonical link-local addresses at their longest, an
/// interface bind at its longest, 4 consents, and 16 relay URLs of 2,048 bytes over the
/// destination; an identity with its label and a 4 KiB endpoint. ADR-0006 §19.5 puts the
/// profile at 58,381 bytes and the destination with its routes (and a route-health view this
/// crate does not build) at 58,569.
#[tokio::test]
async fn maximal_records_fit_an_item() {
    use heimdall_contract::bounds::{
        ITEM_SPARE_BYTES, MAX_CONSENTS_PER_ROUTE, MAX_DIRECT_ADDRESSES_PER_ROUTE, MAX_ITEM_BYTES,
        MAX_PROFILE_PAIRS, MAX_RELAYS_PER_DESTINATION, MAX_RELAYS_PER_ROUTE,
        MAX_ROUTES_PER_DESTINATION,
    };
    use heimdall_contract::catalog::MAX_LABEL_BYTES;
    use heimdall_contract::ids::{
        AccountName, ConsentId, IdentityId, IrohEndpointId, MAX_ID_LEN, RouteId,
    };
    use heimdall_contract::route::{
        BindScope, DestinationRoute, ExposurePolicy, InfrastructureProfile, RELAY_URL_MAX_BYTES,
        RouteSpec,
    };
    use heimdall_domain::scope::AccessPair;
    let store = store();
    let label = "\"".repeat(MAX_LABEL_BYTES);
    let account = AccountName::parse(&filled(1, MAX_ID_LEN)).unwrap();
    let profile = ProfileDefinition {
        id: ProfileId::parse(&filled(0, MAX_ID_LEN)).unwrap(),
        revision: u64::try_from(i64::MAX).unwrap(),
        scope: Scope {
            pairs: (0..MAX_PROFILE_PAIRS)
                .map(|i| AccessPair {
                    destination: DestinationId::parse(&filled(i, MAX_ID_LEN)).unwrap(),
                    account: AccountName::parse(&filled(i, MAX_ID_LEN)).unwrap(),
                })
                .collect(),
            capabilities: [
                heimdall_contract::request::Capability::SshAuthentication,
                heimdall_contract::request::Capability::GitSigning,
                heimdall_contract::request::Capability::AgentForwarding,
            ]
            .into_iter()
            .collect(),
        },
        label: Some(label.clone()),
    };
    let identity = heimdall_domain::catalog::IdentityRecord {
        id: IdentityId::from_random_bytes([0xee; 16]),
        revision: u64::try_from(i64::MAX).unwrap(),
        source: heimdall_domain::catalog::IdentitySource::NativeAgent {
            endpoint: heimdall_contract::provider::EndpointRef {
                kind: heimdall_contract::provider::EndpointKind::UnixSocket,
                locator: format!("/{}", "s".repeat(4095)),
            },
        },
        public_key: "ssh-ed25519 AAAA".to_owned(),
        fingerprint: format!("SHA256:{}", "A".repeat(43)),
        interaction: heimdall_domain::catalog::InteractionProfile {
            interaction: heimdall_contract::provider::InteractionKind::Unknown,
            basis: heimdall_contract::provider::EvidenceBasis::Inferred,
        },
        label: Some(label.clone()),
        adopted_at: t0(),
        updated_at: t0(),
    };
    let destination = DestinationRecord {
        id: DestinationId::parse(&filled(0, MAX_ID_LEN)).unwrap(),
        alias: "a".repeat(255),
        revision: u64::try_from(i64::MAX).unwrap(),
        definition: DestinationDefinition::Managed {
            hostname: "h".repeat(255),
            port: Some(65535),
            account,
            identity: identity.id.clone(),
            jump: Some(DestinationId::parse(&filled(2, MAX_ID_LEN)).unwrap()),
        },
        label: Some(label),
        updated_at: t0(),
    };
    // The canonical link-local IPv6 maximum with the largest numeric zone (ruling R-A).
    let v6 = |i: usize| format!("febf:ffff:ffff:ffff:ffff:ffff:ffff:{i:04x}%4294967295");
    // The longest bind address 1.0 takes: no zone (R-A's reading for binds).
    let bind_v6 = |i: usize| format!("febf:ffff:ffff:ffff:ffff:ffff:ffff:{i:04x}");
    let relay = |i: usize| {
        let head = format!("https://relay{i:02}.example.invalid/");
        format!("{head}{}", "p".repeat(RELAY_URL_MAX_BYTES - head.len()))
    };
    let mut relays_left = MAX_RELAYS_PER_DESTINATION;
    let routes: Vec<DestinationRoute> = (0..MAX_ROUTES_PER_DESTINATION)
        .map(|i| {
            let n = relays_left.min(MAX_RELAYS_PER_ROUTE);
            relays_left -= n;
            let byte = u8::try_from(i).unwrap();
            DestinationRoute {
                id: RouteId::from_random_bytes([byte; 16]),
                route: RouteSpec::Iroh {
                    endpoint: IrohEndpointId::parse(&format!("{byte:02x}").repeat(32)).unwrap(),
                    direct_addresses: (0..MAX_DIRECT_ADDRESSES_PER_ROUTE)
                        .map(|a| {
                            let text = format!("[{}]:65535", v6(a));
                            crate::routes::ops::canonical_socket_address(&text).unwrap()
                        })
                        .collect(),
                    external_roost: true,
                },
                exposure: Some(ExposurePolicy {
                    bind: BindScope::Interface {
                        address: crate::routes::ops::canonical_interface_address(&bind_v6(i))
                            .unwrap(),
                    },
                    infrastructure: InfrastructureProfile::Custom {
                        relays: (0..n).map(|r| relay(i * 8 + r)).collect(),
                    },
                    direct_fallback: true,
                    port: Some(65535),
                    ..ExposurePolicy::default()
                }),
                consents: (0..MAX_CONSENTS_PER_ROUTE)
                    .map(|c| {
                        ConsentId::from_random_bytes([byte * 8 + u8::try_from(c).unwrap(); 16])
                    })
                    .collect(),
                identification_timeout_ms: Some(u64::MAX),
            }
        })
        .collect();
    assert!(crate::routes::ops::check_list_bounds(&destination, &routes).is_ok());
    {
        let (p, i, d, r) = (
            profile.clone(),
            identity.clone(),
            destination.clone(),
            routes.clone(),
        );
        store
            .transaction(move |tx| {
                tx.upsert_profile(&p)?;
                tx.upsert_identity(&i)?;
                tx.upsert_destination(&d)?;
                tx.put_destination_routes(&d.id, &r, t0())
            })
            .unwrap();
    }
    let ops = ops_on(store.clone(), env_id()).await;
    let room = MAX_ITEM_BYTES - ITEM_SPARE_BYTES;
    let p = item_bytes(&selected_item(&ops, InspectSubject::Profiles, profile.id.as_str()).await);
    assert!(p <= room, "a maximal profile is {p} bytes");
    assert!(p > 50_000, "{p}: the order of ADR-0006 §19.5's 58,381");
    let view = selected_item(&ops, InspectSubject::Destinations, destination.id.as_str()).await;
    let stored = store
        .transaction(|tx| tx.destination_routes(&destination.id))
        .unwrap();
    let d = item_bytes(&view) + item_bytes(&stored);
    assert!(
        d <= room,
        "a maximal destination with its routes is {d} bytes (view {}, routes {})",
        item_bytes(&view),
        item_bytes(&stored)
    );
    // ADR-0006 §19.5's 58,569 also counts 8 host-key pins of 1,536 bytes (no writer stores a
    // pin in this build) and the runtime's route-health view (added by the dispatcher).
    assert!(
        d > 35_000,
        "{d}: the order of ADR-0006 §19.5's routes (52,361) less the pins"
    );
    let i =
        item_bytes(&selected_item(&ops, InspectSubject::Identities, identity.id.as_str()).await);
    assert!(i <= room, "a maximal identity is {i} bytes");
}

/// ⟨D20⟩ A legacy row over a bound (a profile of 300 pairs, written before the bounds) stays
/// readable by ID through the existing read path and is never rewritten by an unrelated write
/// (another profile defined through the catalog); a write to it at its bound is accepted, one
/// over it refused.
#[tokio::test]
async fn a_legacy_over_limit_row_stays_readable_and_unrewritten() {
    use heimdall_contract::ids::{AccountName, RequestId};
    use heimdall_domain::scope::AccessPair;
    let store = store();
    let legacy = ProfileDefinition {
        id: ProfileId::parse("legacy").unwrap(),
        revision: 3,
        scope: Scope {
            pairs: (0..300)
                .map(|i| AccessPair {
                    destination: DestinationId::parse(&format!("dst-{i:04}")).unwrap(),
                    account: AccountName::parse("deploy").unwrap(),
                })
                .collect(),
            capabilities: BTreeSet::new(),
        },
        label: None,
    };
    {
        let l = legacy.clone();
        store.transaction(move |tx| tx.upsert_profile(&l)).unwrap();
    }
    let ops = ops_on(store.clone(), env_id()).await;
    let read = selected_item(&ops, InspectSubject::Profiles, "legacy").await;
    assert_eq!(read["pairs"].as_array().unwrap().len(), 300);
    assert_eq!(read["revision"], 3);
    let raw = || {
        store
            .transaction(|tx| tx.profile(&ProfileId::parse("legacy").unwrap()))
            .unwrap()
            .unwrap()
    };
    let spec =
        |id: &str, n: usize, r: &str| heimdall_contract::catalog::CatalogRequest::UpsertProfile {
            profile: heimdall_contract::catalog::ProfileSpec {
                id: ProfileId::parse(id).unwrap(),
                pairs: (0..n)
                    .map(|i| heimdall_contract::request::AccessPairRef {
                        destination: DestinationId::parse(&format!("dst-{i:04}")).unwrap(),
                        account: AccountName::parse("deploy").unwrap(),
                    })
                    .collect(),
                label: None,
            },
            request_id: RequestId::parse(r).unwrap(),
        };
    ops.catalog(&owner(), spec("other", 2, "u1")).await.unwrap();
    assert_eq!(raw(), legacy, "an unrelated write rewrites nothing");
    let e = ops
        .catalog(&owner(), spec("legacy", 201, "u2"))
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::ITEM_TOO_LARGE));
    assert_eq!(raw(), legacy);
    // Its remediation through the existing catalog command: rewritten within the bound.
    ops.catalog(&owner(), spec("legacy", 200, "u3"))
        .await
        .unwrap();
    assert_eq!(raw().scope.pairs.len(), 200);
}

// --- ⟨rev7; S2, ruled 2026-11-25⟩ a page reads only its `limit + 1` rows ------------------

fn seed_operation(store: &Store, n: u16, who: &Caller) -> String {
    use heimdall_contract::canonical::RequestHash;
    use heimdall_contract::envelope::EffectStatus;
    use heimdall_contract::{
        OperationState,
        ids::{OperationId, RequestId},
    };
    use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
    use heimdall_domain::operation::{EffectClass, OperationKind, OperationRecord};
    let mut bytes = [0u8; 16];
    bytes[..2].copy_from_slice(&n.to_be_bytes());
    let mut hash = [0u8; 32];
    hash[..2].copy_from_slice(&n.to_be_bytes());
    let op = OperationRecord {
        id: OperationId::from_random_bytes(bytes),
        kind: OperationKind::Catalog,
        environment: env_id(),
        key: IdempotencyKey {
            caller: who.context.clone(),
            kind: OperationKind::Catalog,
            request_id: RequestId::parse(&format!("s2-{n}")).unwrap(),
        },
        request_hash: RequestHash(hash),
        effect_class: EffectClass::Local,
        // Unresolved: listed, and never driven by anything in this test.
        state: OperationState::OutcomeUnknown,
        code: None,
        effect_status: EffectStatus::Unknown,
        result: None,
        created_at: t0(),
        updated_at: t0(),
        cancellation: None,
        recovery: Default::default(),
    };
    let idem = IdempotencyRecord {
        key: op.key.clone(),
        request_hash: op.request_hash,
        operation_id: op.id.clone(),
        created_at: t0(),
        expires_at: None,
    };
    let id = op.id.to_string();
    store
        .transaction(move |tx| tx.insert_operation(&op, &idem))
        .unwrap();
    id
}

fn seed_decision(store: &Store, n: u16) -> String {
    use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
    let mut bytes = [0u8; 16];
    bytes[..2].copy_from_slice(&n.to_be_bytes());
    let id = heimdall_contract::ids::DecisionId::from_random_bytes(bytes);
    let text = id.to_string();
    store
        .transaction(move |tx| {
            let generation = tx.authority_generation()?;
            tx.insert_decision(&DecisionRecord {
                id,
                kind: DecisionKind::ConfirmTime {
                    boot_id: heimdall_domain::time::BootId("boot-s2".into()),
                    observed_wall: t0(),
                },
                generation,
                created_at: t0(),
                expires_at: "2099-01-01T00:00:00Z".parse().unwrap(),
                state: DecisionState::Pending,
                decided_at: None,
            })
        })
        .unwrap();
    text
}

/// ⟨S2; ruled 2026-11-25⟩ For each subject with a keyset store read, a page of `limit` over a
/// store of many rows reads only its `limit + 1` rows: the row just after them is damaged (it
/// does not decode), and the page still answers, with `more`, while the whole read, which
/// reaches that row, is refused. The next page, which must read the damaged row, is refused
/// too. A limited role's page of operations holds only its own, page after page.
#[tokio::test]
async fn a_page_reads_only_its_limit_plus_one_rows() {
    use heimdall_store::ext_m07::PageTable;
    const ROWS: u16 = 40;
    const LIMIT: u32 = 3;
    let store = store();
    let ops = ops_on(store.clone(), env_id()).await;
    let mut cases: Vec<(InspectSubject, PageTable, Vec<String>)> = Vec::new();
    let destinations: Vec<String> = (0..ROWS).map(|i| format!("dst-{i:04}")).collect();
    seed_destinations(&store, destinations.clone());
    cases.push((
        InspectSubject::Destinations,
        PageTable::Destinations,
        destinations,
    ));
    let profiles: Vec<String> = (0..ROWS).map(|i| format!("prf-{i:04}")).collect();
    {
        let ids = profiles.clone();
        store
            .transaction(move |tx| {
                for id in &ids {
                    tx.upsert_profile(&ProfileDefinition {
                        id: ProfileId::parse(id).unwrap(),
                        revision: 1,
                        scope: Scope::default(),
                        label: None,
                    })?;
                }
                Ok(())
            })
            .unwrap();
    }
    cases.push((InspectSubject::Profiles, PageTable::Profiles, profiles));
    let identities: Vec<String> = (0..ROWS)
        .map(|i| {
            let mut b = [0u8; 16];
            b[..2].copy_from_slice(&i.to_be_bytes());
            let id = heimdall_contract::ids::IdentityId::from_random_bytes(b);
            let record = heimdall_domain::catalog::IdentityRecord {
                id: id.clone(),
                revision: 1,
                source: heimdall_domain::catalog::IdentitySource::PublicKeyFile {
                    path: format!("/fixture/{i}.pub"),
                },
                public_key: "ssh-ed25519 AAAA".into(),
                fingerprint: format!("SHA256:{i:043}"),
                interaction: heimdall_domain::catalog::InteractionProfile {
                    interaction: heimdall_contract::provider::InteractionKind::Unknown,
                    basis: heimdall_contract::provider::EvidenceBasis::Inferred,
                },
                label: None,
                adopted_at: t0(),
                updated_at: t0(),
            };
            store.transaction(|tx| tx.upsert_identity(&record)).unwrap();
            id.to_string()
        })
        .collect();
    cases.push((
        InspectSubject::Identities,
        PageTable::Identities,
        identities,
    ));
    let operations: Vec<String> = (0..ROWS)
        .map(|i| seed_operation(&store, i, &owner()))
        .collect();
    cases.push((
        InspectSubject::Operations,
        PageTable::Operations,
        operations.clone(),
    ));
    let decisions: Vec<String> = (0..ROWS).map(|i| seed_decision(&store, i)).collect();
    cases.push((InspectSubject::Decisions, PageTable::Decisions, decisions));
    let id_of = |subject: InspectSubject| match subject {
        InspectSubject::Destinations => "destination_id",
        InspectSubject::Profiles => "profile_id",
        InspectSubject::Identities => "identity_id",
        InspectSubject::Operations => "operation_id",
        _ => "decision_id",
    };
    let mut seen = Seen::default();
    for (subject, table, mut ids) in cases {
        ids.sort();
        // Undamaged, the first page is the first `LIMIT` IDs.
        let first = inspect(&ops, &owner(), paged(subject, Some(LIMIT), None), &mut seen)
            .await
            .unwrap()
            .data;
        assert_eq!(
            ids_of(std::slice::from_ref(&first), id_of(subject)),
            ids[..3],
            "{subject:?}"
        );
        // The row just after the page's `limit + 1`.
        let damaged = ids[usize::try_from(LIMIT).unwrap() + 1].clone();
        let d = damaged.clone();
        assert_eq!(
            store
                .transaction(move |tx| tx.damage_document_for_test(table, &d))
                .unwrap(),
            1,
            "{subject:?}"
        );
        let page = inspect(&ops, &owner(), paged(subject, Some(LIMIT), None), &mut seen)
            .await
            .unwrap_or_else(|e| panic!("{subject:?}: the page read the damaged row: {e:?}"))
            .data;
        assert_eq!(page["more"], true, "{subject:?}");
        assert_eq!(page, first, "{subject:?}");
        assert!(
            inspect(&ops, &owner(), whole(subject), &mut seen)
                .await
                .is_err(),
            "{subject:?}: the whole read reaches the damaged row"
        );
        let token: PageToken = serde_json::from_value(page["next_page_token"].clone()).unwrap();
        assert!(
            inspect(
                &ops,
                &owner(),
                paged(subject, Some(LIMIT), Some(token)),
                &mut seen
            )
            .await
            .is_err(),
            "{subject:?}: the next page reads it"
        );
    }
    // A limited role pages its own operations only (the keyset read skips the others' rows
    // and still fills each page).
    let store = self::store();
    let ops = ops_on(store.clone(), env_id()).await;
    let mut own: Vec<String> = Vec::new();
    for i in 0..ROWS {
        if i % 3 == 0 {
            own.push(seed_operation(&store, i, &requester()));
        } else {
            seed_operation(&store, i, &viewer());
        }
    }
    own.sort();
    let pages = traverse(
        &ops,
        &requester(),
        InspectSubject::Operations,
        Some(LIMIT),
        &mut seen,
    )
    .await;
    assert_eq!(ids_of(&pages, "operation_id"), own);
    for p in &pages[..pages.len() - 1] {
        assert_eq!(p["items"].as_array().unwrap().len(), 3, "a full page: {p}");
    }
}

/// ⟨S2⟩ As [`a_page_reads_only_its_limit_plus_one_rows`], for the subjects whose rows need a
/// grant, a binding, an issuer or a projection owner: connections, projections, enrollments.
#[tokio::test]
async fn connection_projection_and_enrollment_pages_read_only_limit_plus_one_rows() {
    use heimdall_contract::GrantState;
    use heimdall_contract::ids::{
        AccountName, BindingId, CaFingerprint, ConnectionId, EnrollmentId, GrantId, IdentityId,
        ResourceId, WorkId,
    };
    use heimdall_contract::issuer::{CaState, StoreKind};
    use heimdall_contract::request::{Capability, DeadlineIntent};
    use heimdall_domain::binding::{BindingRecord, BindingState};
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
    use heimdall_domain::managed::{ConnectionKind, OwnedConnection, OwnedConnectionState};
    use heimdall_domain::policy::AuthorityGeneration;
    use heimdall_domain::projection::{FileIdentity, FileRole, ProjectionLocator, Sha256Hex};
    use heimdall_domain::resource::{
        ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
    };
    use heimdall_domain::scope::AccessPair;
    use heimdall_store::ext_m07::PageTable;
    const ROWS: u16 = 30;
    const LIMIT: u32 = 3;
    let bytes = |tag: u8, i: u16| {
        let mut b = [tag; 16];
        b[..2].copy_from_slice(&i.to_be_bytes());
        b
    };
    let store = store();
    let pair = AccessPair {
        destination: DestinationId::parse("h1").unwrap(),
        account: AccountName::parse("u1").unwrap(),
    };
    let grant = GrantSnapshot {
        id: GrantId::from_random_bytes([0x61; 16]),
        environment: env_id(),
        scope: Scope {
            pairs: [pair.clone()].into_iter().collect(),
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
        },
        starts_at: t0(),
        deadline: heimdall_domain::time::Deadline {
            intent: DeadlineIntent::Duration("2h".into()),
            resolved_at: t0(),
            effective: "2026-11-25T11:00:00Z".parse().unwrap(),
        },
        parent: None,
        source: AuthorizationSource::StandingPolicy {
            revision: PolicyRevision(1),
        },
        generation: AuthorityGeneration(0),
        state: GrantState::Active,
        enforcement: EnforcementEvidence::unknown(),
    };
    let binding = BindingRecord {
        id: BindingId::from_random_bytes([0x62; 16]),
        environment: env_id(),
        grant: grant.id.clone(),
        work_id: WorkId::parse("w").unwrap(),
        owner: owner().context,
        profile: ProfileId::parse("default").unwrap(),
        profile_revision: 1,
        scope: grant.scope.clone(),
        mechanism: "managed_certificate".into(),
        parent: None,
        created_at: t0(),
        released_at: None,
        state: BindingState::Active,
    };
    let ca = CaFingerprint::parse(&format!("SHA256:{}", "C".repeat(43))).unwrap();
    let mut connections = Vec::new();
    let mut resources = Vec::new();
    let mut enrollments = Vec::new();
    {
        let (grant, binding, ca) = (grant.clone(), binding.clone(), ca.clone());
        let seeded = store
            .transaction(move |tx| {
                tx.insert_grant(&grant)?;
                tx.insert_binding(&binding)?;
                tx.insert_issuer(&heimdall_store::IssuerRecord {
                    ca_fingerprint: ca.clone(),
                    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture".into(),
                    state: CaState::Active,
                    store_kind: StoreKind::LinuxSecretService,
                    backup_sha256: "ab".repeat(32),
                    backup_created_at: t0(),
                    restored_without_log: false,
                    created_at: t0(),
                    retired_at: None,
                })?;
                let mut out = (Vec::new(), Vec::new(), Vec::new());
                for i in 0..ROWS {
                    let c = OwnedConnection {
                        id: ConnectionId::from_random_bytes(bytes(0x63, i)),
                        kind: ConnectionKind::Master,
                        binding: binding.id.clone(),
                        grant: grant.id.clone(),
                        pid: 4242,
                        start_token: format!("start-{i}"),
                        image: "/usr/bin/ssh".into(),
                        control_path: Some(format!("/scratch/run/mux/m{i}")),
                        generation: u64::from(i) + 1,
                        state: OwnedConnectionState::Up,
                        started_at: t0(),
                    };
                    out.0.push(c.id.to_string());
                    tx.insert_owned_connection(&c)?;
                    let locator = ProjectionLocator {
                        role: FileRole::ManagedSsh,
                        path: format!("/scratch/home/.ssh/heimdall-{i}"),
                        identity: FileIdentity::Unix {
                            dev: 1,
                            ino: u64::from(i) + 1,
                            birth: None,
                        },
                        sha256: Sha256Hex::of(format!("p{i}").as_bytes()),
                    };
                    let r = ManagedResource {
                        id: ResourceId::from_random_bytes(bytes(0x64, i)),
                        kind: ResourceKind::ConfigProjection,
                        owner: OwnerRef::Projection {
                            environment: env_id(),
                        },
                        generation: ResourceGeneration(1),
                        desired: ResourceState::Present,
                        observed: ResourceState::Present,
                        last_operation: None,
                        locator: locator.canonical().unwrap(),
                        updated_at: t0(),
                    };
                    out.1.push(r.id.to_string());
                    tx.put_projection_resource(&r, None)?;
                    let id = EnrollmentId::from_random_bytes(bytes(0x65, i));
                    let record = heimdall_domain::enrollment::EnrollmentRecord {
                        marker: heimdall_domain::enrollment::marker_for(&id),
                        id: id.clone(),
                        destination: DestinationId::parse(&format!("dst-{i:04}")).unwrap(),
                        account: AccountName::parse("deploy").unwrap(),
                        ca_fingerprint: ca.clone(),
                        form: heimdall_contract::enrollment::EnrollmentForm::Account,
                        registry: heimdall_contract::enrollment::RegistryRef {
                            path_display: "$HOME/.ssh/authorized_keys".into(),
                            resolved_by:
                                heimdall_contract::enrollment::RegistryResolvedBy::RemoteHome,
                        },
                        registry_canonical: heimdall_contract::enrollment::RegistryCanonical {
                            path: None,
                            resolved_by:
                                heimdall_contract::enrollment::RegistryResolvedBy::RemoteHome,
                        },
                        line_sha256: "ab".repeat(32),
                        target: heimdall_contract::enrollment::ApprovedTarget {
                            hostname: format!("h{i}.example.invalid"),
                            port: 22,
                            user: AccountName::parse("deploy").unwrap(),
                            proxy: heimdall_contract::enrollment::NoProxy::None,
                            host_key: heimdall_contract::enrollment::ApprovedHostKey {
                                algorithm: "ssh-ed25519".into(),
                                key: "AAAA".into(),
                                fingerprint: format!("SHA256:{}", "B".repeat(43)),
                            },
                        },
                        existing_access: heimdall_domain::enrollment::ExistingAccessRecord {
                            identity: IdentityId::from_random_bytes([7; 16]),
                            endpoint: None,
                            public_key_file: None,
                        },
                        hold: None,
                        removal_origin: None,
                        late_write: None,
                        state: heimdall_contract::enrollment::EnrollmentState::Planned,
                        verified_at: None,
                        evidence: None,
                        created_at: t0(),
                        updated_at: t0(),
                    };
                    out.2.push(id.to_string());
                    tx.insert_enrollment(&record)?;
                }
                Ok(out)
            })
            .unwrap();
        connections.extend(seeded.0);
        resources.extend(seeded.1);
        enrollments.extend(seeded.2);
    }
    let ops = ops_on(store.clone(), env_id()).await;
    let mut seen = Seen::default();
    for (subject, table, mut ids, key, id) in [
        (
            InspectSubject::Connections,
            PageTable::OwnedConnections,
            connections,
            "connections",
            "id",
        ),
        (
            InspectSubject::Projections,
            PageTable::Resources,
            resources,
            "projections",
            "id",
        ),
        (
            InspectSubject::Enrollments,
            PageTable::Enrollments,
            enrollments,
            "enrollments",
            "enrollment_id",
        ),
    ] {
        ids.sort();
        let all = inspect(&ops, &owner(), whole(subject), &mut seen)
            .await
            .unwrap()
            .data;
        assert_eq!(
            all[key].as_array().map(Vec::len),
            Some(ids.len()),
            "{subject:?}: every row is listed"
        );
        let pages = traverse(&ops, &owner(), subject, Some(LIMIT), &mut seen).await;
        assert_eq!(
            ids_of(&pages, id),
            ids,
            "{subject:?}: the pages list every row once"
        );
        let first = pages[0].clone();
        let damaged = ids[usize::try_from(LIMIT).unwrap() + 1].clone();
        assert_eq!(
            store
                .transaction(move |tx| tx.damage_document_for_test(table, &damaged))
                .unwrap(),
            1
        );
        let page = inspect(&ops, &owner(), paged(subject, Some(LIMIT), None), &mut seen)
            .await
            .unwrap_or_else(|e| panic!("{subject:?}: the page read the damaged row: {e:?}"))
            .data;
        assert_eq!(page, first, "{subject:?}");
        assert!(
            inspect(&ops, &owner(), whole(subject), &mut seen)
                .await
                .is_err(),
            "{subject:?}: the whole read reaches the damaged row"
        );
    }
}

/// ⟨S2; U3-2b⟩ As [`a_page_reads_only_its_limit_plus_one_rows`], for environments and policies.
/// The owner's environments are the union of three sources (the native entry, this runtime's
/// managed rows, the distributions served in Mode A only, listed by namespace): the pages hold
/// exactly the whole read's items, in ID order, each once, with the rows another runtime
/// manages and the distributions the whole read leaves out (Mode B, no namespace, neither mode)
/// left out too, and `select` answers each by its ID as the whole read lists it. A page reads
/// only its `limit + 1` managed rows and policies: the row after them is damaged, the page
/// still answers, the whole read and the next page are refused.
#[tokio::test]
async fn environment_and_policy_pages_read_only_limit_plus_one_rows() {
    use heimdall_contract::environment::DistributionGuid;
    use heimdall_domain::environment::{
        EnvironmentRealization, ManagedEnvironment, ManagedState, WslDistributionRecord,
    };
    use heimdall_store::ext_m07::PageTable;
    const ROWS: u16 = 30;
    const LIMIT: u32 = 3;
    let bytes = |tag: u8, i: u16| {
        let mut b = [tag; 16];
        b[..2].copy_from_slice(&i.to_be_bytes());
        b
    };
    let store = store();
    let ops = ops_on(store.clone(), env_id()).await;
    let other_runtime = EnvironmentId::from_random_bytes([0x77; 16]);
    let managed: Vec<String> = (0..ROWS)
        .map(|i| EnvironmentId::from_random_bytes(bytes(0x00, i)).to_string())
        .collect();
    let guid = |tag: u8, i: u16| {
        DistributionGuid::parse(&format!("{tag:02x}{i:06x}-0000-0000-0000-000000000000")).unwrap()
    };
    let wsl = |tag: u8, i: u16, namespace: Option<EnvironmentId>| WslDistributionRecord {
        guid: guid(tag, i),
        name: format!("d{tag}-{i}"),
        mode_a: true,
        mode_b: None,
        cleanup_pending: false,
        account: Some("u".to_owned()),
        namespace,
        updated_at: t0(),
    };
    let namespaces = {
        let managed = managed.clone();
        let other_runtime = other_runtime.clone();
        store
            .transaction(move |tx| {
                let row =
                    |id: EnvironmentId, controller: EnvironmentId, i: u16| ManagedEnvironment {
                        environment: id,
                        controller,
                        realization: EnvironmentRealization::Container {
                            label: format!("c{i}"),
                            dir_tag: format!("{i:016x}"),
                        },
                        state: if i.is_multiple_of(2) {
                            ManagedState::Active
                        } else {
                            ManagedState::Removed
                        },
                        created_at: t0(),
                        updated_at: t0(),
                    };
                for (i, id) in (0..ROWS).zip(&managed) {
                    tx.insert_managed_environment(&row(
                        EnvironmentId::parse(id).unwrap(),
                        env_id(),
                        i,
                    ))?;
                    // Rows another runtime manages, interleaved by ID: never listed.
                    tx.insert_managed_environment(&row(
                        EnvironmentId::from_random_bytes(bytes(0x01, i)),
                        other_runtime.clone(),
                        i,
                    ))?;
                }
                let mut listed = Vec::new();
                for i in 0..ROWS {
                    // Mode A only (some still owing cleanup after a disable): listed by namespace.
                    let ns = EnvironmentId::from_random_bytes(bytes(0xf0, i));
                    let mut rec = wsl(0xa0, i, Some(ns.clone()));
                    if i.is_multiple_of(3) {
                        rec.mode_a = false;
                        rec.cleanup_pending = true;
                    }
                    tx.put_wsl_distribution(&rec)?;
                    listed.push(ns.to_string());
                    // Never listed: Mode B enabled, no namespace, neither mode.
                    let mut b = wsl(
                        0xb0,
                        i,
                        Some(EnvironmentId::from_random_bytes(bytes(0xf1, i))),
                    );
                    b.mode_b = Some(EnvironmentId::from_random_bytes(bytes(0x02, i)));
                    tx.put_wsl_distribution(&b)?;
                    tx.put_wsl_distribution(&wsl(0xc0, i, None))?;
                    let mut n = wsl(
                        0xd0,
                        i,
                        Some(EnvironmentId::from_random_bytes(bytes(0xf2, i))),
                    );
                    n.mode_a = false;
                    tx.put_wsl_distribution(&n)?;
                }
                for i in 0..ROWS {
                    tx.upsert_policy(
                        &StandingPolicy {
                            id: PolicyId::parse(&format!("pol-{i:04}")).unwrap(),
                            revision: PolicyRevision(1),
                            profile: ProfileId::parse("dev").unwrap(),
                            workspace: None,
                            scope: Scope::default(),
                            environments: [env_id()].into_iter().collect(),
                            max_window: Duration::from_secs(3600),
                            pause: PauseState::Active,
                            cutoff_at: None,
                            source: PolicySource::SetupDefault,
                            lock_behavior: Default::default(),
                            connection: Default::default(),
                            default: false,
                        },
                        false,
                    )?;
                }
                Ok(listed)
            })
            .unwrap()
    };
    let mut environments: Vec<String> = managed.clone();
    environments.push(env_id().to_string());
    environments.extend(namespaces.iter().cloned());
    environments.sort();
    let policies: Vec<String> = (0..ROWS).map(|i| format!("pol-{i:04}")).collect();
    let mut seen = Seen::default();
    for (subject, mut ids, id) in [
        (InspectSubject::Environments, environments, "environment_id"),
        (InspectSubject::Policies, policies, "policy_id"),
    ] {
        ids.sort();
        let all = inspect(&ops, &owner(), whole(subject), &mut seen)
            .await
            .unwrap()
            .data;
        let mut items: Vec<serde_json::Value> = all["items"].as_array().unwrap().clone();
        items.sort_by(|a, b| a[id].as_str().cmp(&b[id].as_str()));
        assert_eq!(
            items
                .iter()
                .map(|i| i[id].as_str().unwrap())
                .collect::<Vec<_>>(),
            ids,
            "{subject:?}: the whole read lists exactly these"
        );
        let pages = traverse(&ops, &owner(), subject, Some(LIMIT), &mut seen).await;
        let paged_items: Vec<serde_json::Value> = pages
            .iter()
            .flat_map(|p| p["items"].as_array().unwrap().iter().cloned())
            .collect();
        assert_eq!(
            paged_items, items,
            "{subject:?}: the pages are the whole read"
        );
        for p in &pages[..pages.len() - 1] {
            assert_eq!(p["items"].as_array().unwrap().len(), 3, "a full page: {p}");
        }
        // `select`: the first, a middle and the last item by ID, and one the read leaves out.
        let pick = [
            ids[0].as_str(),
            ids[ids.len() / 2].as_str(),
            ids[ids.len() - 1].as_str(),
        ];
        let left_out = EnvironmentId::from_random_bytes(bytes(0x01, 0)).to_string();
        let mut asked: Vec<&str> = pick.to_vec();
        asked.push(&left_out);
        let chosen = inspect(&ops, &owner(), selected(subject, &asked, &[]), &mut seen)
            .await
            .unwrap()
            .data;
        let want: Vec<serde_json::Value> = pick
            .iter()
            .map(|p| items.iter().find(|i| i[id] == *p).unwrap().clone())
            .collect();
        assert_eq!(
            chosen["items"],
            serde_json::Value::Array(want),
            "{subject:?}"
        );
        assert_eq!(
            chosen["missing"],
            serde_json::json!([left_out]),
            "{subject:?}"
        );
    }
    // A page reads only its `limit + 1` managed rows and policies.
    for (subject, table, damaged) in [
        (
            InspectSubject::Environments,
            PageTable::ManagedEnvironments,
            managed[usize::try_from(LIMIT).unwrap() + 1].clone(),
        ),
        (
            InspectSubject::Policies,
            PageTable::Policies,
            format!("pol-{:04}", LIMIT + 1),
        ),
    ] {
        let first = inspect(&ops, &owner(), paged(subject, Some(LIMIT), None), &mut seen)
            .await
            .unwrap()
            .data;
        assert_eq!(
            store
                .transaction(move |tx| tx.damage_document_for_test(table, &damaged))
                .unwrap(),
            1,
            "{subject:?}"
        );
        let page = inspect(&ops, &owner(), paged(subject, Some(LIMIT), None), &mut seen)
            .await
            .unwrap_or_else(|e| panic!("{subject:?}: the page read the damaged row: {e:?}"))
            .data;
        assert_eq!(page["more"], true, "{subject:?}");
        assert_eq!(page, first, "{subject:?}");
        assert!(
            inspect(&ops, &owner(), whole(subject), &mut seen)
                .await
                .is_err(),
            "{subject:?}: the whole read reaches the damaged row"
        );
        let token: PageToken = serde_json::from_value(page["next_page_token"].clone()).unwrap();
        assert!(
            inspect(
                &ops,
                &owner(),
                paged(subject, Some(LIMIT), Some(token)),
                &mut seen
            )
            .await
            .is_err(),
            "{subject:?}: the next page reads it"
        );
    }
}
