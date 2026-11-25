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
