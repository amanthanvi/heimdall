//! ADR-0006 revision 5 contract deltas (joint wave 0 of M04 and M05; ADR-0006 §17).
//!
//! Expected values are transcribed from `docs/architecture/m04-plan.md` §5,
//! `docs/architecture/m05-plan.md` §4 and the rulings (ADR-0010 §9, ADR-0011 §10), never
//! from the code under test:
//! * `rev5_reason_golden`: the M04 and M05 reasons, and the M03 reason revision 5 adds
//!   (`issuer_refused`, wave 6 I-8(2)), with their codes (`golden/rev5-reasons.golden.json`)
//!   against `envelope::reason::{M03_REV5, M04, M05}`, both ways; no reason string reused
//!   across M02, M03, M04 and M05; the M05 warning;
//! * `rev5_examples_round_trip_and_validate`: every new example payload round-trips
//!   exactly through its type and validates against its generated public schema;
//! * `rev5_capabilities_declared_not_offered_and_required`: `environments/1` and
//!   `trusted-work/1` exist, are what the new request forms require, and the M01–M03
//!   forms still require nothing new. The offer itself is the runtime's, not the contract's:
//!   ⟨M04 U5⟩ `environments/1` and ⟨M05 W3⟩ `trusted-work/1` are both offered
//!   (`heimdall_ipc::session::tests::the_revision_5_offer_is_environments_and_trusted_work`);
//!   the name is kept because ADR-0006 §17.7 cites it;
//! * `rev5_m01_m03_forms_unchanged`: every pre-revision-5 example decodes into the
//!   extended types and re-encodes byte-identically, and none uses a revision-5 form.
//!
//! The ensure-hash rule (§17.4) is proven where the hash is computed: the base goldens
//! of `e2e_consumer_m03`, `model_operations_m03::connection_absent_hash_unchanged_from_m02`
//! and the unit test of `app::operations::pair_mechanism_m03::ensure_hash_extra`.

use std::collections::BTreeSet;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use heimdall_contract::code::Code;
use heimdall_contract::envelope::{m03_warning, m05_warning, reason};
use heimdall_contract::environment::EnvironmentsView;
use heimdall_contract::ipc::capability;
use heimdall_contract::project::{Manifest, PortableBundle};
use heimdall_contract::request::Request;
use heimdall_contract::schema::{project_schemas, public_schemas};
use heimdall_contract::trust::{
    DecisionScope, PoliciesView, PolicyRevisionRef, PolicyTargetResult, WorkspaceView,
};

use crate::jsonschema_lite::validate;
use crate::{assert_clean, repo_root};

fn load(path: &str) -> Value {
    let text = std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|e| panic!("{path} unreadable: {}", e.kind()));
    assert_clean(path, &text);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn rows(golden: &Value, key: &str) -> BTreeSet<(String, String)> {
    golden[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["reason"].as_str().unwrap().to_owned(),
                r["code"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn in_code(list: &[(&str, Code)]) -> BTreeSet<(String, String)> {
    list.iter()
        .map(|(r, c)| ((*r).to_owned(), c.as_str().to_owned()))
        .collect()
}

#[test]
fn rev5_reason_golden() {
    let golden = load("tests/contracts/golden/rev5-reasons.golden.json");
    for (key, list) in [
        ("m03", reason::M03_REV5),
        ("m04", reason::M04),
        ("m05", reason::M05),
    ] {
        let want = rows(&golden, key);
        assert_eq!(
            want.len(),
            golden[key].as_array().unwrap().len(),
            "{key}: duplicate golden rows"
        );
        let got = in_code(list);
        assert_eq!(got.len(), list.len(), "{key}: duplicate rows in code");
        assert_eq!(got, want, "{key}: reasons and codes");
        for (r, _) in &got {
            assert!(
                r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{r}"
            );
        }
    }
    // Each reason string is used once across the four lists (M05's two-code rows are
    // one reason).
    let names = |list: &[(&str, Code)]| -> BTreeSet<String> {
        list.iter().map(|(r, _)| (*r).to_owned()).collect()
    };
    let m02: BTreeSet<String> = reason::ALL.iter().map(|s| (*s).to_owned()).collect();
    let mut m03 = names(reason::M03);
    m03.extend(names(reason::M03_REV5));
    assert_eq!(
        m03.len(),
        reason::M03.len() + reason::M03_REV5.len(),
        "a revision-5 M03 reason repeats M03"
    );
    let lists = [m02, m03, names(reason::M04), names(reason::M05)];
    for (i, a) in lists.iter().enumerate() {
        for b in &lists[i + 1..] {
            assert!(
                a.is_disjoint(b),
                "a reason reused: {:?}",
                a.intersection(b).collect::<Vec<_>>()
            );
        }
    }
    let warnings: BTreeSet<String> = m05_warning::ALL.iter().map(|s| (*s).to_owned()).collect();
    let want: BTreeSet<String> = serde_json::from_value(golden["m05_warnings"].clone()).unwrap();
    assert_eq!(warnings, want);
    assert!(
        warnings
            .iter()
            .all(|w| !m03_warning::ALL.contains(&w.as_str()))
    );
    // ⟨M04; ruling I-9⟩ The M04 finding codes and their sub-reasons, both ways; distinct
    // from M02's and M03's findings, snake_case, and each sub-reason refines an M04 finding.
    let m04_findings: BTreeSet<String> = heimdall_contract::doctor::finding::M04
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let want: BTreeSet<String> =
        serde_json::from_value(golden["m04_doctor_findings"].clone()).unwrap();
    assert_eq!(m04_findings, want, "M04 doctor findings");
    for f in &m04_findings {
        assert!(
            f.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "{f}"
        );
        assert!(
            !heimdall_contract::doctor::finding::ALL.contains(&f.as_str())
                && !heimdall_contract::doctor::finding::M03.contains(&f.as_str()),
            "{f} repeats an earlier finding"
        );
    }
    let reasons: BTreeSet<(String, String)> = golden["m04_finding_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["reason"].as_str().unwrap().to_owned(),
                r["finding"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let in_code: BTreeSet<(String, String)> = heimdall_contract::doctor::finding::M04_REASONS
        .iter()
        .map(|(r, f)| ((*r).to_owned(), (*f).to_owned()))
        .collect();
    assert_eq!(in_code, reasons, "M04 finding sub-reasons");
    assert!(in_code.iter().all(|(_, f)| m04_findings.contains(f)));
    // ⟨rev7; M08 U2b-2⟩ Unchanged by this revision: 31 since revision 7's `REQUEST_STALE`.
    assert_eq!(Code::all().len(), 31, "the code table is unchanged");
}

/// `T` round-trips `path` exactly and the document validates against `schema`'s
/// generated public schema.
fn exact<T: Serialize + DeserializeOwned>(path: &str, schema: &str) -> T {
    let v = load(path);
    let typed: T = serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{path}: {e}"));
    assert_eq!(
        serde_json::to_value(&typed).unwrap(),
        v,
        "{path}: exact round trip"
    );
    let doc = public_schemas()
        .into_iter()
        .find(|s| s.name == schema)
        .unwrap_or_else(|| panic!("no public schema {schema}"));
    let doc = serde_json::to_value(&doc.schema).unwrap();
    if let Err(e) = validate(&doc, &v) {
        panic!("{path} against {schema}: {e:?}");
    }
    typed
}

#[test]
fn rev5_examples_round_trip_and_validate() {
    for path in [
        "schemas/examples/request.environment.wsl-enable.json",
        "schemas/examples/request.environment.wsl-disable.json",
        "schemas/examples/request.environment.container-add.json",
        "schemas/examples/request.environment.container-remove.json",
        "schemas/examples/request.catalog.apply-import.json",
        // ⟨rev5.1⟩ ADR-0006 §17.9 (U7, ruling I-6; `dry_run`).
        "schemas/examples/request.catalog.set-default-profile.json",
        "schemas/examples/request.catalog.apply-import.dry-run.json",
        "schemas/examples/request.ensure.context.json",
        "schemas/examples/request.revoke.work.json",
        "schemas/examples/request.policy.pause-target.json",
        "schemas/examples/request.policy.trust-workspace.json",
        "schemas/examples/request.inspect.workspace.json",
    ] {
        let r: Request = exact(path, "request");
        assert!(
            r.required_capability().is_some(),
            "{path}: a revision-5 form needs a capability"
        );
    }
    let envs: EnvironmentsView = exact(
        "schemas/examples/inspect.environments.json",
        "inspect-environments",
    );
    assert_eq!(envs.items.len(), 3);
    let plain: WorkspaceView = exact(
        "schemas/examples/inspect.workspace.json",
        "inspect-workspace",
    );
    assert!(plain.proposal.is_none(), "revision 5: no proposal key");
    // ⟨rev5.2⟩ ADR-0006 §17.10 item 21: the server-built trust proposal.
    let with_proposal: WorkspaceView = exact(
        "schemas/examples/inspect.workspace.proposal.json",
        "inspect-workspace",
    );
    let proposal = with_proposal
        .proposal
        .expect("the example carries a proposal");
    assert_eq!(proposal.profile.as_str(), "homelab-dev");
    assert!(proposal.background_work && proposal.pairs.len() == 1);
    let _: PoliciesView = exact("schemas/examples/inspect.policies.json", "inspect-policies");
    // ⟨rev5.1⟩ The default-profile list is omitted when empty, so the document above is
    // unchanged; with one set it round-trips and validates.
    let with_default: PoliciesView = exact(
        "schemas/examples/inspect.policies.default-profile.json",
        "inspect-policies",
    );
    assert_eq!(with_default.default_profiles.len(), 1);
    // ⟨rev5.1⟩ C2: the typed result of a targeted policy action.
    let target: PolicyTargetResult = exact(
        "schemas/examples/policy-target-result.json",
        "policy-target-result",
    );
    assert_eq!(target.policies.len(), 2);
    // The trusted-work file formats (`schemas/project/`): exact round trips; the
    // manifest's closed schema is checked in `schema_export`.
    let v = load("schemas/examples/project-manifest.json");
    let m: Manifest = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(serde_json::to_value(&m).unwrap(), v);
    assert_eq!(m.preferences.background_work, Some(true));
    let mut unknown = v.clone();
    unknown["trusted"] = Value::Bool(true);
    assert!(
        serde_json::from_value::<Manifest>(unknown).is_err(),
        "closed: an unknown key rejects the file"
    );
    let import = load("schemas/examples/request.catalog.apply-import.json");
    let bundle: PortableBundle = serde_json::from_value(import["bundle"].clone()).unwrap();
    assert_eq!(serde_json::to_value(&bundle).unwrap(), import["bundle"]);
    assert_eq!(
        bundle.schema,
        heimdall_contract::project::PORTABLE_BUNDLE_SCHEMA
    );
}

/// The revision-5 capabilities and what requires them. Whether the runtime offers each is
/// pinned in `heimdall-ipc` (module docs): `trusted-work/1` since M05 W3, `environments/1`
/// not yet.
#[test]
fn rev5_capabilities_declared_not_offered_and_required() {
    assert_eq!(capability::ENVIRONMENTS_V1, "environments/1");
    assert_eq!(capability::TRUSTED_WORK_V1, "trusted-work/1");
    assert_eq!(
        capability::REVISION_5_DECLARED,
        [capability::ENVIRONMENTS_V1, capability::TRUSTED_WORK_V1]
    );
    let need = |path: &str| -> Option<&'static str> {
        let r: Request = serde_json::from_value(load(path)).unwrap();
        r.required_capability()
    };
    for path in [
        "schemas/examples/request.environment.wsl-enable.json",
        "schemas/examples/request.environment.container-remove.json",
    ] {
        assert_eq!(need(path), Some(capability::ENVIRONMENTS_V1), "{path}");
    }
    for path in [
        "schemas/examples/request.catalog.apply-import.json",
        "schemas/examples/request.catalog.apply-import.dry-run.json",
        "schemas/examples/request.catalog.set-default-profile.json",
        "schemas/examples/request.ensure.context.json",
        "schemas/examples/request.revoke.work.json",
        "schemas/examples/request.policy.pause-target.json",
        "schemas/examples/request.policy.trust-workspace.json",
        "schemas/examples/request.inspect.workspace.json",
    ] {
        assert_eq!(need(path), Some(capability::TRUSTED_WORK_V1), "{path}");
    }
    // W0-R04: a revision-5 field on an M01–M03 request needs its track's capability: a
    // route's `jump` and an M04 setup item or distribution `environments/1`, `cwd` or
    // `redact` on any inspect subject `trusted-work/1`; without them, what they needed.
    let edited = |path: &str, edit: fn(&mut Value)| {
        let mut v = load(path);
        edit(&mut v);
        v
    };
    let upsert = "schemas/examples/request.catalog.upsert-destination.json";
    let preview = "schemas/examples/request.setup.preview-apply.json";
    let rollback = "schemas/examples/request.setup.preview-rollback.json";
    let inspect = |extra: Value| {
        let mut v = serde_json::json!({"op": "inspect", "subject": "capabilities"});
        if let Value::Object(m) = extra {
            v.as_object_mut().unwrap().extend(m);
        }
        v
    };
    for (v, expected) in [
        (
            edited(upsert, |v| {
                v["destination"]["definition"]["jump"] = "dest-0".into();
            }),
            Some(capability::ENVIRONMENTS_V1),
        ),
        (
            edited(preview, |v| {
                v["intent"]["items"] = serde_json::json!(["login_entry"]);
            }),
            Some(capability::ENVIRONMENTS_V1),
        ),
        (
            edited(rollback, |v| {
                v["intent"]["distribution"] = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0".into();
            }),
            Some(capability::ENVIRONMENTS_V1),
        ),
        (
            inspect(serde_json::json!({"cwd": "/home/dev/src"})),
            Some(capability::TRUSTED_WORK_V1),
        ),
        (
            inspect(serde_json::json!({"redact": true})),
            Some(capability::TRUSTED_WORK_V1),
        ),
        (load(upsert), Some(capability::SETUP_V1)),
        (load(preview), Some(capability::SETUP_V1)),
        (load(rollback), Some(capability::SETUP_V1)),
        (inspect(Value::Null), None),
    ] {
        let r: Request = serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{v}: {e}"));
        assert_eq!(r.required_capability(), expected, "{v}");
    }
    // The M01–M03 forms still need nothing beyond what they needed.
    for path in [
        "schemas/examples/request.ensure.json",
        "schemas/examples/request.revoke.json",
        "schemas/examples/request.policy-cutoff.json",
    ] {
        assert_eq!(need(path), None, "{path}");
    }
}

#[test]
fn rev5_m01_m03_forms_unchanged() {
    let dir = repo_root().join("schemas/examples");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with("request.") {
            continue;
        }
        let rev5 = name.starts_with("request.environment.")
            || [
                "request.catalog.apply-import.json",
                "request.catalog.apply-import.dry-run.json",
                "request.catalog.set-default-profile.json",
                "request.ensure.context.json",
                "request.revoke.work.json",
                "request.policy.pause-target.json",
                "request.policy.trust-workspace.json",
                "request.inspect.workspace.json",
            ]
            .contains(&name.as_str());
        let v = load(&format!("schemas/examples/{name}"));
        let r: Request =
            serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            v,
            "{name}: byte-identical re-encode"
        );
        if !rev5 {
            let new_capability = matches!(
                r.required_capability(),
                Some(c) if capability::REVISION_5_DECLARED.contains(&c)
            );
            assert!(
                !new_capability,
                "{name}: an M01–M03 form needs a revision-5 capability"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 40,
        "only {checked} pre-revision-5 request examples"
    );
}

/// ⟨rev5.1⟩ ADR-0006 §17.9 (orchestrator ruling I-6, M05 wave 2 U7): `catalog
/// set_default_profile`. Each golden request decodes, re-encodes byte-identically (an
/// absent environment is omitted; `profile` is always written, `null` clearing), validates
/// against the generated public schema, is a journaled `catalog` action, and needs
/// `trusted-work/1`; `inspect policies` carries the preference only when one is set.
#[test]
fn rev5_1_set_default_profile_forms() {
    use heimdall_contract::request::Admission;
    let golden = load("tests/contracts/golden/rev5-1.golden.json");
    assert_eq!(golden["capability"], capability::TRUSTED_WORK_V1);
    let schema = public_schemas()
        .into_iter()
        .find(|s| s.name == "request")
        .unwrap();
    let schema = serde_json::to_value(&schema.schema).unwrap();
    let rows = golden["requests"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        let v = &row["json"];
        let what = row["what"].as_str().unwrap();
        let r: Request =
            serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(
            &serde_json::to_value(&r).unwrap(),
            v,
            "{what}: exact round trip"
        );
        if let Err(e) = validate(&schema, v) {
            panic!("{what} against the request schema: {e:?}");
        }
        let Request::Catalog(c) = &r else {
            panic!("{what}: not a catalog request");
        };
        assert_eq!(c.action(), golden["action"].as_str().unwrap(), "{what}");
        assert_eq!(r.kind(), golden["kind"].as_str().unwrap(), "{what}");
        assert_eq!(r.admission(), Admission::Journaled("catalog"), "{what}");
        assert_eq!(
            r.required_capability(),
            Some(capability::TRUSTED_WORK_V1),
            "{what}"
        );
        assert!(r.is_effectful() && !r.requires_attended_session(), "{what}");
        assert!(
            !r.is_widening_policy_action(),
            "{what}: a preference is not authority"
        );
    }
    // A missing `profile` clears, as `null` does (never a decode error that hides the
    // owner's intent), and the clear is written out explicitly.
    let missing: Request = serde_json::from_value(
        serde_json::json!({"op": "catalog", "action": "set_default_profile", "request_id": "r-5"}),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&missing).unwrap()["profile"],
        Value::Null
    );
    // The view.
    let view = &golden["view"];
    let empty: PoliciesView = serde_json::from_value(view["empty"].clone()).unwrap();
    assert!(empty.default_profiles.is_empty());
    assert_eq!(serde_json::to_value(&empty).unwrap(), view["empty"]);
    let set: PoliciesView = serde_json::from_value(view["set"].clone()).unwrap();
    assert_eq!(serde_json::to_value(&set).unwrap(), view["set"]);
}

/// ⟨rev5.1⟩ ADR-0006 §17.9 items `dry_run`, the closed bundle, C1 and C2, from the golden
/// (transcribed from the contract owner's delta): `dry_run` is omitted when false (an
/// earlier `apply_import` is unchanged) and written when true, and either way needs
/// `trusted-work/1`; an unknown key at any of the four bundle levels makes the request
/// undecodable, and the published `portable` schema is closed at each; the targeted-action
/// result and the decision view's policy list round-trip exactly and the result validates
/// against its published schema.
#[test]
fn rev5_1_dry_run_closed_bundle_and_typed_results() {
    let golden = load("tests/contracts/golden/rev5-1.golden.json");
    let request_schema = {
        let s = public_schemas()
            .into_iter()
            .find(|s| s.name == "request")
            .unwrap();
        serde_json::to_value(&s.schema).unwrap()
    };
    let dry = &golden["dry_run"];
    for row in dry["requests"].as_array().unwrap() {
        let v = &row["json"];
        let what = row["what"].as_str().unwrap();
        let r: Request =
            serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(&serde_json::to_value(&r).unwrap(), v, "{what}: round trip");
        if let Err(e) = validate(&request_schema, v) {
            panic!("{what} against the request schema: {e:?}");
        }
        let Request::Catalog(heimdall_contract::catalog::CatalogRequest::ApplyImport {
            dry_run,
            ..
        }) = &r
        else {
            panic!("{what}: not apply_import");
        };
        assert_eq!(*dry_run, row["dry_run"].as_bool().unwrap(), "{what}");
        assert_eq!(
            v.get("dry_run").is_some(),
            *dry_run,
            "{what}: omitted when false"
        );
        assert_eq!(
            r.required_capability(),
            Some(capability::TRUSTED_WORK_V1),
            "{what}"
        );
    }
    // Closed: a key added at each level of the bundle is refused by the type and the
    // request; the published file schema says so at every level.
    let portable = project_schemas()
        .into_iter()
        .find(|s| s.name == "portable")
        .unwrap();
    let portable = serde_json::to_value(&portable.schema).unwrap();
    let closed = |node: &Value| node["additionalProperties"] == Value::Bool(false);
    assert!(closed(&portable), "PortableBundle");
    for def in ["PortableDestination", "PortableIdentity", "PortableProfile"] {
        assert!(closed(&portable["$defs"][def]), "{def}");
    }
    let mut base = dry["requests"][1]["json"].clone();
    base["bundle"]["identities"] = serde_json::json!([{
        "fingerprint": format!("SHA256:{}", "B".repeat(43)), "provider": "native_agent"
    }]);
    base["bundle"]["profiles"] = serde_json::json!([{"id": "dev", "pairs": ["lab-db:deploy"]}]);
    assert!(
        serde_json::from_value::<Request>(base.clone()).is_ok(),
        "control: every level exists and decodes"
    );
    for row in golden["closed_bundle"]["unknown_keys"].as_array().unwrap() {
        let mut v = base.clone();
        let at = match row["at"].as_str().unwrap() {
            "bundle" => "/bundle",
            "destination" => "/bundle/destinations/0",
            "identity" => "/bundle/identities/0",
            "profile" => "/bundle/profiles/0",
            other => panic!("{other}"),
        };
        v.pointer_mut(at).unwrap()[row["key"].as_str().unwrap()] = row["value"].clone();
        assert!(
            serde_json::from_value::<Request>(v).is_err(),
            "{row}: an unknown key is refused"
        );
    }
    // C2 and C1.
    let target_schema = public_schemas()
        .into_iter()
        .find(|s| s.name == "policy-target-result")
        .unwrap();
    let target_schema = serde_json::to_value(&target_schema.schema).unwrap();
    for row in golden["policy_target_result"]["results"]
        .as_array()
        .unwrap()
    {
        let v = &row["json"];
        let what = row["what"].as_str().unwrap();
        let t: PolicyTargetResult = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(&serde_json::to_value(&t).unwrap(), v, "{what}");
        if let Err(e) = validate(&target_schema, v) {
            panic!("{what}: {e:?}");
        }
    }
    let listed = &golden["decision_policies"]["json"];
    let policies: Vec<PolicyRevisionRef> = serde_json::from_value(listed.clone()).unwrap();
    assert_eq!(&serde_json::to_value(&policies).unwrap(), listed);
}

/// ⟨rev5.2⟩ ADR-0006 §17.10 item 21 (orchestrator ruling I-14, M05 wave 3):
/// `WorkspaceView.proposal`, from the golden (transcribed from the contract owner's delta).
/// Each view round-trips byte-identically and validates against the generated
/// `inspect-workspace` schema; the proposal is written when present and its key is absent
/// otherwise, so every earlier `inspect workspace` document is unchanged; the field is part
/// of the schema, optional, and the same `inspect workspace` needs `trusted-work/1`.
#[test]
fn rev5_2_workspace_proposal() {
    let golden = load("tests/contracts/golden/rev5-2.golden.json");
    assert_eq!(golden["capability"], capability::TRUSTED_WORK_V1);
    let doc = public_schemas()
        .into_iter()
        .find(|s| s.name == golden["subject"].as_str().unwrap())
        .unwrap();
    let doc = serde_json::to_value(&doc.schema).unwrap();
    let rows = golden["views"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        let v = &row["json"];
        let what = row["what"].as_str().unwrap();
        let view: WorkspaceView =
            serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(
            &serde_json::to_value(&view).unwrap(),
            v,
            "{what}: exact round trip"
        );
        if let Err(e) = validate(&doc, v) {
            panic!("{what} against inspect-workspace: {e:?}");
        }
        assert_eq!(
            view.proposal.is_some(),
            row["has_proposal"].as_bool().unwrap(),
            "{what}"
        );
        assert_eq!(
            v.get("proposal").is_some(),
            view.proposal.is_some(),
            "{what}: the key is written exactly when there is a proposal"
        );
    }
    // The field is optional in the schema: a revision-5 document still validates.
    assert!(
        !doc["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k == "proposal"),
        "proposal is not required"
    );
    assert!(doc["properties"].get("proposal").is_some());
    // `inspect workspace` stays gated on `trusted-work/1` (unchanged by this revision).
    let r: Request = exact("schemas/examples/request.inspect.workspace.json", "request");
    assert_eq!(r.required_capability(), Some(capability::TRUSTED_WORK_V1));
}

/// ⟨rev5.2⟩ ADR-0006 §17.10 item 22 (review M05-W3-R01): a pending `create` record's
/// decision view carries `scope`, from the golden (transcribed from the contract owner's
/// ruling). The scope round-trips byte-identically through [`DecisionScope`] with every
/// list written (an empty one included); the key is present exactly for the pinned
/// `create` forms and absent for the other records (an `extend_scope`, a targeted
/// `resume`), so every earlier decision view is unchanged. It is a typed struct inside the
/// untyped decision view: no published schema names it.
#[test]
fn rev5_2_decision_scope() {
    let golden = load("tests/contracts/golden/rev5-2.golden.json");
    let rows = golden["decision_scope"]["views"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let mut kinds = BTreeSet::new();
    for row in rows {
        let v = &row["json"];
        let what = row["what"].as_str().unwrap();
        let has_scope = row["has_scope"].as_bool().unwrap();
        assert_eq!(v.get("scope").is_some(), has_scope, "{what}");
        assert_eq!(v["kind"], "widen_policy", "{what}");
        let action = v["request"]["action"]["action"].as_str().unwrap();
        assert_eq!(
            has_scope,
            action == "create",
            "{what}: only a create has a scope"
        );
        kinds.insert((action.to_owned(), has_scope));
        let Some(scope) = v.get("scope") else {
            continue;
        };
        let typed: DecisionScope =
            serde_json::from_value(scope.clone()).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(
            &serde_json::to_value(&typed).unwrap(),
            scope,
            "{what}: exact round trip"
        );
        for key in [
            "profile_id",
            "profile_revision",
            "pairs",
            "environments",
            "capabilities",
            "lock_behavior",
        ] {
            assert!(scope.get(key).is_some(), "{what}: {key} is always written");
        }
        assert_eq!(
            typed.profile_id.as_str(),
            v["request"]["action"]["profile"].as_str().unwrap(),
            "{what}"
        );
        // A scope missing a list is not read as an empty one.
        let mut partial = scope.clone();
        partial.as_object_mut().unwrap().remove("pairs");
        assert!(
            serde_json::from_value::<DecisionScope>(partial).is_err(),
            "{what}: a missing list is refused"
        );
    }
    assert_eq!(
        kinds,
        [
            ("create".to_owned(), true),
            ("extend_scope".to_owned(), false),
            ("resume".to_owned(), false),
        ]
        .into_iter()
        .collect()
    );
    for schema in public_schemas() {
        let text = serde_json::to_string(&schema.schema).unwrap();
        assert!(
            !text.contains("DecisionScope"),
            "{}: no schema changes for item 22",
            schema.name
        );
    }
}
