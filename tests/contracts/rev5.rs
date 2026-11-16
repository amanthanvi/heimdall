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
//!   forms still require nothing new;
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
use heimdall_contract::schema::public_schemas;
use heimdall_contract::trust::{PoliciesView, WorkspaceView};

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
    assert_eq!(Code::all().len(), 30, "the code table is unchanged");
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
    let _: WorkspaceView = exact(
        "schemas/examples/inspect.workspace.json",
        "inspect-workspace",
    );
    let _: PoliciesView = exact("schemas/examples/inspect.policies.json", "inspect-policies");
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
        "schemas/examples/request.ensure.context.json",
        "schemas/examples/request.revoke.work.json",
        "schemas/examples/request.policy.pause-target.json",
        "schemas/examples/request.policy.trust-workspace.json",
        "schemas/examples/request.inspect.workspace.json",
    ] {
        assert_eq!(need(path), Some(capability::TRUSTED_WORK_V1), "{path}");
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
