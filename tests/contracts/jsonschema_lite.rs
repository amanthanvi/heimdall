//! A small JSON Schema (draft 2020-12 subset) validator.
//!
//! No schema-validation crate is pinned in the workspace, so this covers exactly the
//! keywords `schemars` emits for the public contract. An unsupported keyword is a
//! test failure (never silently ignored), so a schema change that introduces new
//! constraints cannot weaken the example checks unnoticed.

use serde_json::Value;

/// Keywords that carry no validation semantics.
const ANNOTATIONS: &[&str] = &[
    "$schema",
    "$defs",
    "title",
    "description",
    "default",
    "format",
    "examples",
    "deprecated",
];

/// Validate `instance` against `root` (the whole schema document).
pub(crate) fn validate(root: &Value, instance: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    check(root, root, instance, "$", &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn type_matches(name: &str, v: &Value) -> bool {
    match name {
        "null" => v.is_null(),
        "boolean" => v.is_boolean(),
        "string" => v.is_string(),
        "array" => v.is_array(),
        "object" => v.is_object(),
        "number" => v.is_number(),
        "integer" => v.is_i64() || v.is_u64(),
        _ => false,
    }
}

fn resolve<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let pointer = reference.strip_prefix('#')?;
    root.pointer(pointer)
}

fn check(root: &Value, schema: &Value, inst: &Value, path: &str, errors: &mut Vec<String>) {
    let obj = match schema {
        Value::Bool(true) => return,
        Value::Bool(false) => {
            errors.push(format!("{path}: schema `false` rejects everything"));
            return;
        }
        Value::Object(map) => map,
        other => {
            errors.push(format!("{path}: schema is not an object: {other}"));
            return;
        }
    };
    for (key, value) in obj {
        match key.as_str() {
            k if ANNOTATIONS.contains(&k) => {}
            "$ref" => match value.as_str().and_then(|r| resolve(root, r)) {
                Some(target) => check(root, target, inst, path, errors),
                None => errors.push(format!("{path}: unresolvable $ref {value}")),
            },
            "type" => {
                let ok = match value {
                    Value::String(t) => type_matches(t, inst),
                    Value::Array(ts) => ts
                        .iter()
                        .any(|t| t.as_str().is_some_and(|t| type_matches(t, inst))),
                    _ => false,
                };
                if !ok {
                    errors.push(format!("{path}: expected type {value}, got {inst}"));
                }
            }
            "const" => {
                if inst != value {
                    errors.push(format!("{path}: expected const {value}, got {inst}"));
                }
            }
            "enum" => {
                let ok = value.as_array().is_some_and(|vs| vs.contains(inst));
                if !ok {
                    errors.push(format!("{path}: {inst} not in enum"));
                }
            }
            "minimum" | "maximum" => {
                if let (Some(bound), Some(n)) = (value.as_f64(), inst.as_f64()) {
                    let bad = if key == "minimum" {
                        n < bound
                    } else {
                        n > bound
                    };
                    if bad {
                        errors.push(format!("{path}: {n} violates {key} {bound}"));
                    }
                }
            }
            "properties" => {
                if let (Some(props), Some(map)) = (value.as_object(), inst.as_object()) {
                    for (name, sub) in props {
                        if let Some(child) = map.get(name) {
                            check(root, sub, child, &format!("{path}.{name}"), errors);
                        }
                    }
                }
            }
            "required" => {
                if let (Some(names), Some(map)) = (value.as_array(), inst.as_object()) {
                    for name in names.iter().filter_map(Value::as_str) {
                        if !map.contains_key(name) {
                            errors.push(format!("{path}: missing required `{name}`"));
                        }
                    }
                }
            }
            "additionalProperties" => {
                // The public schemas tolerate unknown fields; a restriction here
                // would contradict ADR-0006 section 9, so surface it.
                errors.push(format!(
                    "{path}: additionalProperties {value} contradicts unknown-field tolerance"
                ));
            }
            "items" => {
                if let Some(items) = inst.as_array() {
                    let skip = obj
                        .get("prefixItems")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len);
                    for (i, item) in items.iter().enumerate().skip(skip) {
                        check(root, value, item, &format!("{path}[{i}]"), errors);
                    }
                }
            }
            "prefixItems" => {
                if let (Some(subs), Some(items)) = (value.as_array(), inst.as_array()) {
                    for (i, (sub, item)) in subs.iter().zip(items).enumerate() {
                        check(root, sub, item, &format!("{path}[{i}]"), errors);
                    }
                }
            }
            "minItems" | "maxItems" => {
                if let (Some(bound), Some(items)) = (value.as_u64(), inst.as_array()) {
                    let len = items.len() as u64;
                    let bad = if key == "minItems" {
                        len < bound
                    } else {
                        len > bound
                    };
                    if bad {
                        errors.push(format!("{path}: {len} items violates {key} {bound}"));
                    }
                }
            }
            "uniqueItems" => {
                if value == &Value::Bool(true)
                    && let Some(items) = inst.as_array()
                {
                    for (i, a) in items.iter().enumerate() {
                        if items.iter().skip(i + 1).any(|b| a == b) {
                            errors.push(format!("{path}: duplicate items"));
                            break;
                        }
                    }
                }
            }
            "anyOf" | "oneOf" | "allOf" => {
                let subs = value.as_array().map_or(&[][..], Vec::as_slice);
                let matching = subs
                    .iter()
                    .filter(|sub| {
                        let mut scratch = Vec::new();
                        check(root, sub, inst, path, &mut scratch);
                        scratch.is_empty()
                    })
                    .count();
                let ok = match key.as_str() {
                    "anyOf" => matching >= 1,
                    "oneOf" => matching == 1,
                    _ => matching == subs.len(),
                };
                if !ok {
                    errors.push(format!(
                        "{path}: {key} matched {matching} of {} alternatives for {inst}",
                        subs.len()
                    ));
                }
            }
            other => errors.push(format!("{path}: unsupported schema keyword `{other}`")),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::validate;

    #[test]
    fn accepts_and_rejects_basic_shapes() {
        let schema = json!({
            "type": "object",
            "properties": {
                "n": {"type": "integer", "minimum": 0},
                "k": {"oneOf": [{"type": "string", "const": "a"}, {"type": "string", "const": "b"}]},
                "xs": {"type": "array", "items": {"$ref": "#/$defs/S"}},
                "t": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "string"}],
                       "minItems": 2, "maxItems": 2},
                "o": {"anyOf": [{"type": "string"}, {"type": "null"}]}
            },
            "required": ["n"],
            "$defs": {"S": {"type": "string"}}
        });
        let good = json!({"n": 1, "k": "a", "xs": ["x"], "t": ["a", "b"], "o": null, "extra": 1});
        assert!(validate(&schema, &good).is_ok());
        for bad in [
            json!({}),
            json!({"n": -1}),
            json!({"n": 1.5}),
            json!({"n": 1, "k": "c"}),
            json!({"n": 1, "xs": [1]}),
            json!({"n": 1, "t": ["a"]}),
            json!({"n": 1, "o": 3}),
        ] {
            assert!(validate(&schema, &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn one_of_requires_exactly_one_match() {
        let schema = json!({"oneOf": [{"type": "integer"}, {"type": "number"}]});
        assert!(validate(&schema, &json!(1)).is_err(), "matches both");
        assert!(validate(&schema, &json!(1.5)).is_ok());
    }

    #[test]
    fn unsupported_keywords_fail_loudly() {
        let schema = json!({"type": "string", "pattern": "^a$"});
        let errs = validate(&schema, &json!("a")).unwrap_err();
        assert!(errs[0].contains("unsupported schema keyword"));
    }

    #[test]
    fn unique_items_detects_duplicates() {
        let schema = json!({"type": "array", "uniqueItems": true});
        assert!(validate(&schema, &json!([1, 2])).is_ok());
        assert!(validate(&schema, &json!([1, 1])).is_err());
    }
}
