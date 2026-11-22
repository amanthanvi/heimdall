#!/usr/bin/env python3
"""Check the reference configuration and the example manifest against the published
schemas (m08-plan U7a).

Usage: python3 -I examples/reference-config/check.py [--self-test]
Exit code: 0 when both files validate and config.toml states every default the schema
declares; 1 otherwise; 2 on a setup error. Python 3.11+ (tomllib), standard library only.

The validator covers the JSON Schema subset these two schemas use: type (also a list),
properties, required, additionalProperties, enum, minimum, maximum, items, $ref into $defs,
anyOf and oneOf. An unsupported keyword that could reject a value is a setup error, so the
check cannot pass by ignoring a rule.
"""
import json
import os
import sys

try:
    import tomllib
except ImportError:
    sys.stderr.write("check: Python 3.11+ is required\n")
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
KNOWN = {"$schema", "title", "description", "type", "properties", "required", "additionalProperties", "enum",
         "minimum", "maximum", "items", "$ref", "$defs", "anyOf", "oneOf", "default", "format", "const",
         "maxLength", "minLength", "maxItems", "minItems", "pattern", "uniqueItems", "examples"}
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


class Unsupported(Exception):
    pass


def validate(value, schema, root, path="$"):
    errs = []
    if not isinstance(schema, dict):
        return errs
    extra = set(schema) - KNOWN
    if extra:
        raise Unsupported(f"{path}: schema keyword(s) not supported by this check: {sorted(extra)}")
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise Unsupported(f"{path}: $ref {ref}")
        errs += validate(value, root["$defs"][ref[len("#/$defs/"):]], root, path)
    for key in ("anyOf", "oneOf"):
        if key in schema:
            hits = sum(1 for s in schema[key] if not validate(value, s, root, path))
            if hits == 0 or (key == "oneOf" and hits != 1):
                errs.append(f"{path}: matches {hits} of {key}")
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]

        def is_type(t):
            if t == "integer":
                return isinstance(value, int) and not isinstance(value, bool)
            if t == "number":
                return isinstance(value, (int, float)) and not isinstance(value, bool)
            return isinstance(value, TYPES[t])
        if not any(is_type(t) for t in types):
            return errs + [f"{path}: expected {'/'.join(types)}"]
    if "const" in schema and value != schema["const"]:
        errs.append(f"{path}: not the required value")
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: not one of {schema['enum']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errs.append(f"{path}: below {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errs.append(f"{path}: above {schema['maximum']}")
    if isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errs.append(f"{path}: longer than {schema['maxLength']}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema:
            import re
            if not re.search(schema["pattern"], value):
                errs.append(f"{path}: does not match the pattern")
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errs.append(f"{path}: more than {schema['maxItems']} items")
        if "minItems" in schema and len(value) < schema["minItems"]:
            errs.append(f"{path}: fewer than {schema['minItems']} items")
        for i, v in enumerate(value):
            errs += validate(v, schema.get("items", {}), root, f"{path}[{i}]")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for r in schema.get("required", []):
            if r not in value:
                errs.append(f"{path}: missing {r}")
        for k, v in value.items():
            if k in props:
                errs += validate(v, props[k], root, f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                errs.append(f"{path}: unknown key {k}")
            elif isinstance(schema.get("additionalProperties"), dict):
                errs += validate(v, schema["additionalProperties"], root, f"{path}.{k}")
    return errs


def defaults_stated(doc, schema):
    """Every top-level default the schema declares must be stated, with that value."""
    errs = []
    for key, prop in schema.get("properties", {}).items():
        if "default" not in prop:
            continue
        if key not in doc:
            errs.append(f"config.toml does not state [{key}]")
            continue
        for k, v in prop["default"].items() if isinstance(prop["default"], dict) else []:
            if doc[key].get(k) != v:
                errs.append(f"config.toml [{key}] {k} is not the schema default {v!r}")
    return errs


def self_test():
    root = {"$defs": {"E": {"type": "string", "enum": ["a", "b"]}},
            "type": "object", "required": ["n"], "additionalProperties": False,
            "properties": {"n": {"type": "integer", "minimum": 1, "maximum": 9}, "e": {"$ref": "#/$defs/E"},
                           "l": {"type": "array", "items": {"type": "string"}}, "o": {"type": ["string", "null"]}}}
    cases = [("good", {"n": 3, "e": "a", "l": ["x"], "o": None}, 0), ("missing required", {"e": "a"}, 1),
             ("unknown key", {"n": 1, "zz": 1}, 1), ("wrong enum", {"n": 1, "e": "c"}, 1),
             ("out of range", {"n": 10}, 1), ("wrong item type", {"n": 1, "l": [1]}, 1),
             ("a boolean is not an integer", {"n": True}, 1)]
    bad = 0
    for name, value, want in cases:
        if bool(validate(value, root, root)) != bool(want):
            bad += 1
            print(f"self-test FAILED: {name}")
    try:
        validate({}, {"type": "object", "dependentRequired": {}}, {})
        bad += 1
        print("self-test FAILED: an unsupported keyword was ignored")
    except Unsupported:
        pass
    print(f"reference-config check self-test: {len(cases) + 1} cases, {bad} failed")
    return 1 if bad else 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    bad = 0
    for toml_name, schema_rel in (("config.toml", "schemas/configuration/config.schema.json"),
                                  ("heimdall.toml", "schemas/project/manifest.schema.json")):
        try:
            with open(os.path.join(HERE, toml_name), "rb") as fh:
                doc = tomllib.load(fh)
            with open(os.path.join(REPO, schema_rel), encoding="utf-8") as fh:
                schema = json.load(fh)
            errs = validate(doc, schema, schema)
            if toml_name == "config.toml":
                errs += defaults_stated(doc, schema)
        except (OSError, ValueError) as e:
            print(f"check: cannot read {toml_name} or its schema: {type(e).__name__}")
            return 2
        except Unsupported as e:
            print(f"check: {e}")
            return 2
        for e in errs:
            bad += 1
            print(f"FAIL {toml_name}: {e}")
    print(f"reference-config check: {'PASS' if not bad else 'FAIL'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
