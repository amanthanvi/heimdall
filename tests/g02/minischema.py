"""Tiny JSON Schema (2020-12 subset) validator, Python stdlib only.

Supports exactly the keywords used by schemas/g02/result.schema.json and
tests/evidence/record.schema.json.  Any other validation keyword raises
SchemaUnsupported (fail closed) so a schema change can never be silently
under-validated.
"""
import re

ANNOTATIONS = {"$schema", "$id", "title", "description", "$defs", "default", "examples", "$comment"}
SUPPORTED = {
    "type", "const", "enum", "required", "properties", "additionalProperties",
    "items", "minLength", "minimum", "maximum", "pattern", "allOf", "if", "then",
    "$ref",
}


class SchemaUnsupported(Exception):
    pass


def _type_ok(value, t):
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "null":
        return value is None
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise SchemaUnsupported("type %r" % (t,))


def _equal(a, b):
    # JSON equality: True != 1
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


def _resolve(root, ref):
    if not ref.startswith("#/"):
        raise SchemaUnsupported("$ref %r" % ref)
    node = root
    for part in ref[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def _check(root, schema, value, path, errors):
    if schema is True:
        return
    if schema is False:
        errors.append("%s: schema is false" % path)
        return
    for key in schema:
        if key not in SUPPORTED and key not in ANNOTATIONS:
            raise SchemaUnsupported("keyword %r at %s" % (key, path))
    if "$ref" in schema:
        _check(root, _resolve(root, schema["$ref"]), value, path, errors)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(value, t) for t in types):
            errors.append("%s: expected type %s, got %s" % (path, "|".join(types), type(value).__name__))
            return
    if "const" in schema and not _equal(value, schema["const"]):
        errors.append("%s: expected const %r" % (path, schema["const"]))
    if "enum" in schema and not any(_equal(value, e) for e in schema["enum"]):
        errors.append("%s: value not in enum %r" % (path, schema["enum"]))
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append("%s: shorter than minLength %d" % (path, schema["minLength"]))
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append("%s: does not match pattern %s" % (path, schema["pattern"]))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append("%s: below minimum %r" % (path, schema["minimum"]))
        if "maximum" in schema and value > schema["maximum"]:
            errors.append("%s: above maximum %r" % (path, schema["maximum"]))
    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                errors.append("%s: missing required property %r" % (path, req))
        props = schema.get("properties", {})
        for k, sub in props.items():
            if k in value:
                _check(root, sub, value[k], "%s.%s" % (path, k), errors)
        if schema.get("additionalProperties") is False:
            for k in value:
                if k not in props:
                    errors.append("%s: additional property %r not allowed" % (path, k))
        elif isinstance(schema.get("additionalProperties"), dict):
            for k in value:
                if k not in props:
                    _check(root, schema["additionalProperties"], value[k], "%s.%s" % (path, k), errors)
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            _check(root, schema["items"], item, "%s[%d]" % (path, i), errors)
    for sub in schema.get("allOf", []):
        _check(root, sub, value, path, errors)
    if "if" in schema:
        probe = []
        _check(root, schema["if"], value, path, probe)
        if not probe and "then" in schema:
            _check(root, schema["then"], value, path, errors)


def validate(schema, value):
    """Return a list of error strings (empty list means valid)."""
    errors = []
    _check(schema, schema, value, "$", errors)
    return errors


def _selftest():
    s = {"type": "object", "required": ["a"], "additionalProperties": False,
         "properties": {"a": {"type": ["integer", "null"], "minimum": 1},
                        "b": {"enum": ["x", "y"]}, "c": {"const": "1"},
                        "d": {"type": "string", "pattern": "^SHA256:[A-Za-z0-9+/]{43}$"}}}
    assert validate(s, {"a": 1, "b": "x", "c": "1"}) == []
    assert validate(s, {"a": None}) == []
    assert validate(s, {"a": True}), "bool is not integer"
    assert validate(s, {"a": 0}), "minimum"
    assert validate(s, {}), "required"
    assert validate(s, {"a": 1, "z": 1}), "additionalProperties"
    assert validate(s, {"a": 1, "b": "q"}), "enum"
    assert validate(s, {"a": 1, "c": 1}), "const type"
    assert validate(s, {"a": 1, "d": "SHA256:abc"}), "pattern"
    cond = {"allOf": [{"if": {"properties": {"k": {"const": 1}}}, "then": {"required": ["m"]}}]}
    assert validate(cond, {"k": 1}), "then applies"
    assert validate(cond, {"k": 1, "m": 0}) == []
    assert validate(cond, {"k": 2}) == []
    try:
        validate({"oneOf": []}, 1)
    except SchemaUnsupported:
        pass
    else:
        raise AssertionError("unsupported keyword must raise")
    ref = {"$defs": {"n": {"type": "integer"}}, "properties": {"x": {"$ref": "#/$defs/n"}}}
    assert validate(ref, {"x": 1}) == [] and validate(ref, {"x": "s"})


if __name__ == "__main__":
    _selftest()
    print("minischema selftest ok")
