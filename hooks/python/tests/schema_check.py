"""A small JSON Schema checker, limited to the keywords the event schema uses.

The hook may not depend on anything outside the standard library, and neither
may its tests. This covers `type`, `required`, `properties`,
`additionalProperties: false`, `enum`, `pattern`, `items`, `minimum` and
`maximum`, which is every keyword in egress-event.schema.json.

It is trusted only because the suite makes it prove itself: it has to accept the
repository's valid example and reject the invalid one for the documented reason
(schemas/examples/invalid-expectations.json).
"""

import re

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _type_matches(value, name):
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    expected = _TYPES.get(name)
    if expected is None:
        return True
    if expected is not bool and isinstance(value, bool):
        return False
    return isinstance(value, expected)


def validate(instance, schema, path=""):
    """Return a list of error strings. Empty means the instance conforms."""
    errors = []
    declared = schema.get("type")
    if declared is not None:
        names = declared if isinstance(declared, list) else [declared]
        if not any(_type_matches(instance, name) for name in names):
            errors.append("{0}: expected type {1}".format(path or "/", declared))
            return errors

    if "enum" in schema and instance not in schema["enum"]:
        errors.append("{0}: {1!r} is not one of {2}".format(
            path or "/", instance, schema["enum"]))

    if "pattern" in schema and isinstance(instance, str):
        if re.search(schema["pattern"], instance) is None:
            errors.append("{0}: {1!r} does not match {2}".format(
                path or "/", instance, schema["pattern"]))

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append("{0}: below minimum".format(path or "/"))
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append("{0}: above maximum".format(path or "/"))

    if isinstance(instance, dict):
        errors.extend(_validate_object(instance, schema, path))
    elif isinstance(instance, list) and "items" in schema:
        for index, item in enumerate(instance):
            errors.extend(
                validate(item, schema["items"], "{0}/{1}".format(path, index))
            )
    return errors


def _validate_object(instance, schema, path):
    errors = []
    properties = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in instance:
            errors.append("{0}/{1}: required property missing".format(path, name))
    for name, value in instance.items():
        child = "{0}/{1}".format(path, name)
        if name in properties:
            errors.extend(validate(value, properties[name], child))
        elif schema.get("additionalProperties") is False:
            errors.append("{0}: property not allowed".format(child))
    return errors
