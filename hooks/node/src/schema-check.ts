// A validator for the subset of JSON Schema the event contract uses.
//
// Test utility, and the counterpart of hooks/python/tests/schema_check.py. It
// lives beside the sources because this package keeps its tests there too, and
// it is shared rather than copied so that the in-process check and the child
// process check are provably the same check.
//
// Reaching for ajv would mean a dependency, and the schema uses six keywords:
// type, required, properties, additionalProperties, enum, pattern, items,
// minimum and maximum. It is trusted only because the suite makes it prove
// itself: it has to accept the repository's valid example and reject the
// invalid one.

export type Schema = Record<string, unknown>;

/** Returns a list of error strings. Empty means the instance conforms. */
export function validate(schema: Schema, value: unknown, path = "$"): string[] {
  const errors: string[] = [];

  const enumeration = schema["enum"] as unknown[] | undefined;
  if (enumeration !== undefined && !enumeration.includes(value)) {
    errors.push(`${path}: ${String(value)} is not one of ${enumeration.join(", ")}`);
  }

  const type = schema["type"] as string | undefined;
  if (type === "object") {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return [`${path}: expected object`];
    }
    const record = value as Record<string, unknown>;
    const properties = (schema["properties"] ?? {}) as Record<string, Schema>;

    for (const key of (schema["required"] ?? []) as string[]) {
      if (!(key in record)) errors.push(`${path}.${key}: required`);
    }
    if (schema["additionalProperties"] === false) {
      for (const key of Object.keys(record)) {
        if (!(key in properties)) errors.push(`${path}.${key}: not allowed by the schema`);
      }
    }
    for (const [key, subSchema] of Object.entries(properties)) {
      if (key in record) errors.push(...validate(subSchema, record[key], `${path}.${key}`));
    }
    return errors;
  }

  if (type === "array") {
    if (!Array.isArray(value)) return [`${path}: expected array`];
    const items = schema["items"] as Schema | undefined;
    if (items !== undefined) {
      value.forEach((item, index) => errors.push(...validate(items, item, `${path}[${index}]`)));
    }
    return errors;
  }

  if (type === "string") {
    if (typeof value !== "string") return [`${path}: expected string`];
    const pattern = schema["pattern"] as string | undefined;
    if (pattern !== undefined && !new RegExp(pattern).test(value)) {
      errors.push(`${path}: ${value} does not match ${pattern}`);
    }
    return errors;
  }

  if (type === "integer") {
    if (!Number.isInteger(value)) return [`${path}: expected integer`];
    const minimum = schema["minimum"] as number | undefined;
    const maximum = schema["maximum"] as number | undefined;
    if (minimum !== undefined && (value as number) < minimum) errors.push(`${path}: below minimum`);
    if (maximum !== undefined && (value as number) > maximum) errors.push(`${path}: above maximum`);
  }

  return errors;
}
