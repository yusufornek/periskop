// The event this hook writes is checked against the schema file itself, not
// against a copy of it kept here. A copy would let the hook and the contract
// drift apart quietly, which is the failure this test exists to prevent.

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { buildEgressEvent, type BuildContext, type CallObservation } from "./egress-event";

const SCHEMA_PATH = join(__dirname, "..", "..", "..", "schemas", "egress-event.schema.json");

type Schema = Record<string, unknown>;

/**
 * A validator for the subset of JSON Schema this contract uses.
 *
 * Reaching for ajv would mean a dependency, and the schema uses six keywords.
 */
function validate(schema: Schema, value: unknown, path = "$"): string[] {
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

const SCHEMA = JSON.parse(readFileSync(SCHEMA_PATH, "utf8")) as Schema;

const CONTEXT: BuildContext = {
  runtime: "node/20",
  pid: 4711,
  entrypointHint: "billing-worker",
  bodyParseLimitBytes: 65536,
  epochMillis: 1_764_000_000_000,
};

function observation(overrides: Partial<CallObservation> = {}): CallObservation {
  return {
    module: "node:https",
    method: "POST",
    host: "api.openai.com",
    port: 443,
    path: "/v1/chat/completions",
    body: {
      byteSize: 120,
      streamed: false,
      sample: JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: "hi" }] }),
    },
    callSite: { path: "services/customer.ts", symbol: "summarize" },
    ...overrides,
  };
}

test("a recorded call validates against the egress event schema", () => {
  const event = buildEgressEvent(observation(), CONTEXT);
  assert.deepEqual(validate(SCHEMA, event), []);
  assert.deepEqual(event.payload_shape.field_paths, [
    "messages[].content",
    "messages[].role",
    "model",
  ]);
  assert.equal(event.target.provider_ref, "openai");
  assert.equal(event.operation, "post");
});

test("a call to an unclassified host is recorded, not hidden", () => {
  const event = buildEgressEvent(
    observation({ host: "gateway.internal.corp", port: 8443 }),
    CONTEXT,
  );
  assert.deepEqual(validate(SCHEMA, event), []);
  assert.equal(event.target.host_id, "gateway.internal.corp");
  assert.equal(event.target.provider_ref, "unknown");
});

test("an unresolved destination is declared rather than dropped", () => {
  const event = buildEgressEvent(observation({ host: undefined }), CONTEXT);
  assert.deepEqual(validate(SCHEMA, event), []);
  assert.equal(event.target.host_id, "unknown");
  assert.ok(event.degraded_reasons?.includes("target_not_resolved"));
});

test("a missing call site is declared rather than left to look absent", () => {
  const event = buildEgressEvent(observation({ callSite: undefined }), CONTEXT);
  assert.deepEqual(validate(SCHEMA, event), []);
  assert.equal(event.call_site_hint, undefined);
  assert.ok(event.degraded_reasons?.includes("call_site_unavailable"));
});

test("a streaming body is sized from its header and declared unmeasured", () => {
  const event = buildEgressEvent(
    observation({ body: { byteSize: 900, streamed: true, sample: undefined } }),
    CONTEXT,
  );
  assert.deepEqual(validate(SCHEMA, event), []);
  assert.deepEqual(event.payload_shape.field_paths, []);
  assert.equal(event.payload_shape.byte_size_estimate, 900);
  assert.ok(event.degraded_reasons?.includes("streaming_body_not_measured"));
});

test("the same call in the same second carries one identity", () => {
  const first = buildEgressEvent(observation(), CONTEXT);
  const second = buildEgressEvent(observation(), { ...CONTEXT, epochMillis: CONTEXT.epochMillis + 400 });
  assert.equal(first.egress_event_id, second.egress_event_id);
});

test("the published valid example still passes this validator", () => {
  // Guards the validator itself: if it stops rejecting things, this example
  // passing means nothing.
  const example = JSON.parse(
    readFileSync(
      join(__dirname, "..", "..", "..", "schemas", "examples", "egress-event.valid.json"),
      "utf8",
    ),
  ) as unknown;
  assert.deepEqual(validate(SCHEMA, example), []);

  const invalid = JSON.parse(
    readFileSync(
      join(__dirname, "..", "..", "..", "schemas", "examples", "egress-event.invalid.json"),
      "utf8",
    ),
  ) as unknown;
  assert.notDeepEqual(validate(SCHEMA, invalid), []);
});
