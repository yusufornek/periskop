// The event this hook writes is checked against the schema file itself, not
// against a copy of it kept here. A copy would let the hook and the contract
// drift apart quietly, which is the failure this test exists to prevent.

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { buildEgressEvent, type BuildContext, type CallObservation } from "./egress-event";
import { validate, type Schema } from "./schema-check";

const SCHEMA_PATH = join(__dirname, "..", "..", "..", "schemas", "egress-event.schema.json");

const SCHEMA = JSON.parse(readFileSync(SCHEMA_PATH, "utf8")) as Schema;

const CONTEXT: BuildContext = {
  runtime: "node/20",
  entrypointHint: "billing-worker",
  bodyParseLimitBytes: 65536,
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

test("the same call carries one identity, whenever and wherever it happened", () => {
  // Two workers, a day apart, sending a bigger payload from another call site.
  // It is still the same call, and the report has to say so once.
  const first = buildEgressEvent(observation(), CONTEXT);
  const second = buildEgressEvent(
    observation({
      body: { byteSize: 900_000, streamed: false, sample: JSON.stringify({ model: "gpt-4" }) },
      callSite: undefined,
      port: 8443,
    }),
    { ...CONTEXT, entrypointHint: "nightly-batch", runtime: "node/24" },
  );
  assert.equal(first.egress_event_id, second.egress_event_id);
});

test("the identity a real observation produces is the one the contract publishes", () => {
  // The published example is an openai sdk_wrapper record; this hook sits on the
  // transport and reports module node:https. Same four inputs, same identity, so
  // the derivation here is provably the contract's and not a lookalike.
  const event = buildEgressEvent(
    observation({ module: "openai", method: "chat.completions.create" }),
    CONTEXT,
  );
  assert.equal(event.egress_event_id, "ee_3dfe316616cd47b4");
});

test("a different destination or operation is a different call", () => {
  const base = buildEgressEvent(observation(), CONTEXT).egress_event_id;
  assert.notEqual(
    base,
    buildEgressEvent(observation({ host: "api.anthropic.com" }), CONTEXT).egress_event_id,
  );
  assert.notEqual(
    base,
    buildEgressEvent(observation({ method: "GET" }), CONTEXT).egress_event_id,
  );
  assert.notEqual(
    base,
    buildEgressEvent(observation({ path: "/v1/embeddings" }), CONTEXT).egress_event_id,
  );
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
