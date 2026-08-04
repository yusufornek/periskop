// The identity every hook has to agree on, pinned to fixed expected values.
//
// CROSS_LANGUAGE_VECTORS below is duplicated verbatim in
// hooks/python/tests/test_event_id.py. The duplication is the point: two hooks
// that derive an identity differently give one call two identities and defeat
// deduplication, and the only way to prove they do not is for both suites to
// hardcode the same expected strings and both compute them. If either hook
// drifts, one of the two suites goes red rather than reconciliation quietly
// double counting.
//
// The first vector is the contract example, schemas/examples/egress-event.valid.json.

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { egressEventId, type CallShape } from "./event-id";

/** module, operation, host_id, path_template, expected identity. */
const CROSS_LANGUAGE_VECTORS: ReadonlyArray<
  readonly [string, string, string, string, string]
> = [
  [
    "openai",
    "chat.completions.create",
    "api.openai.com",
    "/v1/chat/completions",
    "ee_3dfe316616cd47b4",
  ],
  ["anthropic", "messages.create", "api.anthropic.com", "/v1/messages", "ee_e8f55ce3debd7846"],
  ["node:https", "post", "api.openai.com", "/v1/embeddings", "ee_2918520a58b33a3c"],
  ["httpx", "http.post", "api.cohere.com", "", "ee_c896832e544738fd"],
  ["requests", "http.get", "unknown", "", "ee_be40919f69bdf6d4"],
];

const BASE: CallShape = {
  module: "openai",
  operation: "chat.completions.create",
  hostId: "api.openai.com",
  pathTemplate: "/v1/chat/completions",
};

function shapeOf(vector: readonly [string, string, string, string, string]): CallShape {
  return { module: vector[0], operation: vector[1], hostId: vector[2], pathTemplate: vector[3] };
}

test("the pinned cross language vectors are reproduced", () => {
  for (const vector of CROSS_LANGUAGE_VECTORS) {
    assert.equal(egressEventId(shapeOf(vector)), vector[4], `${vector[0]} ${vector[1]}`);
  }
});

test("the contract example identity is reproduced", () => {
  // The one identity that is already published. A derivation that cannot
  // reproduce it is a derivation the rest of the project does not share.
  const example = JSON.parse(
    readFileSync(
      join(__dirname, "..", "..", "..", "schemas", "examples", "egress-event.valid.json"),
      "utf8",
    ),
  ) as {
    egress_event_id: string;
    library: { module: string };
    operation: string;
    target: { host_id: string; path_template: string };
  };

  assert.equal(
    egressEventId({
      module: example.library.module,
      operation: example.operation,
      hostId: example.target.host_id,
      pathTemplate: example.target.path_template,
    }),
    example.egress_event_id,
  );
});

test("the identity has the prefix and the width the contract fixes", () => {
  for (const vector of CROSS_LANGUAGE_VECTORS) {
    assert.match(egressEventId(shapeOf(vector)), /^ee_[0-9a-f]{16}$/);
  }
});

test("the same call yields the same identity", () => {
  assert.equal(egressEventId(BASE), egressEventId({ ...BASE }));
});

test("an absent path template hashes as the empty string", () => {
  // The schema makes path_template optional, so a hook that could not read one
  // has to agree with a hook that read an empty one.
  assert.equal(
    egressEventId({ ...BASE, pathTemplate: undefined }),
    egressEventId({ ...BASE, pathTemplate: "" }),
  );
});

test("every named field changes the identity", () => {
  const changed: CallShape[] = [
    { ...BASE, module: "anthropic" },
    { ...BASE, operation: "embeddings.create" },
    { ...BASE, hostId: "api.anthropic.com" },
    { ...BASE, pathTemplate: "/v1/embeddings" },
  ];
  for (const candidate of changed) {
    assert.notEqual(egressEventId(BASE), egressEventId(candidate), JSON.stringify(candidate));
  }
});

test("the separator keeps field boundaries unambiguous", () => {
  // Without a separator these two would serialise to the same bytes.
  assert.notEqual(
    egressEventId({ module: "open", operation: "ai.create", hostId: "host", pathTemplate: "/p" }),
    egressEventId({ module: "openai", operation: ".create", hostId: "host", pathTemplate: "/p" }),
  );
});
