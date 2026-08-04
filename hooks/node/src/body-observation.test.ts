import assert from "node:assert/strict";
import test from "node:test";

import { describeBody, EMPTY_BODY } from "./body-observation";

const LIMIT = 1024;

test("a body that arrived whole is described by its shape", () => {
  const sample = JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: "hi" }] });
  const described = describeBody(
    { byteSize: Buffer.byteLength(sample), streamed: false, sample },
    LIMIT,
  );
  assert.deepEqual(described.shape.field_paths, ["messages[].content", "messages[].role", "model"]);
  assert.equal(described.shape.byte_size_estimate, Buffer.byteLength(sample));
  assert.deepEqual(described.degraded, []);
});

test("a streaming body is sized but never read", () => {
  // The whole reason byte_size_estimate is an estimate: reading a stream to
  // measure it takes the bytes away from the socket.
  const described = describeBody({ byteSize: 4096, streamed: true, sample: undefined }, LIMIT);
  assert.deepEqual(described.shape.field_paths, []);
  assert.equal(described.shape.byte_size_estimate, 4096);
  assert.deepEqual(described.degraded, ["streaming_body_not_measured"]);
});

test("a body written in pieces is counted and not put back together", () => {
  const described = describeBody({ byteSize: 900, streamed: false, sample: undefined }, LIMIT);
  assert.deepEqual(described.shape.field_paths, []);
  assert.equal(described.shape.byte_size_estimate, 900);
  assert.equal(described.shape.truncated_depth, 0);
  assert.deepEqual(described.degraded, ["payload_traversal_truncated"]);
});

test("a body past the parse limit is declared thin rather than reported as small", () => {
  const sample = JSON.stringify({ model: "x" });
  const described = describeBody({ byteSize: LIMIT + 1, streamed: false, sample }, LIMIT);
  assert.deepEqual(described.shape.field_paths, []);
  assert.deepEqual(described.degraded, ["payload_traversal_truncated"]);
});

test("a body that is not JSON reports no fields and says why", () => {
  const described = describeBody(
    { byteSize: 11, streamed: false, sample: "name=ahmet" },
    LIMIT,
  );
  assert.deepEqual(described.shape.field_paths, []);
  assert.deepEqual(described.degraded, ["payload_traversal_truncated"]);
});

test("no body at all is a fact, not a gap", () => {
  const described = describeBody(EMPTY_BODY, LIMIT);
  assert.deepEqual(described.shape.field_paths, []);
  assert.equal(described.shape.byte_size_estimate, 0);
  assert.deepEqual(described.degraded, []);
  assert.equal(described.shape.truncated_depth, undefined);
});

test("a byte buffer body is decoded for its shape and dropped after", () => {
  const sample = Buffer.from(JSON.stringify({ model: "gpt-4" }), "utf8");
  const described = describeBody(
    { byteSize: sample.byteLength, streamed: false, sample },
    LIMIT,
  );
  assert.deepEqual(described.shape.field_paths, ["model"]);
});

test("a deep body carries its truncation depth into the event", () => {
  const sample = JSON.stringify({
    messages: { content: { text: { data: { parts: { items: { name: 1 } } } } } },
  });
  const described = describeBody(
    { byteSize: Buffer.byteLength(sample), streamed: false, sample },
    LIMIT,
  );
  assert.equal(described.shape.truncated_depth, 7);
  assert.deepEqual(described.degraded, ["payload_traversal_truncated"]);
});
