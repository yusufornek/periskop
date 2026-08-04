import assert from "node:assert/strict";
import test from "node:test";

import { egressEventId, processIdentity, targetCanonical } from "./event-id";

const BASE = {
  processIdentity: processIdentity("node/20", 4711),
  targetCanonical: targetCanonical("api.openai.com", 443, "/v1/chat/completions"),
  callShapeHash: undefined,
  epochMillis: 1_764_000_000_000,
};

test("the identity has the prefix and the width the contract fixes", () => {
  assert.match(egressEventId(BASE), /^ee_[0-9a-f]{16}$/);
});

test("the same call yields the same identity", () => {
  assert.equal(egressEventId(BASE), egressEventId({ ...BASE }));
});

test("two calls inside one bucket share an identity, so a repeat is not a second call", () => {
  assert.equal(egressEventId(BASE), egressEventId({ ...BASE, epochMillis: BASE.epochMillis + 999 }));
  assert.notEqual(
    egressEventId(BASE),
    egressEventId({ ...BASE, epochMillis: BASE.epochMillis + 1000 }),
  );
});

test("a different destination is a different call", () => {
  assert.notEqual(
    egressEventId(BASE),
    egressEventId({ ...BASE, targetCanonical: targetCanonical("api.anthropic.com", 443, "/v1/messages") }),
  );
});

test("a different process is a different call", () => {
  assert.notEqual(
    egressEventId(BASE),
    egressEventId({ ...BASE, processIdentity: processIdentity("node/20", 4712) }),
  );
});

test("the canonical target folds case in the host and leaves the path alone", () => {
  assert.equal(targetCanonical("API.OpenAI.Com", 443, "/v1/Chat"), "api.openai.com:443/v1/Chat");
});
