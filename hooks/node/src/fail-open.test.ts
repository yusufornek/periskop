import assert from "node:assert/strict";
import test from "node:test";

import { callSafely, runSafely } from "./fail-open";
import { resetStatus, snapshot } from "./hook-status";

test("observation work that throws stops at the boundary", () => {
  resetStatus();
  assert.doesNotThrow(() => {
    runSafely(() => {
      throw new Error("patching went wrong");
    });
  });
  assert.deepEqual(snapshot().failures, ["hook.observe"]);
});

test("a thrown value that is not an Error is contained just the same", () => {
  resetStatus();
  assert.doesNotThrow(() => {
    runSafely(() => {
      throw "a string, because libraries do this";
    });
  });
  assert.deepEqual(snapshot().failures, ["hook.observe"]);
});

test("a value producing step falls back instead of failing", () => {
  resetStatus();
  const value = callSafely(() => {
    throw new Error("shape extraction went wrong");
  }, "fallback");
  assert.equal(value, "fallback");
  assert.deepEqual(snapshot().failures, ["hook.observe"]);
});

test("a step that succeeds returns its own value and counts no failure", () => {
  resetStatus();
  assert.equal(
    callSafely(() => "real", "fallback"),
    "real",
  );
  assert.deepEqual(snapshot().failures, []);
});

test("a swallowed failure is named, so nothing is lost quietly", () => {
  resetStatus();
  for (let i = 0; i < 5; i += 1) {
    runSafely(() => {
      throw new Error("again");
    });
  }
  // Deduplicated by stage: a hot loop that fails on every call must not turn
  // the failure list into the payload. What matters is that the stage is named,
  // not how many times it went wrong.
  assert.deepEqual(snapshot().failures, ["hook.observe"]);
  assert.equal(snapshot().hook_status, "active");
});
