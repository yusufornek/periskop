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
  assert.equal(snapshot().hook_failures, 1);
});

test("a thrown value that is not an Error is contained just the same", () => {
  resetStatus();
  assert.doesNotThrow(() => {
    runSafely(() => {
      throw "a string, because libraries do this";
    });
  });
  assert.equal(snapshot().hook_failures, 1);
});

test("a value producing step falls back instead of failing", () => {
  resetStatus();
  const value = callSafely(() => {
    throw new Error("shape extraction went wrong");
  }, "fallback");
  assert.equal(value, "fallback");
  assert.equal(snapshot().hook_failures, 1);
});

test("a step that succeeds returns its own value and counts no failure", () => {
  resetStatus();
  assert.equal(
    callSafely(() => "real", "fallback"),
    "real",
  );
  assert.equal(snapshot().hook_failures, 0);
});

test("failures are counted, so nothing is lost quietly", () => {
  resetStatus();
  for (let i = 0; i < 5; i += 1) {
    runSafely(() => {
      throw new Error("again");
    });
  }
  assert.equal(snapshot().hook_failures, 5);
  assert.equal(snapshot().status, "active");
});
