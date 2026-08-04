// The two hooks have to agree, and this is where that is checked.
//
// The Node hook and the Python hook write into one stream under one contract.
// The same call recorded by both derives the same egress_event_id, so the
// collector keeps one of the two records and discards the other without
// counting the discard. Everything that differs between the two implementations
// therefore decides what the report says by way of a sort order.
//
// The vector file is one file read by both suites, not a copy in each. Drifting
// apart is exactly the failure being guarded against, and two files drift
// together. It sits in the Python tree because that is a directory both hooks
// can read from today; a request to give it a home of its own is filed in
// hub/memory/interfaces.md.

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { fieldPaths } from "./payload-shape";
import { classifyHost } from "./provider-ref";

interface FieldPathCase {
  readonly name: string;
  readonly payload: unknown;
  readonly paths: readonly string[];
  readonly truncated_depth: number | null;
}

interface ProviderCase {
  readonly host: string;
  readonly provider: string;
}

interface Vectors {
  readonly field_paths: readonly FieldPathCase[];
  readonly provider_ref: readonly ProviderCase[];
}

function vectors(): Vectors {
  // From dist/ back up to hooks/, then across into the Python hook's tests.
  const path = join(__dirname, "..", "..", "python", "tests", "hook-parity-vectors.json");
  return JSON.parse(readFileSync(path, "utf8")) as Vectors;
}

test("every vector produces the field paths the other hook produces", () => {
  for (const testCase of vectors().field_paths) {
    const { paths } = fieldPaths(testCase.payload);
    assert.deepEqual([...paths], [...testCase.paths], testCase.name);
  }
});

test("every vector produces the truncated depth the other hook produces", () => {
  // Absent and zero are different statements: absent means the walk finished,
  // zero means it stopped at the root. And where a walk stopped twice, the
  // deeper stop is the one reported, or a deep payload would be described as
  // the shallow thing it is not.
  for (const testCase of vectors().field_paths) {
    const { truncatedDepth } = fieldPaths(testCase.payload);
    const expected = testCase.truncated_depth ?? undefined;
    assert.equal(truncatedDepth, expected, testCase.name);
  }
});

test("every host classifies the way the other hook classifies it", () => {
  // A table that knows a provider in one language and not in the other makes
  // "the code says OpenAI, the wire says Groq" a finding that only ever appears
  // in half the processes.
  for (const testCase of vectors().provider_ref) {
    assert.equal(classifyHost(testCase.host), testCase.provider, testCase.host);
  }
});
