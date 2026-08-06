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
// together.
//
// It lives in hooks/shared/, which belongs to neither implementation. That is
// the point: while it sat under the Python hook's test directory this suite
// reached across into another hook's tests, so either side could have relaxed a
// vector the other was still being held to, and renaming a Python test
// directory would have removed this gate without failing a single test.

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { admittedKeys, fieldPaths, maskKey } from "./payload-shape";
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

interface KeyVocabulary {
  readonly allowed: readonly string[];
}

interface Vectors {
  readonly field_paths: readonly FieldPathCase[];
  readonly key_vocabulary: KeyVocabulary;
  readonly provider_ref: readonly ProviderCase[];
}

function vectors(): Vectors {
  // dist/ -> node/ -> hooks/ -> shared/. Resolved from __dirname rather than
  // from cwd, because this file runs compiled out of dist/ and the suite is
  // started from hooks/node.
  const path = join(__dirname, "..", "..", "shared", "hook-parity-vectors.json");
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

test("the admitted key vocabulary is the one the other hook admits", () => {
  // Entry for entry, not merely overlapping. A key one hook knows and the other
  // masks gives one call two shapes under one identity, and the collector keeps
  // whichever record sorted first. Widening the vocabulary is now one edit to
  // three files, and skipping any of the three fails both suites.
  assert.deepEqual([...admittedKeys()], [...vectors().key_vocabulary.allowed]);
});

test("a key outside the shared vocabulary is masked", () => {
  // The other direction. Without it a hook could admit everything and still
  // pass the list above.
  assert.equal(maskKey("balance_owed"), "<dyn>");
  assert.equal(maskKey("ahmet@firma.com"), "<dyn>");
});

test("every host classifies the way the other hook classifies it", () => {
  // A table that knows a provider in one language and not in the other makes
  // "the code says OpenAI, the wire says Groq" a finding that only ever appears
  // in half the processes.
  for (const testCase of vectors().provider_ref) {
    assert.equal(classifyHost(testCase.host), testCase.provider, testCase.host);
  }
});
