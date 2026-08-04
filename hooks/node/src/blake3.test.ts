// Vectors taken from the official BLAKE3 test set and re-generated with the
// blake3 crate this repository already depends on, so the hook and the engine
// cannot drift into two different identities for the same call.
//
// The input for a length N is the repeating byte pattern i % 251, which is the
// pattern the reference test vectors use. The lengths cross every boundary the
// implementation has: single block, block edge, chunk edge, and several levels
// of the parent tree.

import assert from "node:assert/strict";
import test from "node:test";

import { blake3, blake3Short } from "./blake3";

// The separator the identity formula in data-model.md section 2 joins fields with.
const UNIT_SEPARATOR = "\u001f";

const VECTORS: ReadonlyArray<readonly [number, string]> = [
  [0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"],
  [1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"],
  [2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"],
  [3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"],
  [63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"],
  [64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"],
  [65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"],
  [1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"],
  [1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"],
  [1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"],
  [2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"],
  [2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"],
  [3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"],
  [4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"],
  [8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"],
];

function patternInput(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) bytes[i] = i % 251;
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

test("blake3 matches the reference digest at every block and chunk boundary", () => {
  for (const [length, expected] of VECTORS) {
    assert.equal(toHex(blake3(patternInput(length))), expected, `length ${length}`);
  }
});

test("blake3 matches the reference digest for the strings identities are built from", () => {
  const cases: ReadonlyArray<readonly [string, string]> = [
    ["abc", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"],
    ["periskop", "ccbfc5c0d76f82d6c780f0f364c4eaa4cec7adc876e4f2badb1c58a59b9c1402"],
    [
      ["ee/v1", "node/26", "api.openai.com:443"].join(UNIT_SEPARATOR),
      "ed11bc99653a5e2e875ab9d9e98919ec169a08740f0bbaf085cc6462b41ae792",
    ],
  ];
  for (const [input, expected] of cases) {
    assert.equal(toHex(blake3(Buffer.from(input, "utf8"))), expected, JSON.stringify(input));
  }
});

test("the short form is the first eight bytes as sixteen lowercase hex characters", () => {
  const short = blake3Short(Buffer.from("periskop", "utf8"));
  assert.match(short, /^[0-9a-f]{16}$/);
  assert.equal(short, "ccbfc5c0d76f82d6");
});
