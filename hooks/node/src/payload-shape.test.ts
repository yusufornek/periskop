import assert from "node:assert/strict";
import test from "node:test";

import { fieldPaths, maskKey } from "./payload-shape";

// The test this package exists to pass. A payload is built out of values that
// would be damaging to copy, and every one of them is looked for in the output.
test("no value from the payload reaches the field paths", () => {
  const secrets = [
    "Merhaba, hesap numaram TR120006200119000006672315",
    "sk-proj-9f3ac1d2e4b5",
    "patient had a myocardial infarction in 2019",
    "4111111111111111",
    "ahmet.yilmaz@firma.com.tr",
  ];

  const body = {
    model: "gpt-4",
    messages: [
      { role: "user", content: secrets[0] },
      { role: "assistant", content: secrets[2] },
    ],
    metadata: { api_key: secrets[1], card: secrets[3] },
    customers: { [secrets[4] as string]: { total: 42 } },
    user: secrets[4],
  };

  const { paths } = fieldPaths(body);
  const serialised = paths.join("\n");

  for (const secret of secrets) {
    assert.ok(!serialised.includes(secret), `leaked: ${secret}`);
    // Also check the pieces, so a partially copied value cannot pass either.
    for (const fragment of secret.split(/[\s@.]/).filter((part) => part.length > 4)) {
      assert.ok(!serialised.includes(fragment), `leaked fragment: ${fragment}`);
    }
  }

  // The shape still has to be useful, or the masking has thrown out the point.
  assert.ok(paths.includes("messages[].content"));
  assert.ok(paths.includes("messages[].role"));
  assert.ok(paths.includes("model"));
});

test("a key that carries data is replaced by a placeholder", () => {
  const { paths } = fieldPaths({ customers: { "ahmet@firma.com": { total: 1 } } });
  assert.deepEqual(paths, ["<dyn>.<dyn>.<dyn>"]);
});

test("keys outside the request schema allow list are masked", () => {
  assert.equal(maskKey("messages"), "messages");
  assert.equal(maskKey("model"), "model");
  assert.equal(maskKey("content"), "content");
  assert.equal(maskKey("internal_customer_reference"), "<dyn>");
  assert.equal(maskKey("a@b.com"), "<dyn>");
  assert.equal(maskKey("123456789"), "<dyn>");
  assert.equal(maskKey("/etc/passwd"), "<dyn>");
});

test("the leak filter still holds for a key that is also on the allow list", () => {
  // The allow list will be widened as providers add fields. The pattern check is
  // what has to keep standing on the day somebody widens it carelessly.
  assert.equal(maskKey("user name"), "<dyn>");
  assert.equal(maskKey("model/2024"), "<dyn>");
});

test("traversal stops at depth six and says where it stopped", () => {
  const deep = { messages: { content: { text: { data: { parts: { items: { name: 1 } } } } } } };
  const { paths, truncatedDepth } = fieldPaths(deep);
  assert.equal(truncatedDepth, 7);
  assert.ok(paths.every((path) => path.split(".").length <= 6));
});

test("a shallow payload reports no truncation", () => {
  const { truncatedDepth } = fieldPaths({ model: "gpt-4", messages: [{ role: "user" }] });
  assert.equal(truncatedDepth, undefined);
});

test("field paths are sorted and free of duplicates", () => {
  const { paths } = fieldPaths({
    messages: [
      { role: "a", content: "b" },
      { role: "c", content: "d" },
    ],
    model: "e",
  });
  assert.deepEqual(paths, ["messages[].content", "messages[].role", "model"]);
});

test("a long array is sampled rather than walked, and the stop is declared", () => {
  const messages = Array.from({ length: 200 }, () => ({ role: "user", content: "x" }));
  const { paths, truncatedDepth } = fieldPaths({ messages });
  assert.deepEqual(paths, ["messages[].content", "messages[].role"]);
  assert.equal(truncatedDepth, 2);
});
