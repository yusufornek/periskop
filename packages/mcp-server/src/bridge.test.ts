// What the bridge does when the engine misbehaves.
//
// The smoke test covers the happy path across the language boundary with the
// real binary. This covers the other half, which the real binary is bad at
// producing on demand: a line that is not JSON, an error the engine cannot
// attribute to a request, an engine that explains itself on stderr and then
// says nothing. Each of those used to leave the caller waiting for the full
// timeout and then blaming the wrong thing.
//
// The stand in is a program rather than an object, because the behaviour under
// test lives between two processes: the line framing, the stderr capture and
// the timer. A fake object in place of the child would exercise none of it.

import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";

import { EngineBridge } from "./bridge.js";

const scratch: string[] = [];

after(() => {
  for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});

/**
 * Writes a program that speaks the engine's side of the protocol, badly.
 *
 * `.cjs` and an absolute interpreter in the shebang, so the file runs the same
 * way whatever the temporary directory contains and whichever node is first on
 * the path.
 */
function fakeEngine(body: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), "periskop-bridge-"));
  scratch.push(dir);
  const file = path.join(dir, "fake-engine.cjs");
  writeFileSync(file, `#!${process.execPath}\n${body}\n`);
  chmodSync(file, 0o755);
  return file;
}

/** Reads requests and answers each one with the given object. */
function answersWith(response: string): string {
  return `
const { createInterface } = require("node:readline");
createInterface({ input: process.stdin }).on("line", (line) => {
  const request = JSON.parse(line);
  const response = ${response};
  process.stdout.write(JSON.stringify(response) + "\\n");
});
`;
}

/** Prints something that is not a message, then serves requests normally. */
const STRAY_LINE = `
process.stdout.write("engine warming up, not json\\n");
const { createInterface } = require("node:readline");
createInterface({ input: process.stdin }).on("line", (line) => {
  const request = JSON.parse(line);
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: request.id, result: { ok: true } }) + "\\n");
});
`;

test("a line that is not a message is reported rather than dropped", async () => {
  const binary = fakeEngine(STRAY_LINE);
  const seen: string[] = [];
  const engine = new EngineBridge({ binary, timeoutMs: 3000, onDiagnostic: (m) => seen.push(m) });

  try {
    await engine.call("ping");
    // The line arrives before the answer to the request, so by the time the
    // call has resolved the bridge has had its chance to notice it.
    assert.ok(seen.length > 0, "a line the bridge could not parse left no trace");
    assert.match(seen.join(" "), /engine warming up, not json/);
  } finally {
    await engine.close();
  }
});

test("a line that is not a message does not take the session down", async () => {
  // Reporting it must not turn a stray print into a dead connection: the
  // engine is still answering, and the requests after it are still valid.
  const binary = fakeEngine(STRAY_LINE);
  const engine = new EngineBridge({ binary, timeoutMs: 3000, onDiagnostic: () => undefined });

  try {
    assert.deepEqual(await engine.call("ping"), { ok: true });
    assert.deepEqual(await engine.call("ping"), { ok: true });
  } finally {
    await engine.close();
  }
});

test("a bridge told nowhere to report still reports somewhere", async () => {
  // No sink configured is the shape the server itself uses. The message goes to
  // stderr, which for a stdio server is the only channel that is not the
  // protocol, and the run must survive the attempt.
  const binary = fakeEngine(STRAY_LINE);
  const engine = new EngineBridge({ binary, timeoutMs: 3000 });

  try {
    assert.deepEqual(await engine.call("ping"), { ok: true });
  } finally {
    await engine.close();
  }
});

test("an error the engine could not attribute reaches the request in flight", async () => {
  // JSON-RPC uses a null id when the engine cannot tell which request failed,
  // which is exactly the case where dropping the message costs the caller the
  // reason. One request is in flight, so there is nothing to disambiguate.
  const binary = fakeEngine(
    answersWith(
      `{ jsonrpc: "2.0", id: null, error: { code: -32700, message: "rules directory is empty" } }`,
    ),
  );
  const engine = new EngineBridge({ binary, timeoutMs: 3000 });

  try {
    await assert.rejects(() => engine.call("scan", { path: "." }), /rules directory is empty/);
  } finally {
    await engine.close();
  }
});

test("an error nobody can be blamed for is still visible in the failure", async () => {
  // Two requests in flight and one complaint with no id on it. Handing it to
  // either request would be a guess, so both time out, and the complaint has to
  // travel with the timeout instead of dying with the line it arrived on.
  const binary = fakeEngine(`
let seen = 0;
const { createInterface } = require("node:readline");
createInterface({ input: process.stdin }).on("line", () => {
  seen += 1;
  if (seen === 2) {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32602, message: "cannot parse params" },
    }) + "\\n");
  }
});
`);
  const seen: string[] = [];
  const engine = new EngineBridge({ binary, timeoutMs: 800, onDiagnostic: (m) => seen.push(m) });

  try {
    const outcomes = await Promise.allSettled([
      engine.call("scan", { path: "." }),
      engine.call("scan", { path: "/other" }),
    ]);

    assert.match(seen.join(" "), /cannot parse params/);
    for (const outcome of outcomes) {
      assert.equal(outcome.status, "rejected");
      const message = outcome.status === "rejected" ? String(outcome.reason) : "";
      assert.match(message, /did not answer within/);
      assert.match(message, /cannot parse params/);
    }
  } finally {
    await engine.close();
  }
});

test("an answer to a request that is no longer waiting is reported", async () => {
  // An id nothing is waiting for means an answer went missing somewhere: a
  // request that already timed out, or an engine numbering its replies wrong.
  // Either way the caller below is about to be told nobody answered, which is
  // only half of what happened.
  const binary = fakeEngine(
    answersWith(`{ jsonrpc: "2.0", id: request.id + 1000, result: { ok: true } }`),
  );
  const seen: string[] = [];
  const engine = new EngineBridge({ binary, timeoutMs: 800, onDiagnostic: (m) => seen.push(m) });

  try {
    await assert.rejects(() => engine.call("ping"), /did not answer within/);
    assert.match(seen.join(" "), /1001/);
  } finally {
    await engine.close();
  }
});

test("a message past the length limit is reported rather than parsed", async () => {
  // Nothing bounded the length of a line, so an engine that sent one without an
  // end handed unbounded work to JSON.parse, to the projection and to the
  // caller's context. The limit is an option so that the bound can be exercised
  // without moving sixteen megabytes through a pipe.
  const binary = fakeEngine(`
const { createInterface } = require("node:readline");
createInterface({ input: process.stdin }).on("line", (line) => {
  const request = JSON.parse(line);
  process.stdout.write(JSON.stringify({
    jsonrpc: "2.0",
    id: request.id,
    result: { ok: true, filler: "x".repeat(4096) },
  }) + "\\n");
});
`);
  const seen: string[] = [];
  const engine = new EngineBridge({
    binary,
    timeoutMs: 800,
    maxMessageChars: 512,
    onDiagnostic: (m) => seen.push(m),
  });

  try {
    // The over long answer is not delivered, so this request goes unanswered and
    // fails on the timeout. What it must not do is come back as a result.
    await assert.rejects(() => engine.call("ping"), /did not answer within/);
    assert.match(seen.join(" "), /past the 512 character limit/);
    // The failure carries the reason, rather than leaving the caller with a bare
    // timeout for an engine that did answer.
    await assert.rejects(() => engine.call("ping"), /past the 512 character limit/);
  } finally {
    await engine.close();
  }
});

test("a message inside the limit is delivered as before", async () => {
  // The bound must not become a limit on real answers.
  const binary = fakeEngine(
    answersWith(`{ jsonrpc: "2.0", id: request.id, result: { ok: true } }`),
  );
  const engine = new EngineBridge({ binary, timeoutMs: 3000, maxMessageChars: 512 });

  try {
    assert.deepEqual(await engine.call("ping"), { ok: true });
  } finally {
    await engine.close();
  }
});

test("a timeout says what the engine printed on stderr", async () => {
  // The engine had already explained itself. The caller waited two minutes and
  // was told only that nobody answered.
  const binary = fakeEngine(`
process.stderr.write("engine: rules failed to compile at line 7\\n");
process.stdin.resume();
`);
  const engine = new EngineBridge({ binary, timeoutMs: 800 });

  try {
    await assert.rejects(
      () => engine.call("scan", { path: "." }),
      (error: Error) => {
        assert.match(error.message, /did not answer within/);
        assert.match(error.message, /rules failed to compile at line 7/);
        return true;
      },
    );
  } finally {
    await engine.close();
  }
});
