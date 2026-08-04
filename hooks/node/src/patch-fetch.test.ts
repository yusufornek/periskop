import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import { Readable } from "node:stream";
import type { AddressInfo } from "node:net";

import { patchFetch } from "./patch-fetch";
import type { CallObservation } from "./egress-event";

async function echoServer(): Promise<{
  url: string;
  received: () => string[];
  close: () => Promise<void>;
}> {
  const bodies: string[] = [];
  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      bodies.push(Buffer.concat(chunks).toString("utf8"));
      response.writeHead(200);
      response.end('{"ok":true}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    received: () => bodies,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

interface Scope {
  fetch?: (...args: unknown[]) => unknown;
}

test("a fetch call is recorded and its response is untouched", async (t) => {
  const server = await echoServer();
  const observations: CallObservation[] = [];
  const undo = patchFetch(globalThis as Scope, (observation) => observations.push(observation));
  t.after(async () => {
    undo();
    await server.close();
  });

  const payload = JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: "hi" }] });
  const response = await fetch(`${server.url}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: payload,
  });

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
  assert.equal(server.received()[0], payload);

  assert.equal(observations.length, 1);
  const observed = observations[0] as CallObservation;
  assert.equal(observed.module, "undici");
  assert.equal(observed.method, "POST");
  assert.equal(observed.path, "/v1/chat/completions");
  assert.equal(observed.body.byteSize, Buffer.byteLength(payload));
});

test("a streaming request body is never read by the hook", async (t) => {
  const server = await echoServer();
  const observations: CallObservation[] = [];
  const undo = patchFetch(globalThis as Scope, (observation) => observations.push(observation));
  t.after(async () => {
    undo();
    await server.close();
  });

  const pieces = ['{"model":', '"gpt-4"}'];
  const body = Readable.toWeb(Readable.from(pieces)) as ReadableStream;
  const response = await fetch(server.url, {
    method: "POST",
    body,
    // Node requires this for a streamed request body.
    duplex: "half",
  } as RequestInit);

  assert.equal(response.status, 200);
  // The stream is read exactly once, by the socket. If the hook had touched it
  // the server would have seen a truncated body or the call would have failed.
  assert.equal(server.received()[0], pieces.join(""));

  const observed = observations[0] as CallObservation;
  assert.equal(observed.body.streamed, true);
  assert.equal(observed.body.sample, undefined);
});

test("a rejection reaches the caller unchanged", async (t) => {
  const observations: CallObservation[] = [];
  const undo = patchFetch(globalThis as Scope, (observation) => observations.push(observation));
  t.after(() => undo());

  // Port zero never accepts, so the fetch fails at connect time.
  await assert.rejects(() => fetch("http://127.0.0.1:1/never"), TypeError);
  // The call still happened, so it is still recorded.
  assert.equal(observations.length, 1);
});

test("a recorder that throws does not disturb the caller", async (t) => {
  const server = await echoServer();
  const undo = patchFetch(globalThis as Scope, () => {
    throw new Error("recorder is broken");
  });
  t.after(async () => {
    undo();
    await server.close();
  });

  const response = await fetch(server.url, { method: "POST", body: '{"model":"gpt-4"}' });
  assert.equal(response.status, 200);
  assert.equal(server.received()[0], '{"model":"gpt-4"}');
});

test("a scope without fetch is left alone", () => {
  const scope: Scope = {};
  const undo = patchFetch(scope, () => undefined);
  assert.equal(scope.fetch, undefined);
  undo();
});

test("undoing the patch puts fetch back", () => {
  const original = globalThis.fetch;
  const undo = patchFetch(globalThis as Scope, () => undefined);
  assert.notEqual(globalThis.fetch, original);
  undo();
  assert.equal(globalThis.fetch, original);
});
