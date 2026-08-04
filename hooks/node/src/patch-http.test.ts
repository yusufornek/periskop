import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import { Readable } from "node:stream";
import type { AddressInfo } from "node:net";

import { patchHttpModule, type HttpModuleLike } from "./patch-http";
import type { CallObservation } from "./egress-event";

function collector(): {
  record: (observation: CallObservation) => void;
  captured: CallObservation[];
} {
  const captured: CallObservation[] = [];
  return { record: (observation) => captured.push(observation), captured };
}

/** A server that reports back exactly what it received, so nothing is assumed. */
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
      response.writeHead(200, { "content-type": "application/json" });
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

function readResponse(request: http.ClientRequest): Promise<string> {
  return new Promise((resolve, reject) => {
    request.on("response", (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
    request.on("error", reject);
  });
}

test("a call through node:http is recorded with its shape and not its content", async (t) => {
  const server = await echoServer();
  const { record, captured } = collector();
  const undo = patchHttpModule(http as unknown as HttpModuleLike, "node:http", false, record);
  t.after(async () => {
    undo();
    await server.close();
  });

  const payload = JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: "hi" }] });
  const request = http.request(`${server.url}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
  });
  const answer = readResponse(request);
  request.end(payload);

  assert.equal(await answer, '{"ok":true}');
  assert.equal(server.received()[0], payload);
  assert.equal(captured.length, 1);

  const observed = captured[0] as CallObservation;
  assert.equal(observed.host, "127.0.0.1");
  assert.equal(observed.method, "POST");
  assert.equal(observed.path, "/v1/chat/completions");
  assert.equal(observed.body.byteSize, Buffer.byteLength(payload));
});

test("the patched request returns what the original returned", async (t) => {
  const server = await echoServer();
  const { record } = collector();
  const undo = patchHttpModule(http as unknown as HttpModuleLike, "node:http", false, record);
  t.after(async () => {
    undo();
    await server.close();
  });

  const request = http.request(server.url, { method: "POST" });
  assert.ok(request instanceof http.ClientRequest);
  const answer = readResponse(request);

  // write returns the drain flag and end returns the request, both unchanged.
  assert.equal(typeof request.write("a"), "boolean");
  assert.equal(request.end(), request);
  assert.equal(await answer, '{"ok":true}');
});

function thrownBy(action: () => unknown): NodeJS.ErrnoException {
  try {
    action();
  } catch (error) {
    return error as NodeJS.ErrnoException;
  }
  throw new Error("expected the call to throw");
}

test("an error from the original propagates unchanged", () => {
  const { record } = collector();
  const before = thrownBy(() => http.request("::not a url::"));
  const undo = patchHttpModule(http as unknown as HttpModuleLike, "node:http", false, record);
  try {
    const after = thrownBy(() => http.request("::not a url::"));
    assert.equal(after.constructor, before.constructor);
    assert.equal(after.code, before.code);
    assert.equal(after.message, before.message);
  } finally {
    undo();
  }
});

test("a recorder that throws never reaches the application", async (t) => {
  const server = await echoServer();
  const undo = patchHttpModule(http as unknown as HttpModuleLike, "node:http", false, () => {
    throw new Error("recorder is broken");
  });
  t.after(async () => {
    undo();
    await server.close();
  });

  const request = http.request(server.url, { method: "POST" });
  const answer = readResponse(request);
  request.end('{"model":"gpt-4"}');

  assert.equal(await answer, '{"ok":true}');
  assert.equal(server.received()[0], '{"model":"gpt-4"}');
});

test("a piped stream reaches the server whole and is never reassembled", async (t) => {
  const server = await echoServer();
  const { record, captured } = collector();
  const undo = patchHttpModule(http as unknown as HttpModuleLike, "node:http", false, record);
  t.after(async () => {
    undo();
    await server.close();
  });

  const pieces = ['{"model":', '"gpt-4",', '"messages":[]}'];
  const request = http.request(server.url, { method: "POST" });
  const answer = readResponse(request);
  Readable.from(pieces).pipe(request);

  assert.equal(await answer, '{"ok":true}');
  // The application's stream arrived intact: nothing was read out from under it.
  assert.equal(server.received()[0], pieces.join(""));

  const observed = captured[0] as CallObservation;
  assert.equal(observed.body.byteSize, Buffer.byteLength(pieces.join("")));
  // Sized, but not put back together: the pieces were counted, not collected.
  assert.equal(observed.body.sample, undefined);
});

test("http.get is patched in its own right", async (t) => {
  const server = await echoServer();
  const { record, captured } = collector();
  const undo = patchHttpModule(http as unknown as HttpModuleLike, "node:http", false, record);
  t.after(async () => {
    undo();
    await server.close();
  });

  const request = http.get(`${server.url}/models`);
  assert.equal(await readResponse(request), '{"ok":true}');
  assert.equal(captured.length, 1);
  assert.equal((captured[0] as CallObservation).method, "GET");
});

test("undoing the patch puts the module back as it was", () => {
  const original = http.request;
  const { record } = collector();
  const undo = patchHttpModule(http as unknown as HttpModuleLike, "node:http", false, record);
  assert.notEqual(http.request, original);
  undo();
  assert.equal(http.request, original);
});
