import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { install } from "./install";
import { resetStatus, snapshot } from "./hook-status";
import type { EgressEvent } from "./egress-event";
import type { EventSink } from "./event-writer";

function collectingSink(): { sink: EventSink; events: EgressEvent[] } {
  const events: EgressEvent[] = [];
  return {
    events,
    sink: {
      record: (event) => events.push(event),
      close: () => undefined,
    },
  };
}

async function echoServer(): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((_request, response) => {
    response.writeHead(200);
    response.end('{"ok":true}');
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

test("installing patches every transport the process has", async (t) => {
  resetStatus();
  const server = await echoServer();
  const { sink, events } = collectingSink();
  const result = install({ sink, now: () => 1_764_000_000_000 });
  t.after(async () => {
    result.uninstall();
    await server.close();
  });

  assert.equal(result.installed, true);

  await new Promise<void>((resolve, reject) => {
    const request = http.request(server.url, { method: "POST" }, (response) => {
      response.resume();
      response.on("end", resolve);
    });
    request.on("error", reject);
    request.end('{"model":"gpt-4"}');
  });
  await fetch(`${server.url}/v1/models`);

  assert.equal(events.length, 2);
  assert.deepEqual(
    events.map((event) => event.library.module).sort(),
    ["node:http", "undici"],
  );
  for (const event of events) {
    assert.match(event.egress_event_id, /^ee_[0-9a-f]{16}$/);
    assert.equal(event.process.language, "javascript");
    assert.match(event.process.runtime, /^node\/\d+$/);
  }
});

test("installing twice does not record the same call twice", (t) => {
  resetStatus();
  const first = install({ sink: collectingSink().sink });
  const second = install({ sink: collectingSink().sink });
  t.after(() => {
    second.uninstall();
    first.uninstall();
  });

  assert.equal(first.installed, true);
  // NODE_OPTIONS and an explicit --require can both fire. A second install has
  // to be a no-op or every call would be counted twice.
  assert.equal(second.installed, false);
});

test("uninstalling leaves the process as it found it", () => {
  resetStatus();
  const originalRequest = http.request;
  const originalFetch = globalThis.fetch;

  const result = install({ sink: collectingSink().sink });
  assert.notEqual(http.request, originalRequest);
  assert.notEqual(globalThis.fetch, originalFetch);

  result.uninstall();
  assert.equal(http.request, originalRequest);
  assert.equal(globalThis.fetch, originalFetch);
});

test("a sink that cannot be built leaves the application unhooked and says so", (t) => {
  resetStatus();
  const originalRequest = http.request;
  // A directory that cannot exist, so the real sink fails to be created.
  const previous = process.env["PERISKOP_HOOK_DIR"];
  process.env["PERISKOP_HOOK_DIR"] = "/dev/null/not-a-directory";
  t.after(() => {
    if (previous === undefined) delete process.env["PERISKOP_HOOK_DIR"];
    else process.env["PERISKOP_HOOK_DIR"] = previous;
  });

  const result = install({});
  if (result.installed) result.uninstall();

  assert.equal(result.installed, false);
  assert.equal(http.request, originalRequest);
  assert.equal(snapshot().status, "disabled");
  assert.equal(snapshot().reason, "install_failed");
});
