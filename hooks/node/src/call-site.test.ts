import assert from "node:assert/strict";
import test from "node:test";

import { currentStack, findCallSite } from "./call-site";

const CWD = "/srv/app";

function stackOf(...frames: string[]): string {
  return ["Error", ...frames].join("\n");
}

test("the first application frame is the one reported", () => {
  const site = findCallSite(
    stackOf(
      "    at ClientRequest.periskopEnd (/srv/app/hooks/node/dist/patch-http.js:80:12)",
      "    at post (/srv/app/node_modules/openai/core.js:210:9)",
      "    at summarize (/srv/app/services/customer.js:42:17)",
      "    at main (/srv/app/index.js:8:3)",
    ),
    CWD,
  );
  assert.deepEqual(site, { path: "services/customer.js", symbol: "summarize" });
});

test("a path is relative to the project root, because the schema rejects absolute ones", () => {
  const site = findCallSite(stackOf("    at run (/srv/app/src/worker.js:3:1)"), CWD);
  assert.equal(site?.path, "src/worker.js");
  assert.equal(site?.path.startsWith("/"), false);
});

test("a frame outside the project root is dropped rather than leaked", () => {
  // A build machine's directory layout is not something a report should carry.
  const site = findCallSite(stackOf("    at run (/opt/vendor/tool.js:3:1)"), CWD);
  assert.equal(site, undefined);
});

test("node internals and dependencies are skipped", () => {
  const site = findCallSite(
    stackOf(
      "    at node:internal/http/client:100:5",
      "    at /srv/app/node_modules/undici/lib/fetch.js:9:1",
    ),
    CWD,
  );
  assert.equal(site, undefined);
});

test("an anonymous frame still gives a path", () => {
  const site = findCallSite(stackOf("    at /srv/app/src/worker.js:3:1"), CWD);
  assert.deepEqual(site, { path: "src/worker.js", symbol: undefined });
});

test("a missing stack is a missing call site, not a failure", () => {
  assert.equal(findCallSite(undefined, CWD), undefined);
  assert.equal(findCallSite("", CWD), undefined);
});

test("capturing a stack leaves the process wide trace limit alone", () => {
  // Raising it would change how every later exception in the application
  // behaves, which is a change to the program under observation.
  const before = Error.stackTraceLimit;
  currentStack();
  assert.equal(Error.stackTraceLimit, before);
});
