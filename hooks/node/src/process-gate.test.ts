import assert from "node:assert/strict";
import test from "node:test";

import { decideInstrumentation, entrypointName, isNonTargetEntrypoint } from "./process-gate";

const APP: readonly string[] = ["/usr/bin/node", "/srv/app/server.js"];

test("an application process is instrumented", () => {
  assert.deepEqual(decideInstrumentation({}, APP, "v20.11.0"), { instrument: true });
  assert.deepEqual(decideInstrumentation({}, APP, "v22.3.1"), { instrument: true });
});

test("PERISKOP_HOOK=0 turns the hook off before anything else is decided", () => {
  // Checked first on purpose: the off switch has to work in a process that
  // would also have been rejected for some other reason, and in one that would
  // have been accepted.
  assert.deepEqual(decideInstrumentation({ PERISKOP_HOOK: "0" }, APP, "v20.11.0"), {
    instrument: false,
    reason: "disabled_by_env",
  });
  assert.deepEqual(
    decideInstrumentation({ PERISKOP_HOOK: "0" }, ["/usr/bin/node", "/x/npm-cli.js"], "v18.0.0"),
    { instrument: false, reason: "disabled_by_env" },
  );
});

test("any other value of PERISKOP_HOOK leaves the hook on", () => {
  assert.deepEqual(decideInstrumentation({ PERISKOP_HOOK: "1" }, APP, "v20.11.0"), {
    instrument: true,
  });
  assert.deepEqual(decideInstrumentation({ PERISKOP_HOOK: "" }, APP, "v20.11.0"), {
    instrument: true,
  });
});

test("a package manager or build tool is not a target", () => {
  const nonTargets = [
    "/usr/lib/node_modules/npm/bin/npm-cli.js",
    "/usr/lib/node_modules/npm/bin/npx-cli.js",
    "/opt/pnpm/bin/pnpm.cjs",
    "/opt/yarn/bin/yarn.js",
    "/app/node_modules/.bin/tsc",
    "/app/node_modules/typescript/bin/tsc",
    "/usr/local/bin/corepack",
  ];
  for (const script of nonTargets) {
    assert.ok(isNonTargetEntrypoint(["node", script]), script);
    assert.deepEqual(decideInstrumentation({}, ["node", script], "v20.11.0"), {
      instrument: false,
      reason: "non_target_process",
    });
  }
});

test("a script whose name merely resembles a build tool is still a target", () => {
  // The deny list is the one place the inverse-list principle is suspended, so
  // it matches whole names and never prefixes.
  for (const script of ["/srv/app/npm-metrics.js", "/srv/app/tsc-report.js", "/srv/app/yarns.js"]) {
    assert.equal(isNonTargetEntrypoint(["node", script]), false, script);
  }
});

test("a runtime older than the patches support is refused, not risked", () => {
  assert.deepEqual(decideInstrumentation({}, APP, "v18.20.4"), {
    instrument: false,
    reason: "unsupported_runtime",
  });
  assert.deepEqual(decideInstrumentation({}, APP, "not-a-version"), {
    instrument: false,
    reason: "unsupported_runtime",
  });
});

test("the entrypoint name is a basename and never a path", () => {
  assert.equal(entrypointName(["node", "/srv/app/server.js"]), "server");
  assert.equal(entrypointName(["node", "/srv/app/worker.mjs"]), "worker");
  assert.equal(entrypointName(["node"]), "node");
  assert.equal(entrypointName([]), "node");
});
