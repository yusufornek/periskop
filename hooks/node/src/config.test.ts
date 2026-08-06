// The transport the event schema fixes: a directory, one file per process.

import assert from "node:assert/strict";
import test from "node:test";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { EVENT_DIR, LEGACY_EVENT_DIR, readConfig } from "./config";

const ARGV = ["/usr/bin/node", "/srv/app/server.js"];

test("the contract variable names the event directory", () => {
  const config = readConfig({ [EVENT_DIR]: "/var/run/periskop" }, ARGV);
  assert.equal(config.outputDir, "/var/run/periskop");
});

test("the previous variable name is still honoured", () => {
  // An existing deployment must survive the upgrade rather than fall back to a
  // temporary directory nobody is watching.
  const config = readConfig({ [LEGACY_EVENT_DIR]: "/var/run/legacy" }, ARGV);
  assert.equal(config.outputDir, "/var/run/legacy");
});

test("the contract variable wins when both are set", () => {
  const config = readConfig(
    { [EVENT_DIR]: "/var/run/periskop", [LEGACY_EVENT_DIR]: "/var/run/legacy" },
    ARGV,
  );
  assert.equal(config.outputDir, "/var/run/periskop");
});

test("an exported but empty variable reads as unset", () => {
  // `export PERISKOP_EVENT_DIR=` in a shell profile would otherwise resolve to
  // the process working directory and scatter event files through a repository.
  const config = readConfig({ [EVENT_DIR]: "  ", [LEGACY_EVENT_DIR]: "/var/run/legacy" }, ARGV);
  assert.equal(config.outputDir, "/var/run/legacy");
});

test("with neither variable there is no destination, and the hook stays off", () => {
  // The old behaviour was a temporary directory nobody named. NODE_OPTIONS
  // spreads down a whole process tree, so one line in a shell profile put the
  // destination hosts, path templates and call sites of every Node process on
  // the machine into a shared directory that nobody collects and nobody clears.
  // periskop must not itself be a source of egress, and a directory the
  // operator never chose is exactly that.
  const config = readConfig({}, ARGV);
  assert.equal(config.outputDir, undefined);
});

test("no destination is chosen from a temporary directory", () => {
  // Pinned by name as well as by value: the failure was a plausible looking
  // default, so a future edit that reintroduces one should fail here.
  const config = readConfig({}, ARGV);
  assert.notEqual(config.outputDir, join(tmpdir(), "periskop-events"));
});

test("an operator supplied entrypoint is reduced to a basename", () => {
  // The field is a name. Without this every event carries /srv/app, the report
  // stops diffing against the same run on another host, and the schema's "never
  // an absolute path" is broken by the hook that writes the field. The schema
  // has no pattern for it, so no later stage would catch the record. The Python
  // hook reduces the same variable the same way.
  const config = readConfig({ PERISKOP_HOOK_ENTRYPOINT: "/srv/app/worker.js" }, ARGV);
  assert.equal(config.entrypointHint, "worker.js");
});

test("an extension the operator wrote survives, unlike the one on argv", () => {
  assert.equal(readConfig({ PERISKOP_HOOK_ENTRYPOINT: "ingest.js" }, ARGV).entrypointHint,
    "ingest.js");
  assert.equal(readConfig({}, ARGV).entrypointHint, "server");
});

test("a trailing separator is read the way the other hook reads it", () => {
  // Python's os.path.basename answers "" here and this basename answers "app".
  // One variable, two hooks, one hint: the divergence had to be closed in one
  // direction, and keeping the operator's last word is that direction.
  assert.equal(readConfig({ PERISKOP_HOOK_ENTRYPOINT: "/srv/app/" }, ARGV).entrypointHint,
    "app");
});

test("an entrypoint that reduces to nothing falls back to the script name", () => {
  // An empty string is a valid value for this field, so it would be written and
  // read as a process that named itself.
  assert.equal(readConfig({ PERISKOP_HOOK_ENTRYPOINT: "/" }, ARGV).entrypointHint,
    "server");
  assert.equal(readConfig({ PERISKOP_HOOK_ENTRYPOINT: "   " }, ARGV).entrypointHint,
    "server");
});

test("reading configuration creates nothing on disk", () => {
  // Configuration is read at startup in every hooked process. Creating the
  // directory here would be a side effect for processes that record nothing.
  const target = join(tmpdir(), "periskop-config-test-should-not-exist");
  readConfig({ [EVENT_DIR]: target }, ARGV);
  assert.throws(() => require("node:fs").readdirSync(target));
});
