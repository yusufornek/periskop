// The bootstrap, tested the way it is actually used: a real child process
// started with --require.
//
// Everything else in this package can be tested in-process. This file cannot:
// the claims are about what happens to a process that was not written with the
// hook in mind, and the only honest way to check them is to start one.
//
// The child serves its own request. A server in the test process would never
// answer it, because the test process is blocked waiting for the child.

import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { EgressEvent } from "./egress-event";

const PRELOAD = join(__dirname, "preload.js");

/** An application that makes one real call and says when it is done. */
const APP_SOURCE = `
const http = require("node:http");
const server = http.createServer((request, response) => {
  request.resume();
  request.on("end", () => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"ok":true}');
  });
});
server.listen(0, "127.0.0.1", () => {
  const url = "http://127.0.0.1:" + server.address().port + "/v1/chat/completions";
  const request = http.request(url, { method: "POST" }, (response) => {
    response.resume();
    response.on("end", () => {
      server.close();
      process.stdout.write("app finished");
    });
  });
  request.on("error", (error) => {
    server.close();
    process.stdout.write("app failed: " + error.message);
  });
  request.end(JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: "hi" }] }));
});
`;

interface Sandbox {
  readonly dir: string;
  readonly appPath: (name: string) => string;
  readonly eventsIn: (dir: string) => EgressEvent[];
  readonly cleanup: () => void;
}

function sandbox(): Sandbox {
  const dir = mkdtempSync(join(tmpdir(), "periskop-preload-"));
  return {
    dir,
    appPath: (name: string) => {
      const path = join(dir, name);
      writeFileSync(path, APP_SOURCE);
      return path;
    },
    eventsIn: (eventDir: string) =>
      readdirSync(eventDir)
        .filter((name) => name.endsWith(".ndjson"))
        .flatMap((name) =>
          readFileSync(join(eventDir, name), "utf8")
            .split("\n")
            .filter((line) => line.length > 0)
            .map((line) => JSON.parse(line) as EgressEvent),
        ),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function runApp(
  script: string,
  env: NodeJS.ProcessEnv,
  extraArgs: string[] = ["--require", PRELOAD],
): string {
  return execFileSync(process.execPath, [...extraArgs, script], {
    env: { ...process.env, ...env },
    encoding: "utf8",
    timeout: 20_000,
  });
}

test("a hooked process records the call it actually made", (t) => {
  const box = sandbox();
  t.after(box.cleanup);

  const eventDir = join(box.dir, "events");
  assert.equal(runApp(box.appPath("server.js"), { PERISKOP_HOOK_DIR: eventDir }), "app finished");

  const events = box.eventsIn(eventDir);
  assert.equal(events.length, 1);

  const event = events[0] as EgressEvent;
  assert.match(event.egress_event_id, /^ee_[0-9a-f]{16}$/);
  assert.equal(event.process.language, "javascript");
  assert.equal(event.process.entrypoint_hint, "server");
  assert.equal(event.library.module, "node:http");
  assert.equal(event.library.mechanism, "http_client");
  assert.equal(event.operation, "post");
  assert.equal(event.target.host_id, "127.0.0.1");
  assert.equal(event.target.path_template, "/v1/chat/completions");
  assert.equal(event.target.provider_ref, "unknown");
  assert.deepEqual(event.payload_shape.field_paths, [
    "messages[].content",
    "messages[].role",
    "model",
  ]);

  // The prompt was "hi" and the model was "gpt-4". Neither reached the record.
  const recorded = JSON.stringify(event);
  assert.ok(!recorded.includes("gpt-4"));
  assert.ok(!recorded.includes('"hi"'));
});

test("NODE_OPTIONS installs the hook just as --require does", (t) => {
  const box = sandbox();
  t.after(box.cleanup);

  const eventDir = join(box.dir, "events");
  const output = runApp(
    box.appPath("server.js"),
    { PERISKOP_HOOK_DIR: eventDir, NODE_OPTIONS: `--require ${PRELOAD}` },
    [],
  );

  assert.equal(output, "app finished");
  assert.equal(box.eventsIn(eventDir).length, 1);
});

test("PERISKOP_HOOK=0 turns the hook off entirely", (t) => {
  const box = sandbox();
  t.after(box.cleanup);

  const eventDir = join(box.dir, "events");
  const output = runApp(box.appPath("server.js"), {
    PERISKOP_HOOK_DIR: eventDir,
    PERISKOP_HOOK: "0",
  });

  assert.equal(output, "app finished");
  // Not even the directory is created: the gate returns before anything is built.
  assert.throws(() => readdirSync(eventDir));
});

test("a process that is not a target exits the hook without building anything", (t) => {
  const box = sandbox();
  t.after(box.cleanup);

  const eventDir = join(box.dir, "events");
  // The entrypoint name is what the gate reads, so the same script under a
  // build tool's name has to be left alone.
  const output = runApp(box.appPath("npm-cli.js"), { PERISKOP_HOOK_DIR: eventDir });

  assert.equal(output, "app finished");
  assert.throws(() => readdirSync(eventDir));
});

test("a broken hook artifact does not stop the application from starting", (t) => {
  const box = sandbox();
  t.after(box.cleanup);

  // A build that went wrong: preload is intact, the module it loads is not.
  const brokenDist = join(box.dir, "broken-dist");
  mkdirSync(brokenDist, { recursive: true });
  for (const name of readdirSync(__dirname).filter((file) => file.endsWith(".js"))) {
    copyFileSync(join(__dirname, name), join(brokenDist, name));
  }
  writeFileSync(join(brokenDist, "install.js"), "this is not javascript {{{");

  const output = runApp(box.appPath("server.js"), {}, [
    "--require",
    join(brokenDist, "preload.js"),
  ]);
  assert.equal(output, "app finished");
});

test("a missing hook module does not stop the application from starting", (t) => {
  const box = sandbox();
  t.after(box.cleanup);

  // Only preload survived the copy. Every module it reaches for is absent.
  const partialDist = join(box.dir, "partial-dist");
  mkdirSync(partialDist, { recursive: true });
  copyFileSync(PRELOAD, join(partialDist, "preload.js"));

  const output = runApp(box.appPath("server.js"), {}, [
    "--require",
    join(partialDist, "preload.js"),
  ]);
  assert.equal(output, "app finished");
});

test("an event sink that cannot be created does not stop the application", (t) => {
  const box = sandbox();
  t.after(box.cleanup);

  // A path that cannot be a directory, which is what a misconfigured deployment
  // looks like from inside the process.
  const output = runApp(box.appPath("server.js"), { PERISKOP_HOOK_DIR: "/dev/null/events" });
  assert.equal(output, "app finished");
});

test("an unwritable event stream does not stop the application", (t) => {
  const box = sandbox();
  t.after(box.cleanup);

  // The event file is taken by a directory, so every write to it fails. The
  // call still goes out and the application never learns that anything did.
  const eventDir = join(box.dir, "events");
  mkdirSync(eventDir, { recursive: true });
  const app = box.appPath("server.js");
  const blocker = `const p = require("node:path");
    require("node:fs").mkdirSync(p.join(process.env.PERISKOP_HOOK_DIR, "node-" + process.pid + ".ndjson"));`;
  writeFileSync(app, `${blocker}\n${APP_SOURCE}`);

  const output = runApp(app, { PERISKOP_HOOK_DIR: eventDir });
  assert.equal(output, "app finished");
});
