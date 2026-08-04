// Putting the hook in place, and being able to take it out again.
//
// Every step is individually recoverable. If node:https cannot be patched,
// node:http still is; if the sink cannot be created, nothing is patched and the
// process runs exactly as it would have without the hook. There is no partial
// state that leaves the application worse off than not installing at all.

import { createRecorder, type CallRecorder } from "./call-recorder";
import { FileEventSink, type EventSink } from "./event-writer";
import { markDisabled } from "./hook-status";
import { patchFetch } from "./patch-fetch";
import { patchHttpModule } from "./patch-http";
import { readConfig } from "./config";
import { runSafely } from "./fail-open";

export interface InstallOptions {
  /** Injected by tests; production writes JSON lines next to the status file. */
  readonly sink?: EventSink;
}

export interface InstallResult {
  readonly installed: boolean;
  readonly uninstall: () => void;
}

const INSTALLED = Symbol.for("periskop.hook.installed");

function alreadyInstalled(): boolean {
  return (globalThis as Record<symbol, unknown>)[INSTALLED] === true;
}

function markInstalled(value: boolean): void {
  (globalThis as Record<symbol, unknown>)[INSTALLED] = value;
}

/** The runtime string the event schema asks for, for example node/20. */
function runtimeName(version: string): string {
  const major = version.replace(/^v/, "").split(".")[0] ?? "0";
  return `node/${major}`;
}

function patchTransports(record: CallRecorder): Array<() => void> {
  const undo: Array<() => void> = [];

  // Required lazily so that a process which never gets here never pays for it.
  runSafely(() => {
    const http = require("node:http") as Parameters<typeof patchHttpModule>[0];
    undo.push(patchHttpModule(http, "node:http", false, record));
  });
  runSafely(() => {
    const https = require("node:https") as Parameters<typeof patchHttpModule>[0];
    undo.push(patchHttpModule(https, "node:https", true, record));
  });
  runSafely(() => {
    undo.push(patchFetch(globalThis as { fetch?: (...args: unknown[]) => unknown }, record));
  });

  return undo;
}

export function install(options: InstallOptions = {}): InstallResult {
  if (alreadyInstalled()) return { installed: false, uninstall: () => undefined };

  let sink: EventSink | undefined = options.sink;
  let undo: Array<() => void> = [];
  let ownsSink = false;

  runSafely(() => {
    const config = readConfig(process.env, process.argv);
    if (sink === undefined) {
      sink = new FileEventSink(config.outputDir, process.pid, config.maxBufferedEvents);
      ownsSink = true;
    }
    const record = createRecorder(sink, {
      runtime: runtimeName(process.version),
      config,
    });
    undo = patchTransports(record);
  });

  if (undo.length === 0) {
    // Nothing is in place, so the hook is not in the way. Say so where an
    // operator can see it rather than leaving an empty stream to be misread.
    markDisabled("install_failed");
    return { installed: false, uninstall: () => undefined };
  }

  markInstalled(true);

  const flushOnExit = (): void => {
    runSafely(() => sink?.close());
  };
  if (ownsSink) process.once("exit", flushOnExit);

  return {
    installed: true,
    uninstall: () => {
      for (const step of undo) runSafely(step);
      undo = [];
      markInstalled(false);
      if (ownsSink) {
        process.removeListener("exit", flushOnExit);
        runSafely(() => sink?.close());
      }
    },
  };
}
