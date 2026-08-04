// Where in the application the call was made, when that can be found cheaply.
//
// This is the field reconciliation uses to point at the same line the static
// scanner found, so it is worth having. It is also advisory: the schema says the
// join runs on the call shape, not on this, which is what lets the hook give up
// on it without losing the event.
//
// Two constraints shape the implementation. The stack trace limit is read, never
// written: raising it would change the behaviour of every exception the
// application throws afterwards. And the path is relative to the working
// directory or it is dropped, because the schema rejects absolute paths and a
// report that leaks a build machine's directory layout is a report that leaks.

import { isAbsolute, relative } from "node:path";

export interface CallSite {
  readonly path: string;
  readonly symbol: string | undefined;
}

//     at Object.send (/app/src/client.js:12:5)
//     at /app/src/client.js:12:5
const FRAME = /^\s*at\s+(?:(.+?)\s+\()?(.+?):\d+:\d+\)?$/;

function isForeignFrame(file: string): boolean {
  return (
    file.startsWith("node:") ||
    file.includes("node_modules") ||
    file.includes(`${"/"}hooks${"/"}node${"/"}dist${"/"}`)
  );
}

/**
 * Pick the first application frame out of a stack trace.
 *
 * Frames inside node internals, inside dependencies and inside this package are
 * skipped: they describe how the call was made, not where the application
 * decided to make it.
 */
export function findCallSite(stack: string | undefined, cwd: string): CallSite | undefined {
  if (stack === undefined) return undefined;

  for (const line of stack.split("\n")) {
    const match = FRAME.exec(line);
    if (match === null) continue;

    const file = match[2];
    if (file === undefined || isForeignFrame(file)) continue;
    if (!isAbsolute(file)) continue;

    const projectPath = relative(cwd, file);
    // Outside the project root there is no relative form the schema accepts.
    if (projectPath.length === 0 || projectPath.startsWith("..")) continue;

    const symbol = match[1];
    return { path: projectPath, symbol: symbol === undefined ? undefined : symbol.split(" ")[0] };
  }

  return undefined;
}

/** Capture the current stack without touching the process wide trace limit. */
export function currentStack(): string | undefined {
  return new Error().stack ?? undefined;
}
