// Everything the hook reads from its environment, in one place.
//
// Configuration arrives through environment variables because installation does
// too: whoever can set NODE_OPTIONS can set these, and no file has to be shipped
// into the image. A config file would add a read, a parse and a failure mode to
// process startup for no gain.

import { tmpdir } from "node:os";
import { join } from "node:path";

import { entrypointName } from "./process-gate";

export interface HookConfig {
  /** Directory the event stream and the status file are written to. */
  readonly outputDir: string;
  /** Name of this process as it will appear in the event, never a path. */
  readonly entrypointHint: string;
  /** Above this many bytes a body is not parsed for field paths. */
  readonly bodyParseLimitBytes: number;
  /** Events held in memory before the oldest are dropped. */
  readonly maxBufferedEvents: number;
}

// A body larger than this is left alone. Extracting field paths means parsing,
// and parsing is work proportional to body size, which spec section 4 does not
// leave room for. Past the limit the event says so through a degraded reason
// rather than quietly reporting an empty shape.
const DEFAULT_BODY_PARSE_LIMIT = 64 * 1024;

// The ring is small on purpose. It exists to cap memory in a process that is
// not ours, not to guarantee delivery; ADR-009 asks for drop-oldest and a
// reported count, which is what overflow does.
const DEFAULT_MAX_BUFFERED_EVENTS = 1024;

function positiveInteger(raw: string | undefined, fallback: number): number {
  if (raw === undefined) return fallback;
  const value = Number.parseInt(raw, 10);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

export function readConfig(
  env: NodeJS.ProcessEnv,
  argv: readonly string[],
): HookConfig {
  const configuredDir = env["PERISKOP_HOOK_DIR"];
  return {
    outputDir:
      configuredDir !== undefined && configuredDir.length > 0
        ? configuredDir
        : join(tmpdir(), "periskop-events"),
    // An operator can name the process; otherwise the script names itself. The
    // event schema rejects absolute paths here, so only a basename is ever used.
    entrypointHint: env["PERISKOP_HOOK_ENTRYPOINT"] ?? entrypointName(argv),
    bodyParseLimitBytes: positiveInteger(
      env["PERISKOP_HOOK_BODY_LIMIT"],
      DEFAULT_BODY_PARSE_LIMIT,
    ),
    maxBufferedEvents: positiveInteger(
      env["PERISKOP_HOOK_BUFFER"],
      DEFAULT_MAX_BUFFERED_EVENTS,
    ),
  };
}
