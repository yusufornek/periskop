// Everything the hook reads from its environment, in one place.
//
// Configuration arrives through environment variables because installation does
// too: whoever can set NODE_OPTIONS can set these, and no file has to be shipped
// into the image. A config file would add a read, a parse and a failure mode to
// process startup for no gain.

import { entrypointName } from "./process-gate";

/**
 * Directory the event stream goes into, as the event schema fixes the transport.
 *
 * A directory rather than a file path because multi process work then needs no
 * coordination: every process picks its own file inside it. A file path would
 * make the caller responsible for inventing a unique name per process, and two
 * processes appending to one file interleave their writes and corrupt lines.
 *
 * There is no default, and the absence is the decision. NODE_OPTIONS spreads
 * down a whole process tree, so a developer who sets it in a shell profile and
 * names no directory would have every Node process on the machine writing
 * observations into a shared temporary directory: destination hosts, path
 * templates, field paths, and the file and function each call came from. Nobody
 * collects those files and nobody deletes them, and on a shared build host
 * anyone can read them. "periskop must not itself be a source of egress" is not
 * a rule that bends for convenience, and a directory the operator never named is
 * exactly the case it was written for. Without one the hook stays off and says
 * so, which is what the Python hook already did.
 */
export const EVENT_DIR = "PERISKOP_EVENT_DIR";

/** The name this hook used before the contract fixed one. Still honoured. */
export const LEGACY_EVENT_DIR = "PERISKOP_HOOK_DIR";

export interface HookConfig {
  /**
   * Directory the event stream and the status file are written to.
   *
   * Undefined when neither variable named one, which switches the hook off
   * rather than choosing a destination on the operator's behalf.
   */
  readonly outputDir: string | undefined;
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

/** An empty variable reads as unset, so an exported blank does not win. */
function firstNonEmpty(...values: ReadonlyArray<string | undefined>): string | undefined {
  for (const value of values) {
    const trimmed = value?.trim();
    if (trimmed !== undefined && trimmed.length > 0) return trimmed;
  }
  return undefined;
}

function positiveInteger(raw: string | undefined, fallback: number): number {
  if (raw === undefined) return fallback;
  const value = Number.parseInt(raw, 10);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

export function readConfig(
  env: NodeJS.ProcessEnv,
  argv: readonly string[],
): HookConfig {
  return {
    outputDir: firstNonEmpty(env[EVENT_DIR], env[LEGACY_EVENT_DIR]),
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
