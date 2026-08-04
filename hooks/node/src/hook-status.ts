// What the hook itself did, kept apart from what the application did.
//
// A hook that swallows its own failures is a hook that can lose data silently,
// and silent loss is the one thing the coverage principle does not allow. So
// every failure is swallowed on the application's behalf and counted on ours.
// The counts leave through a status file, never through the event stream: the
// event schema is a closed set of properties and a status line written into it
// would make the stream fail its own contract.
//
// The document below is the one `periskop-runtime-collector` reads back into
// the coverage statement, and the Python hook writes the same property names
// with the same meanings. That is the point of it: a counter only one hook
// spells the way the reader expects is a counter that reaches nobody, which is
// exactly what happened while this file spelled it `dropped_events` and the
// reader looked for nothing at all.
//
// Failures are labels rather than a count, again to match the other hook. A
// number says the hook broke; a label says which stage broke, and only the
// second is something an operator can act on. Each label is a fixed token, and
// the reader drops any that is not, because a label is copied into a report.

export type DisableReason =
  | "disabled_by_env"
  | "non_target_process"
  | "unsupported_runtime"
  | "no_output_configured"
  | "install_failed"
  | "load_failed";

/** The sidecar document, exactly as both hooks write it. */
export interface StatusSnapshot {
  readonly hook_status: "active" | "disabled";
  /** Empty while active. A fixed token otherwise, never free text. */
  readonly reason: string;
  readonly dropped_events_count: number;
  readonly written_events_count: number;
  /** Stage labels for swallowed failures, sorted and free of duplicates. */
  readonly failures: readonly string[];
}

// A process that fails on every call must not turn its own failure log into the
// payload. Bounded, and deduplicated, so the file stays a summary.
const MAX_RECORDED_FAILURES = 64;

let disabledReason: DisableReason | undefined;
let failures = new Set<string>();
let droppedEvents = 0;
let writtenEvents = 0;

/**
 * Take the hook out of the request path and say so where an operator can see it.
 *
 * The environment variable is the visible half: spec section 5 asks for a
 * process that starts un-hooked to announce it, so that "no events" is never
 * mistaken for "no egress".
 */
export function markDisabled(reason: DisableReason): void {
  disabledReason = reason;
  try {
    process.env["PERISKOP_HOOK_STATUS"] = `disabled:${reason}`;
  } catch {
    // Some sandboxes freeze process.env. Losing the announcement is not worth
    // an exception on a path whose whole purpose is to not throw.
  }
}

export function isDisabled(): boolean {
  return disabledReason !== undefined;
}

/** Record a swallowed failure under the stage that swallowed it. */
export function noteFailure(stage: string): void {
  if (failures.size >= MAX_RECORDED_FAILURES) return;
  failures.add(stage);
}

/** Count events that were observed and will never reach the stream. */
export function countDropped(events = 1): void {
  droppedEvents += events;
}

export function countWritten(events = 1): void {
  writtenEvents += events;
}

export function snapshot(): StatusSnapshot {
  return {
    hook_status: disabledReason === undefined ? "active" : "disabled",
    reason: disabledReason ?? "",
    dropped_events_count: droppedEvents,
    written_events_count: writtenEvents,
    // Sorted so two runs that saw the same failures write the same bytes.
    failures: [...failures].sort(),
  };
}

/** Test seam. Module state outlives a single test file otherwise. */
export function resetStatus(): void {
  disabledReason = undefined;
  failures = new Set<string>();
  droppedEvents = 0;
  writtenEvents = 0;
}
