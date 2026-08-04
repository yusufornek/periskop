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
//
// The same document carries how long this process was watched for, and it is
// the one number a claim about a call that never happened rests on. It cannot
// travel in the event stream: egress_event_id is derived from the call shape
// and holds no clock, which is what makes one call recorded twice one identity.
// It is a duration read from a monotonic clock, never a wall clock stamp, so a
// system clock corrected mid run cannot produce a negative or inflated window.
// Its absence means the hook never entered the call path, which is a different
// fact from a window of zero and is spelled differently on purpose: the
// property is omitted rather than written as 0.
//
// Contract: schemas/hook-status.schema.json.

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
  /**
   * Milliseconds this process has been under observation.
   *
   * Omitted, never zero, when the hook never entered the call path: a reader
   * has to be able to tell "watched for no time" from "cannot say how long".
   */
  readonly observation_window_ms?: number;
}

// A process that fails on every call must not turn its own failure log into the
// payload. Bounded, and deduplicated, so the file stays a summary.
const MAX_RECORDED_FAILURES = 64;

const NS_PER_MS = 1_000_000n;

let disabledReason: DisableReason | undefined;
let failures = new Set<string>();
let droppedEvents = 0;
let writtenEvents = 0;
let observationStartedAt: bigint | undefined;

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

/**
 * Open the observation window.
 *
 * Called when the hook enters the call path, not when the first event arrives.
 * A process that ran for an hour and made one call in the last minute was
 * watched for an hour, and timing from the first event would throw the other
 * fifty-nine minutes of evidence away.
 *
 * process.hrtime.bigint is monotonic. Date.now is not, and a report built on it
 * would move when the machine's clock was corrected.
 */
export function startObservation(): void {
  if (observationStartedAt !== undefined) return;
  observationStartedAt = process.hrtime.bigint();
}

/** Milliseconds watched so far, or undefined when nothing has been watched. */
function observationWindowMs(): number | undefined {
  if (observationStartedAt === undefined) return undefined;
  const elapsed = process.hrtime.bigint() - observationStartedAt;
  // Truncated rather than rounded: a window is the floor of what was watched.
  // The clamp costs nothing and keeps a platform whose monotonic clock ever
  // stepped backwards from putting a negative duration into a report.
  return elapsed > 0n ? Number(elapsed / NS_PER_MS) : 0;
}

export function snapshot(): StatusSnapshot {
  const window = observationWindowMs();
  const document: StatusSnapshot = {
    hook_status: disabledReason === undefined ? "active" : "disabled",
    reason: disabledReason ?? "",
    dropped_events_count: droppedEvents,
    written_events_count: writtenEvents,
    // Sorted so two runs that saw the same failures write the same bytes.
    failures: [...failures].sort(),
  };
  // Built conditionally rather than assigned undefined: JSON.stringify would
  // drop the key either way, but a property that exists holding undefined is a
  // different type, and the contract distinguishes absent from present.
  return window === undefined ? document : { ...document, observation_window_ms: window };
}

/** Test seam. Module state outlives a single test file otherwise. */
export function resetStatus(): void {
  disabledReason = undefined;
  failures = new Set<string>();
  droppedEvents = 0;
  writtenEvents = 0;
  observationStartedAt = undefined;
}
