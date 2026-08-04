// What the hook itself did, kept apart from what the application did.
//
// A hook that swallows its own failures is a hook that can lose data silently,
// and silent loss is the one thing the coverage principle does not allow. So
// every failure is swallowed on the application's behalf and counted on ours.
// The counts leave through a status file, never through the event stream: the
// event schema is a closed set of properties and a status line written into it
// would make the stream fail its own contract.

export type DisableReason =
  | "disabled_by_env"
  | "non_target_process"
  | "unsupported_runtime"
  | "install_failed"
  | "load_failed";

export interface StatusSnapshot {
  readonly status: "active" | "disabled";
  readonly reason: DisableReason | undefined;
  readonly hook_failures: number;
  readonly dropped_events: number;
  readonly recorded_events: number;
}

let disabledReason: DisableReason | undefined;
let hookFailures = 0;
let droppedEvents = 0;
let recordedEvents = 0;

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

export function countFailure(): void {
  hookFailures += 1;
}

export function countDropped(): void {
  droppedEvents += 1;
}

export function countRecorded(): void {
  recordedEvents += 1;
}

export function snapshot(): StatusSnapshot {
  return {
    status: disabledReason === undefined ? "active" : "disabled",
    reason: disabledReason,
    hook_failures: hookFailures,
    dropped_events: droppedEvents,
    recorded_events: recordedEvents,
  };
}

/** Test seam. Module state outlives a single test file otherwise. */
export function resetStatus(): void {
  disabledReason = undefined;
  hookFailures = 0;
  droppedEvents = 0;
  recordedEvents = 0;
}
