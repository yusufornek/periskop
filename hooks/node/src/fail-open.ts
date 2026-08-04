// The rule the rest of this package is built around: an observation tool does
// not break the thing it observes.
//
// ADR-009 states it as non-negotiable and spec section 5 explains the trade it
// settles. A missed call shows up in the coverage report as a gap somebody can
// close. A production service the hook took down is an incident nobody can undo.
// So the tension between complete visibility and reliability is resolved in
// favour of reliability, every time, without a flag to change it.
//
// Two shapes are enough for the whole package:
//   runSafely  for observation work whose result nobody waits for
//   callSafely for observation work that produces a value we can do without
//
// Neither shape ever wraps the application's own call. The original function is
// invoked outside these helpers so that its return value and its exceptions
// reach the caller exactly as they would have without the hook.

import { noteFailure } from "./hook-status";

// Stage these helpers report under. They wrap observation work whose caller has
// no name for the step, so the label says where it was swallowed rather than
// pretending to more precision than the call site gives.
const STAGE = "hook.observe";

function note(error: unknown): void {
  noteFailure(STAGE);
  if (process.env["PERISKOP_HOOK_DEBUG"] !== "1") return;
  try {
    const detail = error instanceof Error ? error.message : String(error);
    process.stderr.write(`periskop hook: ${detail}\n`);
  } catch {
    // Writing the diagnostic failed. There is nowhere left to report that, and
    // it does not matter: the application is unaffected either way.
  }
}

/** Run observation work. Anything it throws stops here. */
export function runSafely(action: () => void): void {
  try {
    action();
  } catch (error) {
    note(error);
  }
}

/** Run observation work that produces a value, falling back when it throws. */
export function callSafely<T>(action: () => T, fallback: T): T {
  try {
    return action();
  } catch (error) {
    note(error);
    return fallback;
  }
}
