// Turning one observed call into one recorded event.
//
// Kept apart from the transport patches so that the patches only have to know
// what they saw, and only this file has to know what the event contract wants.

import { buildEgressEvent, type CallObservation } from "./egress-event";
import type { EventSink } from "./event-writer";
import type { HookConfig } from "./config";

export type CallRecorder = (observation: CallObservation) => void;

export interface RecorderContext {
  readonly runtime: string;
  readonly pid: number;
  readonly config: HookConfig;
  /** Injected so a test can assert on an identity instead of a moving target. */
  readonly now: () => number;
}

export function createRecorder(sink: EventSink, context: RecorderContext): CallRecorder {
  return (observation) => {
    sink.record(
      buildEgressEvent(observation, {
        runtime: context.runtime,
        pid: context.pid,
        entrypointHint: context.config.entrypointHint,
        bodyParseLimitBytes: context.config.bodyParseLimitBytes,
        epochMillis: context.now(),
      }),
    );
  };
}
