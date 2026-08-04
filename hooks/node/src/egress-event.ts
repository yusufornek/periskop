// The event contract, as this hook is allowed to produce it.
//
// schemas/egress-event.schema.json is the binding document; these types are a
// mirror of it and nothing more. The schema sets additionalProperties to false,
// so a field invented here would not be a richer event, it would be an invalid
// one. Fields are added to the schema first and to this file second.

import { describeBody, type BodyObservation } from "./body-observation";
import { egressEventId } from "./event-id";
import { classifyHost } from "./provider-ref";
import { pathTemplate } from "./path-template";
import type { CallSite } from "./call-site";

export const SCHEMA_VERSION = "1.0";

export type DegradedReason =
  | "streaming_body_not_measured"
  | "payload_traversal_truncated"
  | "target_not_resolved"
  | "call_site_unavailable"
  | "sampling_applied";

export interface PayloadShape {
  readonly field_paths: readonly string[];
  readonly byte_size_estimate: number;
  readonly truncated_depth?: number;
}

export interface EgressEvent {
  readonly schema_version: string;
  readonly egress_event_id: string;
  readonly process: {
    readonly language: "javascript";
    readonly runtime: string;
    readonly entrypoint_hint?: string;
  };
  readonly library: {
    readonly module: string;
    // Always http_client. The hook sits on the transport, and the schema notes
    // that this is the weaker of the two observations precisely because it
    // cannot tell a provider call from any other request without the target.
    readonly mechanism: "http_client";
  };
  readonly operation: string;
  readonly target: {
    readonly host_id: string;
    readonly port?: number;
    readonly path_template?: string;
    readonly provider_ref?: string;
  };
  readonly payload_shape: PayloadShape;
  readonly call_site_hint?: { readonly path?: string; readonly symbol?: string };
  readonly degraded_reasons?: readonly DegradedReason[];
}

/** Everything the transport patches can tell us about one call. */
export interface CallObservation {
  /** Package the call went through, as the hook saw it. */
  readonly module: string;
  /** HTTP method, or empty when the transport did not say. */
  readonly method: string | undefined;
  readonly host: string | undefined;
  readonly port: number | undefined;
  readonly path: string | undefined;
  readonly body: BodyObservation;
  readonly callSite: CallSite | undefined;
}

export interface BuildContext {
  readonly runtime: string;
  readonly entrypointHint: string;
  readonly bodyParseLimitBytes: number;
}

/** The schema wants lower case, and a method is the only operation we can name. */
function operationOf(method: string | undefined): string {
  const normalised = (method ?? "get").toLowerCase();
  return /^[a-z][a-z0-9_.]*$/.test(normalised) ? normalised : "unknown";
}

export function buildEgressEvent(
  observation: CallObservation,
  context: BuildContext,
): EgressEvent {
  const degraded: DegradedReason[] = [];

  // A destination we could not read is written down as unresolved, never
  // dropped. An event missing from the stream would read as no call at all.
  const resolved = observation.host !== undefined && observation.host.length > 0;
  if (!resolved) degraded.push("target_not_resolved");
  const host = resolved ? (observation.host as string) : "unknown";
  const port = observation.port ?? 0;
  const template = pathTemplate(observation.path);
  const operation = operationOf(observation.method);

  const described = describeBody(observation.body, context.bodyParseLimitBytes);
  degraded.push(...described.degraded);

  if (observation.callSite === undefined) degraded.push("call_site_unavailable");

  const event: EgressEvent = {
    schema_version: SCHEMA_VERSION,
    // Only the four fields the schema names take part. The port, the payload,
    // the entrypoint and the call site are excluded on purpose: the same call
    // with a longer prompt, from a different worker, is the same call, and an
    // identity that moved with any of them would defeat deduplication.
    egress_event_id: egressEventId({
      module: observation.module,
      operation,
      hostId: host,
      pathTemplate: template,
    }),
    process: {
      language: "javascript",
      runtime: context.runtime,
      entrypoint_hint: context.entrypointHint,
    },
    library: { module: observation.module, mechanism: "http_client" },
    operation,
    target: {
      host_id: host,
      port,
      path_template: template,
      provider_ref: classifyHost(observation.host),
    },
    payload_shape: described.shape,
  };

  const withCallSite =
    observation.callSite === undefined
      ? event
      : {
          ...event,
          call_site_hint:
            observation.callSite.symbol === undefined
              ? { path: observation.callSite.path }
              : { path: observation.callSite.path, symbol: observation.callSite.symbol },
        };

  return degraded.length === 0 ? withCallSite : { ...withCallSite, degraded_reasons: degraded };
}
