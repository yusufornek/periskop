// Global fetch, wrapped without reading anything it owns.
//
// undici's fetch is where most modern SDK traffic leaves a Node process, and it
// is also where the streaming problem is sharpest. A Request body is a
// ReadableStream and a ReadableStream is consumed once: measuring it takes the
// bytes away from the socket. So this file never touches a body it cannot read
// without cost, and says so in the event through streaming_body_not_measured.
//
// The original is called first and its promise is returned unchanged, so a
// rejection rejects the same way and a caller awaiting it sees no difference.

import { currentStack, findCallSite } from "./call-site";
import { readHttpTarget } from "./http-target";
import { runSafely } from "./fail-open";
import type { BodyObservation } from "./body-observation";
import type { CallObservation } from "./egress-event";
import type { CallRecorder } from "./call-recorder";

type FetchLike = (...args: unknown[]) => unknown;

interface FetchScope {
  fetch?: FetchLike;
}

interface HeaderBag {
  get?: (name: string) => string | null;
}

function headerValue(headers: unknown, name: string): string | undefined {
  if (headers === null || headers === undefined) return undefined;

  const bag = headers as HeaderBag;
  if (typeof bag.get === "function") return bag.get(name) ?? undefined;

  if (Array.isArray(headers)) {
    for (const entry of headers) {
      if (Array.isArray(entry) && String(entry[0]).toLowerCase() === name) return String(entry[1]);
    }
    return undefined;
  }

  if (typeof headers === "object") {
    for (const [key, value] of Object.entries(headers as Record<string, unknown>)) {
      if (key.toLowerCase() === name) return String(value);
    }
  }
  return undefined;
}

function declaredLength(headers: unknown): number {
  const raw = headerValue(headers, "content-length");
  if (raw === undefined) return 0;
  const parsed = Number.parseInt(raw, 10);
  return Number.isNaN(parsed) ? 0 : parsed;
}

/**
 * Describe an init body, or refuse to.
 *
 * A string or a byte view has already been materialised by the caller, so
 * looking at it costs nothing it has not already paid. Everything else (streams,
 * blobs, form data) is left alone and reported as unmeasured.
 */
function observeBody(body: unknown, headers: unknown): BodyObservation {
  if (body === undefined || body === null) {
    return { byteSize: 0, streamed: false, sample: undefined };
  }
  if (typeof body === "string") {
    return { byteSize: Buffer.byteLength(body), streamed: false, sample: body };
  }
  if (ArrayBuffer.isView(body)) {
    const view = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    return { byteSize: body.byteLength, streamed: false, sample: view };
  }
  if (body instanceof ArrayBuffer) {
    return { byteSize: body.byteLength, streamed: false, sample: undefined };
  }
  if (body instanceof URLSearchParams) {
    // Sized, not sampled: it is form encoded, so a field path walk would find
    // nothing, and the size is all the event can honestly claim.
    return { byteSize: Buffer.byteLength(body.toString()), streamed: false, sample: undefined };
  }
  return { byteSize: declaredLength(headers), streamed: true, sample: undefined };
}

interface RequestLike {
  readonly url: string;
  readonly method: string;
  readonly headers: unknown;
}

function isRequestLike(value: unknown): value is RequestLike {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as RequestLike).url === "string" &&
    typeof (value as RequestLike).method === "string"
  );
}

function observeCall(args: readonly unknown[]): CallObservation {
  const input = args[0];
  const init = (args[1] ?? {}) as Record<string, unknown>;

  if (isRequestLike(input)) {
    const method = (init["method"] as string | undefined) ?? input.method;
    const target = readHttpTarget([input.url], false);
    // The Request body getter is never read. Not because reading it throws, but
    // because a getter that hands back a stream is one call away from a stream
    // somebody else needed, and the size in the header answers the only
    // question the event asks.
    const hasBody = method.toUpperCase() !== "GET" && method.toUpperCase() !== "HEAD";
    return {
      module: "undici",
      method,
      host: target.host,
      port: target.port,
      path: target.path,
      body: hasBody
        ? { byteSize: declaredLength(input.headers), streamed: true, sample: undefined }
        : { byteSize: 0, streamed: false, sample: undefined },
      callSite: findCallSite(currentStack(), process.cwd()),
    };
  }

  const target = readHttpTarget([input, init], false);
  return {
    module: "undici",
    method: (init["method"] as string | undefined) ?? "GET",
    host: target.host,
    port: target.port,
    path: target.path,
    body: observeBody(init["body"], init["headers"]),
    callSite: findCallSite(currentStack(), process.cwd()),
  };
}

/** Patch a scope's fetch, returning the undo. A scope without fetch is left alone. */
export function patchFetch(scope: FetchScope, record: CallRecorder): () => void {
  const original = scope.fetch;
  if (typeof original !== "function") return () => undefined;

  scope.fetch = function periskopFetch(this: unknown, ...args: unknown[]): unknown {
    const result = Reflect.apply(original, this, args);
    runSafely(() => record(observeCall(args)));
    return result;
  };

  return () => {
    scope.fetch = original;
  };
}
