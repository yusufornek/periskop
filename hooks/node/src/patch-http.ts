// node:http and node:https, wrapped without being changed.
//
// The order of operations in every wrapper is the same and it is the point of
// the file: call the original first, with the arguments it was given and the
// receiver it was called on, and only then look at what happened. An exception
// from the original leaves through the same path it always did, having never
// entered a try block of ours. A return value is passed back untouched. The
// observation runs afterwards, inside runSafely, where it can fail without the
// application ever learning that it did.
//
// http.get is patched separately from http.request because it is a separate
// export that calls a module-internal binding, so patching request does not
// reach it. In the Node versions where it does reach it, the marker on the
// request object keeps the call from being recorded twice.

import type { ClientRequest } from "node:http";

import { currentStack, findCallSite } from "./call-site";
import { readHttpTarget } from "./http-target";
import { runSafely } from "./fail-open";
import type { CallRecorder } from "./call-recorder";
import type { BodyObservation } from "./body-observation";

const OBSERVED = Symbol("periskop.observed");

type RequestFunction = (...args: unknown[]) => ClientRequest;

/** The two methods of a ClientRequest the hook needs to see, minus overloads. */
interface OutgoingLike {
  write: (...args: unknown[]) => boolean;
  end: (...args: unknown[]) => unknown;
  getHeader: (name: string) => unknown;
  readonly writableEnded: boolean;
  [OBSERVED]?: true;
}

export interface HttpModuleLike {
  request: RequestFunction;
  get: RequestFunction;
}

function chunkLength(chunk: unknown): number | undefined {
  if (typeof chunk === "string") return Buffer.byteLength(chunk);
  if (ArrayBuffer.isView(chunk)) return chunk.byteLength;
  return undefined;
}

function declaredLength(request: OutgoingLike): number | undefined {
  const header = request.getHeader("content-length");
  if (typeof header === "number") return header;
  if (typeof header === "string") {
    const parsed = Number.parseInt(header, 10);
    return Number.isNaN(parsed) ? undefined : parsed;
  }
  return undefined;
}

/**
 * Watch one request go out.
 *
 * Body bytes are counted as they pass. They are not collected: when more than
 * one chunk is written the sample is dropped, because putting the pieces back
 * together is exactly the copy of somebody's prompt this hook exists not to make.
 */
function observeRequest(
  request: ClientRequest,
  moduleName: string,
  args: readonly unknown[],
  secure: boolean,
  record: CallRecorder,
): void {
  const outgoing = request as unknown as OutgoingLike;
  if (outgoing[OBSERVED] === true) return;
  outgoing[OBSERVED] = true;

  const target = readHttpTarget(args, secure);
  const callSite = findCallSite(currentStack(), process.cwd());

  let byteSize = 0;
  let chunkCount = 0;
  let sample: string | Uint8Array | undefined;
  let recorded = false;

  const noteChunk = (chunk: unknown): void => {
    const length = chunkLength(chunk);
    if (length === undefined) return;
    byteSize += length;
    chunkCount += 1;
    sample = chunkCount === 1 ? (chunk as string | Uint8Array) : undefined;
  };

  const finish = (): void => {
    if (recorded) return;
    recorded = true;

    const declared = declaredLength(outgoing);
    const body: BodyObservation = {
      byteSize: byteSize > 0 ? byteSize : (declared ?? 0),
      streamed: false,
      sample,
    };
    // The reference is released here. Nothing of the body outlives the event.
    sample = undefined;

    record({
      module: moduleName,
      method: target.method,
      host: target.host,
      port: target.port,
      path: target.path,
      body,
      callSite,
    });
  };

  // http.get ends the request before it hands it back, so by the time the hook
  // sees the object there is nothing left to wrap. A request that is already
  // finished is recorded on the spot rather than waited on forever.
  if (outgoing.writableEnded) {
    finish();
    return;
  }

  const originalWrite = outgoing.write;
  outgoing.write = function periskopWrite(this: unknown, ...writeArgs: unknown[]): boolean {
    const result = Reflect.apply(originalWrite, this, writeArgs) as boolean;
    runSafely(() => noteChunk(writeArgs[0]));
    return result;
  };

  const originalEnd = outgoing.end;
  outgoing.end = function periskopEnd(this: unknown, ...endArgs: unknown[]): unknown {
    const chunksBefore = chunkCount;
    const result = Reflect.apply(originalEnd, this, endArgs);
    runSafely(() => {
      // Node versions disagree on whether end() routes its chunk through
      // write(). Counting before and after settles it without guessing.
      if (chunkCount === chunksBefore) noteChunk(endArgs[0]);
      finish();
    });
    return result;
  };
}

function wrap(
  original: RequestFunction,
  moduleName: string,
  secure: boolean,
  record: CallRecorder,
): RequestFunction {
  return function periskopRequest(this: unknown, ...args: unknown[]): ClientRequest {
    const request = Reflect.apply(original, this, args) as ClientRequest;
    runSafely(() => observeRequest(request, moduleName, args, secure, record));
    return request;
  };
}

/**
 * Patch a module that exports request and get, returning the undo.
 *
 * The undo exists for tests and for a hook that decides to take itself out of
 * the way; nothing in normal operation calls it.
 */
export function patchHttpModule(
  target: HttpModuleLike,
  moduleName: string,
  secure: boolean,
  record: CallRecorder,
): () => void {
  const originalRequest = target.request;
  const originalGet = target.get;

  target.request = wrap(originalRequest, moduleName, secure, record);
  target.get = wrap(originalGet, moduleName, secure, record);

  return () => {
    target.request = originalRequest;
    target.get = originalGet;
  };
}
