// Reading a destination out of the arguments http.request was called with.
//
// The function accepts three shapes (a URL, an options object, or both) and the
// hook has to understand all of them without calling anything on the caller's
// behalf. Nothing here resolves DNS, opens a socket or touches the request: it
// reads arguments and stops.

export interface HttpTarget {
  readonly host: string | undefined;
  readonly port: number | undefined;
  readonly path: string | undefined;
  readonly method: string | undefined;
}

type Options = Record<string, unknown>;

function isOptions(value: unknown): value is Options {
  return typeof value === "object" && value !== null && !(value instanceof URL);
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.length > 0) {
    const parsed = Number.parseInt(value, 10);
    return Number.isNaN(parsed) ? undefined : parsed;
  }
  return undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** options.host may carry a port; options.hostname never does. */
function splitHost(host: string): { host: string; port: number | undefined } {
  const colon = host.lastIndexOf(":");
  if (colon <= 0 || host.includes("]")) return { host, port: undefined };
  return { host: host.slice(0, colon), port: asNumber(host.slice(colon + 1)) };
}

export function readHttpTarget(args: readonly unknown[], secure: boolean): HttpTarget {
  let host: string | undefined;
  let port: number | undefined;
  let path: string | undefined;
  let method: string | undefined;
  let isSecure = secure;
  let optionsIndex = 0;

  const first = args[0];
  if (typeof first === "string" || first instanceof URL) {
    const url = typeof first === "string" ? new URL(first) : first;
    host = url.hostname;
    port = url.port === "" ? undefined : asNumber(url.port);
    path = `${url.pathname}${url.search}`;
    isSecure = url.protocol === "https:";
    optionsIndex = 1;
  }

  const options = args[optionsIndex];
  if (isOptions(options)) {
    const hostname = asString(options["hostname"]);
    if (hostname !== undefined) {
      host = hostname;
    } else {
      const combined = asString(options["host"]);
      if (combined !== undefined) {
        const split = splitHost(combined);
        host = split.host;
        port = port ?? split.port;
      }
    }
    port = asNumber(options["port"]) ?? port;
    path = asString(options["path"]) ?? path;
    method = asString(options["method"]) ?? method;
    const protocol = asString(options["protocol"]);
    if (protocol !== undefined) isSecure = protocol === "https:";
  }

  return {
    host,
    port: port ?? (isSecure ? 443 : 80),
    path: path ?? "/",
    method: method ?? "GET",
  };
}
