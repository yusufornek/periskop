// A request path with the identifiers taken out.
//
// Two calls to the same endpoint have to compare equal, or reconciliation joins
// nothing and the report fills with one finding per request id. The query string
// goes entirely: it is the part of a URL most likely to carry a value, and none
// of it helps identify an endpoint.

const IDENTIFIER_SEGMENT = [
  /^[0-9]+$/,
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  /^[0-9a-f]{8,}$/i,
  // Provider object ids: a short prefix, then opaque characters.
  /^[a-z]{2,12}[-_][A-Za-z0-9]{8,}$/,
];

const PLACEHOLDER = "{id}";

function isIdentifier(segment: string): boolean {
  return IDENTIFIER_SEGMENT.some((pattern) => pattern.test(segment));
}

export function pathTemplate(rawPath: string | undefined): string {
  if (rawPath === undefined || rawPath.length === 0) return "/";

  const withoutQuery = rawPath.split("?")[0] ?? "/";
  const segments = withoutQuery.split("/");
  const normalised = segments.map((segment) =>
    segment.length > 0 && isIdentifier(segment) ? PLACEHOLDER : segment,
  );

  const template = normalised.join("/");
  return template.length === 0 ? "/" : template;
}
