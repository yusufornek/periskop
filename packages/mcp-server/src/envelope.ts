// The one shape a tool answers with when it cannot answer.
//
// Kept apart from the tools so that every handler reports a failure with the
// same three fields. A handler that invents its own error object gives the
// caller a second shape to learn, and a caller who has not learned it reads a
// failure as a result.

/** The common error envelope (mcp-tools.md, shared error shape). */
export function failure(code: string, message: string, retryable = false): Record<string, unknown> {
  return { error: { code, message, retryable } };
}
