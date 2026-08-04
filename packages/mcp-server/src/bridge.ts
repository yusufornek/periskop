// Talking to the engine over JSON-RPC.
//
// The server owns no detection logic. It starts the engine binary, sends
// requests and hands back what comes out. Reimplementing any part of the
// analysis here would give the project two answers to the same question, and
// they would drift.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";

export interface BridgeOptions {
  /** Path to the periskop binary. */
  binary: string;
  /** Directory holding detector rules, when it is not the default. */
  rulesDir?: string;
  /** How long a single request may take before it is abandoned. */
  timeoutMs?: number;
  /**
   * How long one message may be before this side refuses to read it.
   *
   * An option rather than a constant so that the bound itself can be exercised
   * without moving sixteen megabytes through a pipe in a test.
   */
  maxMessageChars?: number;
  /**
   * Where protocol level problems go.
   *
   * A message this side cannot route belongs to no request, so there is no
   * caller to hand it to and it would otherwise be dropped. Defaults to stderr,
   * which for a stdio server is the only channel that is not the protocol.
   */
  onDiagnostic?: (message: string) => void;
}

/**
 * The part of the bridge a tool handler uses.
 *
 * Narrower than the class so that a test can supply a recorded report without
 * starting a process. That is not a convenience: the answers that depend on a
 * second or third observation source cannot be produced by a static only
 * pipeline at all, so a test that could only go through the real binary would
 * leave exactly those answers uncovered.
 */
export interface ReportSource {
  call(method: string, params?: Record<string, unknown>): Promise<unknown>;
}

export class BridgeError extends Error {
  constructor(
    message: string,
    readonly code?: number,
  ) {
    super(message);
    this.name = "BridgeError";
  }
}

const DEFAULT_TIMEOUT_MS = 120_000;

/** How many protocol problems are kept to explain the next failure. */
const MAX_DIAGNOSTICS = 10;

/** How much of an offending line is quoted: enough to recognise, short enough to read. */
const QUOTED_LINE_LIMIT = 200;

/**
 * How long a message may be before this side refuses to read it.
 *
 * Generous, because a scan of a large repository is a large report and this must
 * not become a limit on real answers; bounded, because nothing else was. A
 * malformed or hostile engine could send a line without an end, and every step
 * after this one is unbounded work on it: the parse, the projection, and the
 * caller's context.
 *
 * What this does not bound is the read. The line arrives through readline, which
 * has already buffered it by the time this runs, so an engine that never sends a
 * newline is still a memory problem on the stream itself. This caps everything
 * downstream of that, and says so rather than dropping the line quietly.
 */
const DEFAULT_MAX_MESSAGE_CHARS = 16 * 1024 * 1024;

/** Renders anything a catch clause can receive. */
function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function quote(line: string): string {
  return line.length > QUOTED_LINE_LIMIT ? `${line.slice(0, QUOTED_LINE_LIMIT)}...` : line;
}

/**
 * A live engine process.
 *
 * One process serves many requests. Starting a fresh one per call would pay the
 * rule compilation cost every time, which is the single most expensive part of
 * a small scan.
 */
export class EngineBridge {
  #child: ChildProcessWithoutNullStreams | undefined;
  #pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  #nextId = 1;
  #stderr = "";
  #diagnostics: string[] = [];

  constructor(private readonly options: BridgeOptions) {}

  /**
   * Records a problem that belongs to the connection rather than to a request.
   *
   * Kept as well as emitted: the caller who is about to be told nobody answered
   * needs to read it, and by then the line it arrived on is long gone.
   */
  #report(message: string): void {
    this.#diagnostics.push(message);
    if (this.#diagnostics.length > MAX_DIAGNOSTICS) this.#diagnostics.shift();

    const sink = this.options.onDiagnostic;
    if (sink) sink(message);
    else process.stderr.write(`periskop-mcp: ${message}\n`);
  }

  /**
   * A failure, with everything known about why.
   *
   * The bare sentence was wrong often enough to be a bug: an engine that
   * refused the request or died compiling rules had already said so, and the
   * caller was told only that nobody answered. What is attached is what was
   * seen on this connection, which is not a claim that it caused this failure.
   */
  #explain(headline: string): string {
    const parts = [headline];
    if (this.#diagnostics.length > 0) {
      parts.push(`protocol problems on this connection: ${this.#diagnostics.join("; ")}`);
    }
    const stderr = this.#stderr.trim();
    if (stderr) parts.push(`engine stderr: ${stderr}`);
    return parts.join(". ");
  }

  #start(): ChildProcessWithoutNullStreams {
    if (this.#child && !this.#child.killed) return this.#child;

    const args = ["serve-rpc"];
    if (this.options.rulesDir) args.push("--rules", this.options.rulesDir);

    const child = spawn(this.options.binary, args, {
      stdio: ["pipe", "pipe", "pipe"],
    });

    // Both buffers describe one process. Carrying them into the next one would
    // attach a dead engine's complaint to a live engine's failure.
    this.#stderr = "";
    this.#diagnostics = [];

    // Line delimited framing, matching the engine side.
    createInterface({ input: child.stdout }).on("line", (line) => {
      if (!line.trim()) return;
      this.#deliver(line);
    });

    // Engine diagnostics are kept rather than dropped. When a request fails,
    // the last thing the engine printed is usually the reason, and losing it
    // leaves the user with a bare error code.
    child.stderr.on("data", (chunk: Buffer) => {
      this.#stderr = (this.#stderr + chunk.toString()).slice(-4000);
    });

    child.on("exit", (code) => {
      const message = this.#explain(`engine exited with code ${code}`);
      for (const [, pending] of this.#pending) {
        pending.reject(new BridgeError(message));
      }
      this.#pending.clear();
      this.#child = undefined;
    });

    this.#child = child;
    return child;
  }

  #deliver(line: string): void {
    const limit = this.options.maxMessageChars ?? DEFAULT_MAX_MESSAGE_CHARS;
    if (line.length > limit) {
      this.#report(
        `engine sent a ${line.length} character message, past the ${limit} character limit, and it was not read: ${quote(line)}`,
      );
      return;
    }

    let message: { id?: number | null; result?: unknown; error?: { code: number; message: string } };
    try {
      message = JSON.parse(line);
    } catch (error) {
      // Still not worth tearing the session down for, and no longer silent. The
      // engine did answer, this side could not read it, and the caller used to
      // learn only that nobody answered.
      this.#report(`engine sent a line that is not a message (${describe(error)}): ${quote(line)}`);
      return;
    }

    if (typeof message.id !== "number") {
      this.#deliverUnattributed(message, line);
      return;
    }

    const pending = this.#pending.get(message.id);
    if (!pending) {
      // Nothing is waiting for this id, so an answer went missing somewhere: a
      // request that already timed out, or an engine numbering its replies
      // wrong. Both are faults, and both are invisible from the caller's side.
      this.#report(`engine answered request ${message.id}, which was no longer waiting`);
      return;
    }
    this.#pending.delete(message.id);

    if (message.error) {
      pending.reject(new BridgeError(message.error.message, message.error.code));
    } else {
      pending.resolve(message.result);
    }
  }

  /**
   * A message with no usable request id.
   *
   * JSON-RPC puts a null id on an error when the engine could not tell which
   * request it belongs to, which is precisely the case where dropping it costs
   * the caller the real reason. With one request in flight there is nothing to
   * disambiguate, so the error goes to it rather than making it wait out the
   * timeout. With several, naming one would be a guess, so the complaint is
   * recorded and travels with whichever failure comes next.
   */
  #deliverUnattributed(
    message: { error?: { code: number; message: string } },
    line: string,
  ): void {
    const error = message.error;
    this.#report(
      error
        ? `engine reported an error against no request: ${error.message} (code ${error.code})`
        : `engine sent a message with no request id: ${quote(line)}`,
    );

    if (!error || this.#pending.size !== 1) return;

    for (const [id, pending] of this.#pending) {
      this.#pending.delete(id);
      pending.reject(new BridgeError(error.message, error.code));
    }
  }

  async call(method: string, params: Record<string, unknown> = {}): Promise<unknown> {
    const child = this.#start();
    const id = this.#nextId++;

    const response = new Promise<unknown>((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
    });

    const timeout = setTimeout(() => {
      const pending = this.#pending.get(id);
      if (!pending) return;
      this.#pending.delete(id);
      pending.reject(
        new BridgeError(
          this.#explain(
            `engine did not answer within ${this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS}ms`,
          ),
        ),
      );
    }, this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);

    try {
      return await response;
    } finally {
      clearTimeout(timeout);
    }
  }

  async close(): Promise<void> {
    const child = this.#child;
    if (!child || child.killed) return;
    child.stdin.end();
    child.kill();
    await once(child, "exit").catch((error: unknown) => {
      // Not fatal, the process is going away either way. Reported because a
      // close that fails quietly hides a child that never died.
      this.#report(`engine did not exit cleanly: ${describe(error)}`);
    });
    this.#child = undefined;
  }
}
