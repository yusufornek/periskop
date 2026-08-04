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

  constructor(private readonly options: BridgeOptions) {}

  #start(): ChildProcessWithoutNullStreams {
    if (this.#child && !this.#child.killed) return this.#child;

    const args = ["serve-rpc"];
    if (this.options.rulesDir) args.push("--rules", this.options.rulesDir);

    const child = spawn(this.options.binary, args, {
      stdio: ["pipe", "pipe", "pipe"],
    });

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
      const reason = this.#stderr.trim();
      const message = reason
        ? `engine exited with code ${code}: ${reason}`
        : `engine exited with code ${code}`;
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
    let message: { id?: number; result?: unknown; error?: { code: number; message: string } };
    try {
      message = JSON.parse(line);
    } catch {
      // A line we cannot parse is not worth tearing the session down for. It is
      // reported through the pending request that will time out, if any.
      return;
    }
    if (typeof message.id !== "number") return;

    const pending = this.#pending.get(message.id);
    if (!pending) return;
    this.#pending.delete(message.id);

    if (message.error) {
      pending.reject(new BridgeError(message.error.message, message.error.code));
    } else {
      pending.resolve(message.result);
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
          `engine did not answer within ${this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS}ms`,
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
    await once(child, "exit").catch(() => undefined);
    this.#child = undefined;
  }
}
